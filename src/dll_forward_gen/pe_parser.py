"""Zero-dependency PE (Portable Executable) binary parser for extracting DLL exports, imports, and security mitigations."""

import hashlib
import math
import os
import struct
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from .models import ExportSymbol, ImportDescriptor, ImportSymbol, PeArch, PeExportInfo, PeMitigations, SectionInfo
from .known_ordinals import lookup_known_ordinal


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a given byte buffer (0.0 to 8.0)."""
    if not data:
        return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class PeParseError(Exception):
    """Raised when PE parsing fails due to invalid format or corrupted headers."""
    pass


def resolve_dll_path(name_or_path: str) -> Path:
    """Resolve DLL input argument to an existing file path."""
    p = Path(name_or_path)
    if p.is_file():
        return p.resolve()

    search_dirs = [
        Path.cwd(),
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32",
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SysWOW64",
    ]

    for d in search_dirs:
        candidate = d / name_or_path
        if candidate.is_file():
            return candidate.resolve()
        if not name_or_path.lower().endswith(".dll"):
            candidate_dll = d / f"{name_or_path}.dll"
            if candidate_dll.is_file():
                return candidate_dll.resolve()

    raise FileNotFoundError(f"Could not locate DLL '{name_or_path}' locally or in Windows system directories.")


def demangle_symbol(name: Optional[str]) -> Optional[str]:
    """Demangle MSVC decorated C++ symbols using dbghelp.dll (Windows native)."""
    if not name or not name.startswith("?"):
        return None
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(2048)
        res = ctypes.windll.dbghelp.UnDecorateSymbolNameW(name, buf, 2048, 0)
        if res > 0:
            return buf.value
    except Exception:
        pass
    return None


class PeParser:
    """Parses PE32 and PE32+ (x86 and x64) binaries to extract export/import directories and mitigations."""

    IMAGE_DOS_SIGNATURE = 0x5A4D  # "MZ"
    IMAGE_NT_SIGNATURE = 0x00004550  # "PE\0\0"
    OPTIONAL_HDR_MAGIC_PE32 = 0x010B
    OPTIONAL_HDR_MAGIC_PE32_PLUS = 0x020B

    def __init__(self, data: bytes, filepath: str = ""):
        self.data = data
        self.filepath = filepath
        self.sections: List[Tuple[int, int, int, int]] = []
        self.arch: PeArch = PeArch.UNKNOWN
        self.pe_offset: int = 0
        self.opt_magic: int = 0
        self.export_dir_offset: int = 0
        self.export_rva: int = 0
        self.export_size: int = 0
        self.timestamp: int = 0
        self.characteristics: int = 0
        self.mitigations: Optional[PeMitigations] = None
        self.sha256: str = hashlib.sha256(data).hexdigest() if data else ""
        self._headers_parsed: bool = False

    @classmethod
    def from_file(cls, filepath: Union[str, Path]) -> "PeParser":
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"PE binary not found: {filepath}")
        with open(path, "rb") as f:
            data = f.read()
        return cls(data, str(path.resolve()))

    @classmethod
    def parse_bytes(cls, data: bytes) -> PeExportInfo:
        parser = cls(data)
        return parser.parse()

    def _read_exact(self, offset: int, size: int) -> bytes:
        if offset + size > len(self.data):
            raise PeParseError(f"Unexpected end of file at offset 0x{offset:X} (needed {size} bytes)")
        return self.data[offset : offset + size]

    def _read_u16(self, offset: int) -> int:
        return struct.unpack("<H", self._read_exact(offset, 2))[0]

    def _read_u32(self, offset: int) -> int:
        return struct.unpack("<I", self._read_exact(offset, 4))[0]

    def _read_u64(self, offset: int) -> int:
        return struct.unpack("<Q", self._read_exact(offset, 8))[0]

    def _read_asciiz(self, offset: int, max_len: int = 1024) -> str:
        end = self.data.find(b"\x00", offset, offset + max_len)
        if end == -1:
            end = min(offset + max_len, len(self.data))
        raw = self.data[offset:end]
        return raw.decode("latin1", errors="replace")

    def rva_to_offset(self, rva: int) -> Optional[int]:
        """Convert a Relative Virtual Address (RVA) to physical raw file offset."""
        for va_start, virt_size, raw_ptr, raw_size in self.sections:
            span = max(virt_size, raw_size)
            if va_start <= rva < va_start + span:
                offset_in_sec = rva - va_start
                if offset_in_sec < raw_size:
                    return raw_ptr + offset_in_sec
        return None

    def _parse_headers(self) -> None:
        """Parse DOS, NT, File Header, Optional Header, and Section Headers."""
        if self._headers_parsed:
            return

        if len(self.data) < 64:
            raise PeParseError("Buffer too small to contain IMAGE_DOS_HEADER")

        dos_magic = self._read_u16(0)
        if dos_magic != self.IMAGE_DOS_SIGNATURE:
            raise PeParseError(f"Invalid DOS signature 0x{dos_magic:04X} (expected 'MZ' 0x5A4D)")

        self.pe_offset = self._read_u32(0x3C)
        if self.pe_offset + 4 > len(self.data):
            raise PeParseError(f"Invalid e_lfanew pointer 0x{self.pe_offset:X}")

        nt_sig = self._read_u32(self.pe_offset)
        if nt_sig != self.IMAGE_NT_SIGNATURE:
            raise PeParseError(f"Invalid NT signature 0x{nt_sig:08X} (expected 'PE\\0\\0')")

        file_hdr_offset = self.pe_offset + 4
        machine = self._read_u16(file_hdr_offset)
        num_sections = self._read_u16(file_hdr_offset + 2)
        self.timestamp = self._read_u32(file_hdr_offset + 4)
        size_of_opt_hdr = self._read_u16(file_hdr_offset + 16)
        self.characteristics = self._read_u16(file_hdr_offset + 18)

        self.arch = PeArch.from_machine(machine)

        opt_hdr_offset = file_hdr_offset + 20
        if size_of_opt_hdr < 2:
            raise PeParseError("Missing Optional Header")

        self.opt_magic = self._read_u16(opt_hdr_offset)
        if self.opt_magic == self.OPTIONAL_HDR_MAGIC_PE32:
            self.image_base = self._read_u32(opt_hdr_offset + 28)
            self.export_dir_offset = opt_hdr_offset + 96
        elif self.opt_magic == self.OPTIONAL_HDR_MAGIC_PE32_PLUS:
            self.image_base = self._read_u64(opt_hdr_offset + 24)
            self.export_dir_offset = opt_hdr_offset + 112
        else:
            raise PeParseError(f"Unsupported Optional Header magic: 0x{self.opt_magic:04X}")

        self.tls_dir_offset = self.export_dir_offset + (9 * 8)
        self.delay_dir_offset = self.export_dir_offset + (13 * 8)

        if opt_hdr_offset + size_of_opt_hdr > len(self.data):
            raise PeParseError("Optional Header exceeds file size")

        if size_of_opt_hdr >= 72:
            dll_char = self._read_u16(opt_hdr_offset + 70)
            self.mitigations = PeMitigations(
                dynamic_base=bool(dll_char & 0x0040),
                high_entropy_va=bool(dll_char & 0x0020),
                nx_compat=bool(dll_char & 0x0100),
                no_seh=bool(dll_char & 0x0400),
                guard_cf=bool(dll_char & 0x4000),
                wdm_driver=bool(dll_char & 0x2000),
                ts_aware=bool(dll_char & 0x8000),
            )

        if self.export_dir_offset + 8 <= opt_hdr_offset + size_of_opt_hdr:
            self.export_rva = self._read_u32(self.export_dir_offset)
            self.export_size = self._read_u32(self.export_dir_offset + 4)
        else:
            self.export_rva = 0
            self.export_size = 0

        sections_offset = opt_hdr_offset + size_of_opt_hdr
        self.sections.clear()
        self.section_infos: List[SectionInfo] = []
        for i in range(num_sections):
            sec_ptr = sections_offset + (i * 40)
            if sec_ptr + 40 > len(self.data):
                break
            raw_name = self.data[sec_ptr : sec_ptr + 8].rstrip(b"\x00")
            sec_name = raw_name.decode("latin1", errors="replace")
            virt_size = self._read_u32(sec_ptr + 8)
            virt_addr = self._read_u32(sec_ptr + 12)
            raw_size = self._read_u32(sec_ptr + 16)
            raw_ptr = self._read_u32(sec_ptr + 20)
            chars = self._read_u32(sec_ptr + 36) if sec_ptr + 40 <= len(self.data) else 0
            self.sections.append((virt_addr, virt_size, raw_ptr, raw_size))

            sec_bytes = self.data[raw_ptr : raw_ptr + raw_size]
            entropy = calculate_entropy(sec_bytes)
            self.section_infos.append(
                SectionInfo(
                    name=sec_name,
                    virtual_address=virt_addr,
                    virtual_size=virt_size,
                    raw_data_offset=raw_ptr,
                    raw_data_size=raw_size,
                    characteristics=chars,
                    entropy=entropy,
                )
            )

        self._headers_parsed = True

    def parse(self) -> PeExportInfo:
        """Parse PE headers and extract export table symbols."""
        self._parse_headers()

        fallback_name = Path(self.filepath).name if self.filepath else "unknown.dll"

        if self.export_rva == 0 or self.export_size == 0:
            return PeExportInfo(
                filepath=self.filepath,
                dll_name=fallback_name,
                arch=self.arch,
                timestamp=self.timestamp,
                ordinal_base=1,
                symbols=[],
                sha256=self.sha256,
                mitigations=self.mitigations,
                sections=self.section_infos,
            )

        export_file_offset = self.rva_to_offset(self.export_rva)
        if export_file_offset is None:
            raise PeParseError(f"Failed to resolve Export Directory RVA 0x{self.export_rva:08X} to file offset")

        name_rva = self._read_u32(export_file_offset + 12)
        ordinal_base = self._read_u32(export_file_offset + 16)
        num_functions = self._read_u32(export_file_offset + 20)
        num_names = self._read_u32(export_file_offset + 24)
        addr_functions_rva = self._read_u32(export_file_offset + 28)
        addr_names_rva = self._read_u32(export_file_offset + 32)
        addr_ordinals_rva = self._read_u32(export_file_offset + 36)

        dll_name = fallback_name
        name_offset = self.rva_to_offset(name_rva)
        if name_offset is not None:
            parsed_name = self._read_asciiz(name_offset)
            if parsed_name:
                dll_name = parsed_name

        index_to_name: Dict[int, str] = {}
        names_offset = self.rva_to_offset(addr_names_rva)
        ordinals_offset = self.rva_to_offset(addr_ordinals_rva)

        if names_offset is not None and ordinals_offset is not None:
            for i in range(num_names):
                n_rva = self._read_u32(names_offset + (i * 4))
                fn_idx = self._read_u16(ordinals_offset + (i * 2))
                fn_name_offset = self.rva_to_offset(n_rva)
                if fn_name_offset is not None:
                    sym_name = self._read_asciiz(fn_name_offset)
                    index_to_name[fn_idx] = sym_name

        symbols: List[ExportSymbol] = []
        functions_offset = self.rva_to_offset(addr_functions_rva)
        if functions_offset is not None:
            for idx in range(num_functions):
                fn_rva = self._read_u32(functions_offset + (idx * 4))
                if fn_rva == 0:
                    continue

                ordinal = ordinal_base + idx
                name = index_to_name.get(idx)

                is_fwd = self.export_rva <= fn_rva < (self.export_rva + self.export_size)
                fwd_str = None
                if is_fwd:
                    fwd_offset = self.rva_to_offset(fn_rva)
                    if fwd_offset is not None:
                        fwd_str = self._read_asciiz(fwd_offset)

                demangled = demangle_symbol(name) if name else None
                known = lookup_known_ordinal(dll_name, ordinal) if name is None else None

                symbols.append(
                    ExportSymbol(
                        ordinal=ordinal,
                        rva=fn_rva,
                        name=name,
                        is_forwarded=is_fwd,
                        forward_name=fwd_str,
                        demangled_name=demangled,
                        known_name=known,
                    )
                )

        # Extract TLS callbacks if present
        tls_callbacks: List[int] = []
        is_64 = self.opt_magic == self.OPTIONAL_HDR_MAGIC_PE32_PLUS
        if hasattr(self, "tls_dir_offset") and self.tls_dir_offset + 8 <= len(self.data):
            tls_rva = self._read_u32(self.tls_dir_offset)
            tls_size = self._read_u32(self.tls_dir_offset + 4)
            if tls_rva != 0 and tls_size != 0:
                tls_offset = self.rva_to_offset(tls_rva)
                if tls_offset is not None:
                    cb_addr_offset = tls_offset + (24 if is_64 else 12)
                    if cb_addr_offset + (8 if is_64 else 4) <= len(self.data):
                        cb_va = self._read_u64(cb_addr_offset) if is_64 else self._read_u32(cb_addr_offset)
                        if cb_va and cb_va >= self.image_base:
                            cb_rva = cb_va - self.image_base
                            cb_file_offset = self.rva_to_offset(cb_rva)
                            if cb_file_offset is not None:
                                ptr_size = 8 if is_64 else 4
                                curr_cb = cb_file_offset
                                while curr_cb + ptr_size <= len(self.data):
                                    func_va = self._read_u64(curr_cb) if is_64 else self._read_u32(curr_cb)
                                    if func_va == 0:
                                        break
                                    if func_va >= self.image_base:
                                        tls_callbacks.append(func_va - self.image_base)
                                    curr_cb += ptr_size

        return PeExportInfo(
            filepath=self.filepath,
            dll_name=dll_name,
            arch=self.arch,
            timestamp=self.timestamp,
            ordinal_base=ordinal_base,
            symbols=symbols,
            sha256=self.sha256,
            mitigations=self.mitigations,
            tls_callbacks=tls_callbacks,
            sections=self.section_infos,
        )

    def parse_imports(self, include_delay_load: bool = True) -> List[ImportDescriptor]:
        """Parse PE import directory to extract all imported DLLs and their functions."""
        self._parse_headers()

        import_dir_offset = self.export_dir_offset + 8
        if import_dir_offset + 8 > len(self.data):
            return []

        import_rva = self._read_u32(import_dir_offset)
        import_size = self._read_u32(import_dir_offset + 4)

        descriptors: List[ImportDescriptor] = []
        is_64 = self.opt_magic == self.OPTIONAL_HDR_MAGIC_PE32_PLUS
        thunk_size = 8 if is_64 else 4
        ordinal_mask = 0x8000000000000000 if is_64 else 0x80000000

        if import_rva != 0 and import_size != 0:
            import_offset = self.rva_to_offset(import_rva)
            if import_offset is not None:
                curr_offset = import_offset
                while curr_offset + 20 <= len(self.data):
                    raw_desc = self.data[curr_offset : curr_offset + 20]
                    if raw_desc == b"\x00" * 20:
                        break

                    orig_first_thunk, timestamp, fwd_chain, name_rva, first_thunk = struct.unpack("<IIIII", raw_desc)
                    curr_offset += 20

                    dll_name_offset = self.rva_to_offset(name_rva)
                    if dll_name_offset is None:
                        continue

                    dll_name = self._read_asciiz(dll_name_offset)
                    thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
                    thunk_file_offset = self.rva_to_offset(thunk_rva)
                    if thunk_file_offset is None:
                        descriptors.append(ImportDescriptor(dll_name=dll_name, symbols=[], is_delay_loaded=False))
                        continue

                    symbols: List[ImportSymbol] = []
                    entry_offset = thunk_file_offset

                    while entry_offset + thunk_size <= len(self.data):
                        val = struct.unpack("<Q" if is_64 else "<I", self.data[entry_offset : entry_offset + thunk_size])[0]
                        entry_offset += thunk_size
                        if val == 0:
                            break

                        if val & ordinal_mask:
                            ord_num = val & 0xFFFF
                            symbols.append(ImportSymbol(name=None, ordinal=ord_num))
                        else:
                            name_ptr = val & 0x7FFFFFFFFFFFFFFF if is_64 else val & 0x7FFFFFFF
                            name_file_offset = self.rva_to_offset(name_ptr)
                            if name_file_offset is not None and name_file_offset + 2 < len(self.data):
                                sym_name = self._read_asciiz(name_file_offset + 2)
                                symbols.append(ImportSymbol(name=sym_name, ordinal=None))

                    descriptors.append(ImportDescriptor(dll_name=dll_name, symbols=symbols, is_delay_loaded=False))

        # Parse Delay-Load Imports if requested
        if include_delay_load and hasattr(self, "delay_dir_offset") and self.delay_dir_offset + 8 <= len(self.data):
            delay_rva = self._read_u32(self.delay_dir_offset)
            delay_size = self._read_u32(self.delay_dir_offset + 4)
            if delay_rva != 0 and delay_size != 0:
                delay_offset = self.rva_to_offset(delay_rva)
                if delay_offset is not None:
                    curr_delay = delay_offset
                    # Each IMAGE_DELAYLOAD_DESCRIPTOR is 32 bytes
                    while curr_delay + 32 <= len(self.data):
                        raw_delay = self.data[curr_delay : curr_delay + 32]
                        if raw_delay == b"\x00" * 32:
                            break

                        attrs, d_name_rva, h_mod_rva, iat_rva, int_rva, bound_rva, unload_rva, ts = struct.unpack(
                            "<IIIIIIII", raw_delay
                        )
                        curr_delay += 32

                        d_name_offset = self.rva_to_offset(d_name_rva)
                        if d_name_offset is None:
                            continue

                        delay_dll_name = self._read_asciiz(d_name_offset)
                        table_rva = int_rva if int_rva != 0 else iat_rva
                        table_offset = self.rva_to_offset(table_rva)
                        delay_symbols: List[ImportSymbol] = []

                        if table_offset is not None:
                            entry_off = table_offset
                            while entry_off + thunk_size <= len(self.data):
                                val = struct.unpack("<Q" if is_64 else "<I", self.data[entry_off : entry_off + thunk_size])[0]
                                entry_off += thunk_size
                                if val == 0:
                                    break
                                if val & ordinal_mask:
                                    delay_symbols.append(ImportSymbol(name=None, ordinal=val & 0xFFFF))
                                else:
                                    n_ptr = val & 0x7FFFFFFFFFFFFFFF if is_64 else val & 0x7FFFFFFF
                                    # In delay load, n_ptr could be RVA or VA depending on attributes bit 0 (dlattrRva = 1)
                                    # If VA: n_ptr - image_base
                                    if n_ptr >= self.image_base:
                                        n_ptr -= self.image_base
                                    n_off = self.rva_to_offset(n_ptr)
                                    if n_off is not None and n_off + 2 < len(self.data):
                                        delay_symbols.append(ImportSymbol(name=self._read_asciiz(n_off + 2), ordinal=None))

                        descriptors.append(ImportDescriptor(dll_name=delay_dll_name, symbols=delay_symbols, is_delay_loaded=True))

        return descriptors
