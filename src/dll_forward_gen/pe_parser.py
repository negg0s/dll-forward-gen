"""Zero-dependency PE (Portable Executable) binary parser for extracting DLL exports."""

import struct
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Union

from .models import ExportSymbol, PeArch, PeExportInfo


class PeParseError(Exception):
    """Raised when PE parsing fails due to invalid format or corrupted headers."""
    pass


class PeParser:
    """Parses PE32 and PE32+ (x86 and x64) binaries to extract export directories."""

    IMAGE_DOS_SIGNATURE = 0x5A4D  # "MZ"
    IMAGE_NT_SIGNATURE = 0x00004550  # "PE\0\0"
    OPTIONAL_HDR_MAGIC_PE32 = 0x010B
    OPTIONAL_HDR_MAGIC_PE32_PLUS = 0x020B

    def __init__(self, data: bytes, filepath: str = ""):
        self.data = data
        self.filepath = filepath
        # Section tuple: (virtual_address, virtual_size, raw_data_ptr, raw_data_size)
        self.sections: List[Tuple[int, int, int, int]] = []
        self.arch: PeArch = PeArch.UNKNOWN
        self.pe_offset: int = 0
        self.export_rva: int = 0
        self.export_size: int = 0

    @classmethod
    def from_file(cls, filepath: Union[str, Path]) -> "PeParser":
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"DLL not found: {filepath}")
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

    def parse(self) -> PeExportInfo:
        """Parse PE headers and extract export table symbols."""
        if len(self.data) < 64:
            raise PeParseError("Buffer too small to contain IMAGE_DOS_HEADER")

        # 1. DOS Header
        dos_magic = self._read_u16(0)
        if dos_magic != self.IMAGE_DOS_SIGNATURE:
            raise PeParseError(f"Invalid DOS signature 0x{dos_magic:04X} (expected 'MZ' 0x5A4D)")

        self.pe_offset = self._read_u32(0x3C)
        if self.pe_offset + 4 > len(self.data):
            raise PeParseError(f"Invalid e_lfanew pointer 0x{self.pe_offset:X}")

        # 2. NT Signature
        nt_sig = self._read_u32(self.pe_offset)
        if nt_sig != self.IMAGE_NT_SIGNATURE:
            raise PeParseError(f"Invalid NT signature 0x{nt_sig:08X} (expected 'PE\\0\\0')")

        # 3. File Header
        file_hdr_offset = self.pe_offset + 4
        machine = self._read_u16(file_hdr_offset)
        num_sections = self._read_u16(file_hdr_offset + 2)
        timestamp = self._read_u32(file_hdr_offset + 4)
        size_of_opt_hdr = self._read_u16(file_hdr_offset + 16)
        characteristics = self._read_u16(file_hdr_offset + 18)

        self.arch = PeArch.from_machine(machine)

        # 4. Optional Header
        opt_hdr_offset = file_hdr_offset + 20
        if size_of_opt_hdr < 2:
            raise PeParseError("Missing Optional Header")

        opt_magic = self._read_u16(opt_hdr_offset)
        if opt_magic == self.OPTIONAL_HDR_MAGIC_PE32:
            # 32-bit PE
            export_dir_offset = opt_hdr_offset + 96
        elif opt_magic == self.OPTIONAL_HDR_MAGIC_PE32_PLUS:
            # 64-bit PE
            export_dir_offset = opt_hdr_offset + 112
        else:
            raise PeParseError(f"Unsupported Optional Header magic: 0x{opt_magic:04X}")

        if opt_hdr_offset + size_of_opt_hdr > len(self.data):
            raise PeParseError("Optional Header exceeds file size")

        if export_dir_offset + 8 <= opt_hdr_offset + size_of_opt_hdr:
            self.export_rva = self._read_u32(export_dir_offset)
            self.export_size = self._read_u32(export_dir_offset + 4)
        else:
            self.export_rva = 0
            self.export_size = 0

        # 5. Section Headers
        sections_offset = opt_hdr_offset + size_of_opt_hdr
        self.sections.clear()
        for i in range(num_sections):
            sec_ptr = sections_offset + (i * 40)
            if sec_ptr + 40 > len(self.data):
                break
            virt_size = self._read_u32(sec_ptr + 8)
            virt_addr = self._read_u32(sec_ptr + 12)
            raw_size = self._read_u32(sec_ptr + 16)
            raw_ptr = self._read_u32(sec_ptr + 20)
            self.sections.append((virt_addr, virt_size, raw_ptr, raw_size))

        # Determine default DLL name from filepath or export table
        fallback_name = Path(self.filepath).name if self.filepath else "unknown.dll"

        # If no export directory present, return empty result
        if self.export_rva == 0 or self.export_size == 0:
            return PeExportInfo(
                filepath=self.filepath,
                dll_name=fallback_name,
                arch=self.arch,
                timestamp=timestamp,
                ordinal_base=1,
                symbols=[],
            )

        # 6. Parse Export Directory
        export_file_offset = self.rva_to_offset(self.export_rva)
        if export_file_offset is None:
            raise PeParseError(f"Failed to resolve Export Directory RVA 0x{self.export_rva:08X} to file offset")

        # IMAGE_EXPORT_DIRECTORY structure (40 bytes)
        # Offset 12: Name (RVA)
        # Offset 16: Base (DWORD)
        # Offset 20: NumberOfFunctions (DWORD)
        # Offset 24: NumberOfNames (DWORD)
        # Offset 28: AddressOfFunctions (RVA)
        # Offset 32: AddressOfNames (RVA)
        # Offset 36: AddressOfNameOrdinals (RVA)
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

        # Map function table indices to names
        # index (0..num_functions-1) -> function name
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

        # Read AddressOfFunctions table
        symbols: List[ExportSymbol] = []
        functions_offset = self.rva_to_offset(addr_functions_rva)
        if functions_offset is not None:
            for idx in range(num_functions):
                fn_rva = self._read_u32(functions_offset + (idx * 4))
                if fn_rva == 0:
                    # Unused slot / sparse export table
                    continue

                ordinal = ordinal_base + idx
                name = index_to_name.get(idx)

                # Check if forwarded export: RVA falls inside Export Directory range
                is_fwd = self.export_rva <= fn_rva < (self.export_rva + self.export_size)
                fwd_str = None
                if is_fwd:
                    fwd_offset = self.rva_to_offset(fn_rva)
                    if fwd_offset is not None:
                        fwd_str = self._read_asciiz(fwd_offset)

                symbols.append(
                    ExportSymbol(
                        ordinal=ordinal,
                        rva=fn_rva,
                        name=name,
                        is_forwarded=is_fwd,
                        forward_name=fwd_str,
                    )
                )

        return PeExportInfo(
            filepath=self.filepath,
            dll_name=dll_name,
            arch=self.arch,
            timestamp=timestamp,
            ordinal_base=ordinal_base,
            symbols=symbols,
        )
