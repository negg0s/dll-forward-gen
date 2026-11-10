"""Pure Python Zero-Dependency COFF Import Library (.lib) Generator.

Generates standard Microsoft Short Import Format (.lib) archives compatible
with MSVC link.exe, LLVM lld-link, MinGW, and GCC.
"""

import struct
from pathlib import Path
from typing import List, Tuple, Union
from .models import PeArch, PeExportInfo, ExportSymbol


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

IMPORT_OBJECT_HDR_SIG2 = 0xFFFF
IMPORT_OBJECT_CODE = 0
IMPORT_OBJECT_ORDINAL = 0
IMPORT_OBJECT_NAME = 1
IMPORT_OBJECT_NAME_NOPREFIX = 2
IMPORT_OBJECT_NAME_UNDECORATE = 3


def _format_ar_header(name: str, size: int, timestamp: int = 0) -> bytes:
    """Format standard 60-byte AR archive member header."""
    name_field = f"{name:<16}".encode("ascii")[:16]
    date_field = f"{timestamp:<12}".encode("ascii")[:12]
    uid_field = b"0     "
    gid_field = b"0     "
    mode_field = b"0       "
    size_field = f"{size:<10}".encode("ascii")[:10]
    magic = b"`\n"
    return name_field + date_field + uid_field + gid_field + mode_field + size_field + magic


def create_import_object_record(
    symbol_name: str,
    dll_name: str,
    arch: PeArch,
    ordinal: int = 0,
    is_ordinal_only: bool = False,
    timestamp: int = 0,
) -> bytes:
    """Generate a single Short Import Header record (Format 3)."""
    if arch == PeArch.X86:
        machine = IMAGE_FILE_MACHINE_I386
    elif arch == PeArch.ARM64:
        machine = IMAGE_FILE_MACHINE_ARM64
    else:
        machine = IMAGE_FILE_MACHINE_AMD64

    sym_bytes = symbol_name.encode("utf-8") + b"\x00"
    dll_bytes = dll_name.encode("utf-8") + b"\x00"
    data_payload = sym_bytes + dll_bytes

    name_type = IMPORT_OBJECT_ORDINAL if is_ordinal_only else IMPORT_OBJECT_NAME
    type_type = IMPORT_OBJECT_CODE
    flags = (type_type & 0x3) | ((name_type & 0x7) << 2)

    # 20-byte IMPORT_OBJECT_HEADER
    header = struct.pack(
        "<HHHHIIHH",
        0,                        # Sig1 (IMAGE_FILE_MACHINE_UNKNOWN)
        IMPORT_OBJECT_HDR_SIG2,   # Sig2 (0xFFFF)
        0,                        # Version
        machine,                  # Machine
        timestamp,                # TimeDateStamp
        len(data_payload),        # SizeOfData
        ordinal,                  # Ordinal / Hint
        flags,                    # Flags
    )

    return header + data_payload


class ImportLibGenerator:
    """Generates COFF import libraries (.lib) from PE export specifications."""

    def __init__(self, info: PeExportInfo):
        self.info = info

    def build_library_bytes(self) -> bytes:
        """Construct a complete binary COFF archive (.lib) for the exports."""
        symbols_to_export: List[Tuple[str, ExportSymbol]] = []

        # Determine symbols to include in the index
        for sym in self.info.symbols:
            name = sym.name if sym.name else f"Ordinal_{sym.ordinal}"
            symbols_to_export.append((name, sym))
            # Also create __imp_ prefix alias for dynamic imports
            imp_name = f"__imp_{name}"
            symbols_to_export.append((imp_name, sym))

        # Sort symbols alphabetically for the archive symbol index
        symbols_to_export.sort(key=lambda s: s[0])

        # Generate Import Object records for each unique export symbol
        member_records: List[Tuple[str, bytes, ExportSymbol]] = []
        for sym in self.info.symbols:
            sym_name = sym.name if sym.name else ""
            record = create_import_object_record(
                symbol_name=sym_name,
                dll_name=self.info.dll_name,
                arch=self.info.arch,
                ordinal=sym.ordinal,
                is_ordinal_only=sym.is_ordinal_only,
                timestamp=self.info.timestamp,
            )
            member_name = f"{self.info.dll_name}/"
            member_records.append((member_name, record, sym))

        # Calculate offsets
        # Structure:
        # 1. "!<arch>\n" (8 bytes)
        # 2. First Linker Member
        # 3. Second Linker Member
        # 4. Member Object records...

        # Build First Linker Member (Big Endian)
        str_table = b"".join(name.encode("utf-8") + b"\x00" for name, _ in symbols_to_export)
        num_syms = len(symbols_to_export)

        # Approximate size to compute base offset
        first_member_body_size = 4 + (num_syms * 4) + len(str_table)
        first_member_total = 60 + first_member_body_size + (first_member_body_size % 2)

        # Build Second Linker Member (Little Endian)
        num_members = len(member_records)
        second_member_body_size = (
            4 + (num_members * 4) + 4 + (num_syms * 2) + len(str_table)
        )
        second_member_total = 60 + second_member_body_size + (second_member_body_size % 2)

        # Calculate starting offset for the import object members
        member_start_offset = 8 + first_member_total + second_member_total

        member_offsets: List[int] = []
        current_offset = member_start_offset

        for _, rec, _ in member_records:
            member_offsets.append(current_offset)
            rec_total = 60 + len(rec) + (len(rec) % 2)
            current_offset += rec_total

        # Map each symbol in symbols_to_export to its member index (1-based)
        # Member indices correspond to the export symbol's index in member_records
        sym_to_member_idx: List[int] = []
        sym_to_member_offset: List[int] = []

        export_to_member_idx = {sym: idx for idx, (_, _, sym) in enumerate(member_records, start=1)}

        for name, sym in symbols_to_export:
            mem_idx = export_to_member_idx[sym]
            sym_to_member_idx.append(mem_idx)
            sym_to_member_offset.append(member_offsets[mem_idx - 1])

        # 1. Finalize First Linker Member
        first_body = struct.pack(">I", num_syms)
        for off in sym_to_member_offset:
            first_body += struct.pack(">I", off)
        first_body += str_table
        if len(first_body) % 2 != 0:
            first_body += b"\n"

        first_hdr = _format_ar_header("/", len(first_body) - (1 if first_body.endswith(b"\n") and (len(first_body) - 1) % 2 != 0 else 0), self.info.timestamp)
        first_chunk = _format_ar_header("/", len(first_body) if len(first_body) % 2 == 0 else len(first_body) - 1, self.info.timestamp)
        # Proper size field: exact unpadded content size
        unpadded_first_size = 4 + (num_syms * 4) + len(str_table)
        first_hdr = _format_ar_header("/", unpadded_first_size, self.info.timestamp)
        first_member = first_hdr + (first_body if len(first_body) % 2 == 0 else first_body + b"\n")

        # 2. Finalize Second Linker Member
        second_body = struct.pack("<I", num_members)
        for off in member_offsets:
            second_body += struct.pack("<I", off)
        second_body += struct.pack("<I", num_syms)
        for m_idx in sym_to_member_idx:
            second_body += struct.pack("<H", m_idx)
        second_body += str_table
        unpadded_second_size = len(second_body)
        if len(second_body) % 2 != 0:
            second_body += b"\n"

        second_hdr = _format_ar_header("/", unpadded_second_size, self.info.timestamp)
        second_member = second_hdr + second_body

        # 3. Assemble full archive
        archive = bytearray(b"!<arch>\n")
        archive.extend(first_member)
        archive.extend(second_member)

        for name, rec, _ in member_records:
            hdr = _format_ar_header(name, len(rec), self.info.timestamp)
            archive.extend(hdr)
            archive.extend(rec)
            if len(rec) % 2 != 0:
                archive.extend(b"\n")

        return bytes(archive)

    def write_lib(self, output_path: Union[str, Path]) -> Path:
        """Write the generated .lib import library to disk."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        data = self.build_library_bytes()
        out.write_bytes(data)
        return out
