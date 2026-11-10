"""Command-line interface for dll-forward-gen."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .generator import CodeGenerator, GeneratorMode
from .models import PeExportInfo
from .pe_parser import PeParser, PeParseError


def resolve_dll_path(name_or_path: str) -> Path:
    """Resolve DLL input argument to an existing file path."""
    p = Path(name_or_path)
    if p.is_file():
        return p.resolve()

    # If only a filename was given (e.g. "version.dll"), check common Windows directories
    search_dirs = [
        Path.cwd(),
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32",
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SysWOW64",
    ]

    for d in search_dirs:
        candidate = d / name_or_path
        if candidate.is_file():
            return candidate.resolve()
        # Also try appending .dll if missing
        if not name_or_path.lower().endswith(".dll"):
            candidate_dll = d / f"{name_or_path}.dll"
            if candidate_dll.is_file():
                return candidate_dll.resolve()

    raise FileNotFoundError(f"Could not locate DLL '{name_or_path}' locally or in Windows system directories.")


def format_table(info: PeExportInfo) -> str:
    """Format export table into a clean ASCII view."""
    lines = [
        "",
        "=" * 78,
        f" PE EXPORT DIRECTORY: {info.dll_name}",
        "=" * 78,
        f" File Path:       {info.filepath}",
        f" Architecture:    {info.arch.value.upper()}",
        f" Ordinal Base:    {info.ordinal_base}",
        f" Total Exports:   {info.total_count} (Named: {len(info.named_exports)}, Ordinal-only: {len(info.ordinal_only_exports)}, Forwarded: {len(info.forwarded_exports)})",
        "-" * 78,
        f"{'ORDINAL':<9} {'RVA':<12} {'TYPE':<14} {'NAME / FORWARD TARGET'}",
        "-" * 78,
    ]

    for sym in info.symbols:
        ord_str = f"@{sym.ordinal}"
        rva_str = f"0x{sym.rva:08X}"
        if sym.is_forwarded:
            type_str = "[FORWARDED]"
            target_str = f"{sym.name or '<ordinal>'} -> {sym.forward_name}"
        elif sym.is_ordinal_only:
            type_str = "[ORDINAL-ONLY]"
            target_str = f"<Ordinal_{sym.ordinal}>"
        else:
            type_str = "[FUNCTION]"
            target_str = sym.name or ""

        lines.append(f"{ord_str:<9} {rva_str:<12} {type_str:<14} {target_str}")

    lines.append("=" * 78)
    return "\n".join(lines)


def export_info_to_dict(info: PeExportInfo) -> dict:
    """Serialize PeExportInfo to a JSON-serializable dictionary."""
    return {
        "filepath": info.filepath,
        "dll_name": info.dll_name,
        "arch": info.arch.value,
        "timestamp": info.timestamp,
        "ordinal_base": info.ordinal_base,
        "total_exports": info.total_count,
        "named_count": len(info.named_exports),
        "ordinal_only_count": len(info.ordinal_only_exports),
        "forwarded_count": len(info.forwarded_exports),
        "symbols": [
            {
                "ordinal": s.ordinal,
                "rva": f"0x{s.rva:08X}",
                "name": s.name,
                "is_ordinal_only": s.is_ordinal_only,
                "is_forwarded": s.is_forwarded,
                "forward_name": s.forward_name,
            }
            for s in info.symbols
        ],
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dll-forward-gen",
        description="Fast, zero-dependency PE export forwarder & C++ proxy stub generator for Windows.",
    )
    parser.add_argument(
        "dll",
        type=str,
        help="Path to target DLL (or system DLL name like 'version.dll', 'dxgi.dll')",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="Destination directory for generated proxy project (default: ./<name>_proxy)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=str,
        choices=["pragma", "def", "trampoline"],
        default="pragma",
        help="Forwarding strategy: 'pragma' (MSVC /export), 'def' (.def file), 'trampoline' (dynamic LoadLibrary wrapper)",
    )
    parser.add_argument(
        "-t",
        "--target-dll",
        type=str,
        default=None,
        help="Explicit path to original DLL to forward to (default: C:\\Windows\\System32\\<dll_name>)",
    )
    parser.add_argument(
        "--dump-only",
        action="store_true",
        help="Print export directory details and exit without generating files",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output parsed exports as structured JSON to stdout",
    )
    parser.add_argument(
        "--no-logging",
        action="store_true",
        help="Disable OutputDebugString logging in generated proxy code",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"dll-forward-gen {__version__}",
    )

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        resolved_path = resolve_dll_path(args.dll)
        parser = PeParser.from_file(resolved_path)
        info = parser.parse()
    except (FileNotFoundError, PeParseError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    if args.json:
        data = export_info_to_dict(info)
        print(json.dumps(data, indent=2))
        return 0

    if args.dump_only:
        print(format_table(info))
        return 0

    # Print summary banner
    print(format_table(info))

    out_dir = args.output_dir
    if out_dir is None:
        out_dir = Path.cwd() / f"{Path(info.dll_name).stem}_proxy"

    mode = GeneratorMode(args.mode)
    gen = CodeGenerator(
        info=info,
        mode=mode,
        target_dll=args.target_dll,
        enable_logging=not args.no_logging,
    )

    created_files = gen.emit_project(out_dir)

    print(f"\n[+] Generated {mode.value.upper()} proxy project in: {out_dir}")
    for f in created_files:
        print(f"    - {f.name} ({f.stat().st_size} bytes)")

    print("\nNext steps:")
    print(f"  cd {out_dir}")
    print("  build.bat  (or use CMake to build with Visual Studio / Ninja)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
