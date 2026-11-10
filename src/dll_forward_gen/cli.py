"""Command-line interface for dll-forward-gen."""

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .batch import run_batch_config
from .diff import diff_export_tables
from .generator import CodeGenerator, GeneratorMode
from .models import ExportSymbol, PeExportInfo
from .pe_parser import PeParser, PeParseError, resolve_dll_path

# ANSI color codes for Windows 10/11 Terminal
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_CYAN = "\033[36m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_MAGENTA = "\033[35m"
COLOR_RED = "\033[31m"
COLOR_DIM = "\033[90m"
COLOR_WHITE = "\033[97m"


def supports_color() -> bool:
    """Check if standard output supports ANSI escape codes."""
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty() or os.environ.get("TERM") == "xterm-256color"


def format_table(
    info: PeExportInfo,
    filter_query: Optional[str] = None,
    ordinal_filter: Optional[int] = None,
    use_color: bool = True,
) -> str:
    """Format export table into a clean ASCII/ANSI view with filtering."""
    c_rst = COLOR_RESET if use_color else ""
    c_bld = COLOR_BOLD if use_color else ""
    c_cyn = COLOR_CYAN if use_color else ""
    c_grn = COLOR_GREEN if use_color else ""
    c_ylw = COLOR_YELLOW if use_color else ""
    c_mag = COLOR_MAGENTA if use_color else ""
    c_dim = COLOR_DIM if use_color else ""
    c_wht = COLOR_WHITE if use_color else ""

    mitigations_str = "None"
    if info.mitigations:
        summary_list = info.mitigations.summary()
        if summary_list:
            mitigations_str = ", ".join(summary_list)

    lines = [
        "",
        f"{c_cyn}{'=' * 82}{c_rst}",
        f" {c_bld}PE EXPORT DIRECTORY: {info.dll_name}{c_rst}",
        f"{c_cyn}{'=' * 82}{c_rst}",
        f" {c_bld}File Path:{c_rst}       {c_dim}{info.filepath}{c_rst}",
        f" {c_bld}Architecture:{c_rst}    {c_wht}{info.arch.value.upper()}{c_rst}",
        f" {c_bld}SHA-256:{c_rst}         {c_dim}{info.sha256[:32]}...{c_rst}",
        f" {c_bld}Mitigations:{c_rst}     {c_mag}{mitigations_str}{c_rst}",
        f" {c_bld}TLS Callbacks:{c_rst}   {c_ylw}{len(info.tls_callbacks)}{c_rst}" + (f" ({', '.join(f'0x{cb:08X}' for cb in info.tls_callbacks)})" if info.tls_callbacks else ""),
        f" {c_bld}Ordinal Base:{c_rst}    {info.ordinal_base}",
        f" {c_bld}Total Exports:{c_rst}   {info.total_count} (Named: {len(info.named_exports)}, Ordinal-only: {len(info.ordinal_only_exports)}, Forwarded: {len(info.forwarded_exports)})",
        f"{c_cyn}{'-' * 82}{c_rst}",
        f"{c_bld}{'ORDINAL':<9} {'RVA':<12} {'TYPE':<14} {'NAME / TARGET'}{c_rst}",
        f"{c_cyn}{'-' * 82}{c_rst}",
    ]

    filtered_symbols = info.symbols
    if ordinal_filter is not None:
        filtered_symbols = [s for s in filtered_symbols if s.ordinal == ordinal_filter]
    elif filter_query:
        query_re = re.compile(filter_query, re.IGNORECASE)
        filtered_symbols = [
            s for s in filtered_symbols if (s.name and query_re.search(s.name)) or (s.forward_name and query_re.search(s.forward_name))
        ]

    for sym in filtered_symbols:
        ord_str = f"@{sym.ordinal}"
        rva_str = f"0x{sym.rva:08X}"
        if sym.is_forwarded:
            type_str = f"{c_grn}[FORWARDED]{c_rst}"
            target_str = f"{sym.name or '<ordinal>'} {c_dim}->{c_rst} {c_grn}{sym.forward_name}{c_rst}"
        elif sym.is_ordinal_only:
            type_str = f"{c_ylw}[ORDINAL-ONLY]{c_rst}"
            target_str = f"{c_ylw}<Ordinal_{sym.ordinal}>{c_rst}"
        else:
            type_str = f"{c_cyn}[FUNCTION]{c_rst}"
            target_str = f"{c_wht}{sym.name}{c_rst}" if sym.name else ""

        if sym.demangled_name:
            target_str += f"\n          {c_dim}↳ {sym.demangled_name}{c_rst}"

        lines.append(f"{ord_str:<9} {c_dim}{rva_str:<12}{c_rst} {type_str:<23} {target_str}")

    if not filtered_symbols:
        lines.append(f"  {c_ylw}(No exports matched filter criteria){c_rst}")

    lines.append(f"{c_cyn}{'=' * 82}{c_rst}")
    return "\n".join(lines)


def audit_target_imports(info: PeExportInfo, target_exe: Path, use_color: bool = True) -> str:
    """Check if target executable's imported functions are satisfied by this DLL."""
    c_rst = COLOR_RESET if use_color else ""
    c_bld = COLOR_BOLD if use_color else ""
    c_cyn = COLOR_CYAN if use_color else ""
    c_grn = COLOR_GREEN if use_color else ""
    c_ylw = COLOR_YELLOW if use_color else ""
    c_red = COLOR_RED if use_color else ""
    c_dim = COLOR_DIM if use_color else ""

    target_parser = PeParser.from_file(target_exe)
    all_imports = target_parser.parse_imports()

    # Match target import descriptor by stem or name
    dll_stem = Path(info.dll_name).stem.lower()
    matching_desc = None
    for desc in all_imports:
        desc_stem = Path(desc.dll_name).stem.lower()
        if desc_stem == dll_stem or desc.dll_name.lower() == info.dll_name.lower():
            matching_desc = desc
            break

    lines = [
        "",
        f"{c_cyn}{'=' * 82}{c_rst}",
        f" {c_bld}TARGET IMPORT AUDIT: {target_exe.name} -> {info.dll_name}{c_rst}",
        f"{c_cyn}{'=' * 82}{c_rst}",
    ]

    if not matching_desc:
        lines.append(f"  {c_ylw}Notice: Target '{target_exe.name}' does not directly import '{info.dll_name}'.{c_rst}")
        lines.append(f"{c_cyn}{'=' * 82}{c_rst}")
        return "\n".join(lines)

    exported_names = {s.name for s in info.symbols if s.name}
    exported_ordinals = {s.ordinal for s in info.symbols}

    covered_count = 0
    missing_count = 0

    load_type_str = f" {c_mag}(Delay-Loaded Dependency){c_rst}" if matching_desc.is_delay_loaded else ""
    lines.append(f" {c_bld}Imported Symbols:{c_rst} {len(matching_desc.symbols)}{load_type_str}")
    lines.append(f"{c_cyn}{'-' * 82}{c_rst}")

    for sym in matching_desc.symbols:
        if sym.is_by_ordinal:
            is_covered = sym.ordinal in exported_ordinals
            sym_name = f"<Ordinal_{sym.ordinal}>"
        else:
            is_covered = sym.name in exported_names
            sym_name = sym.name or ""

        if is_covered:
            covered_count += 1
            status_str = f"{c_grn}[COVERED]{c_rst}"
        else:
            missing_count += 1
            status_str = f"{c_red}[MISSING]{c_rst}"

        lines.append(f"  {status_str} {sym_name}")

    lines.append(f"{c_cyn}{'-' * 82}{c_rst}")
    lines.append(f" Result: {c_grn}{covered_count} covered{c_rst}, {c_red if missing_count > 0 else c_grn}{missing_count} missing{c_rst}")
    lines.append(f"{c_cyn}{'=' * 82}{c_rst}")
    return "\n".join(lines)


def export_info_to_dict(info: PeExportInfo) -> dict:
    """Serialize PeExportInfo to a JSON-serializable dictionary."""
    return {
        "filepath": info.filepath,
        "dll_name": info.dll_name,
        "arch": info.arch.value,
        "sha256": info.sha256,
        "mitigations": info.mitigations.summary() if info.mitigations else [],
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
                "demangled_name": s.demangled_name,
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
        description="Fast, zero-dependency PE export forwarder & C++/MASM proxy stub generator for Windows.",
    )
    parser.add_argument(
        "dll",
        nargs="?",
        default=None,
        type=str,
        help="Path to target DLL (or system DLL name like 'version.dll', 'dxgi.dll')",
    )
    parser.add_argument(
        "--batch",
        type=Path,
        default=None,
        help="Execute batch proxy generation from a JSON configuration file",
    )
    parser.add_argument(
        "--export-sdk",
        type=Path,
        default=None,
        help="Export all zero-dependency C++20 Modding & Hooking SDK headers into specified directory",
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
        choices=["pragma", "def", "trampoline", "masm"],
        default="pragma",
        help="Forwarding strategy: 'pragma' (MSVC zero-overhead), 'masm' (pure assembly JMP stubs), 'trampoline' (C++ wrapper), 'def' (.def file)",
    )
    parser.add_argument(
        "-t",
        "--target-dll",
        type=str,
        default=None,
        help="Explicit path to original DLL to forward to (default: C:\\Windows\\System32\\<dll_name>)",
    )
    parser.add_argument(
        "--suffix",
        type=str,
        default=None,
        help="Modding suffix mode: forward to <dll_name><suffix>.dll in the application folder (e.g. '_orig')",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Filter exports by symbol name or forward target (substring or regex)",
    )
    parser.add_argument(
        "--ordinal",
        type=int,
        default=None,
        help="Inspect specific ordinal number only",
    )
    parser.add_argument(
        "--file-log",
        action="store_true",
        help="Enable runtime file logging (proxy_log.txt) in generated proxy code",
    )
    parser.add_argument(
        "--check-target",
        type=Path,
        default=None,
        help="Check if an executable's imports are satisfied by this DLL",
    )
    parser.add_argument(
        "--diff",
        type=str,
        default=None,
        help="Compare export table of this DLL against a second DLL",
    )
    parser.add_argument(
        "--hook",
        action="append",
        default=[],
        help="Name of symbol to intercept with a custom C++ detour hook (can be specified multiple times)",
    )
    parser.add_argument(
        "-H",
        "--header-only",
        action="store_true",
        help="Generate a standalone embeddable C/C++ forwarding header (.h) instead of a full project",
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
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
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
    use_color = supports_color() and not args.no_color

    if args.batch:
        try:
            generated = run_batch_config(args.batch)
            c_grn = COLOR_GREEN if use_color else ""
            c_rst = COLOR_RESET if use_color else ""
            print(f"\n{c_grn}[+] Batch generation completed ({len(generated)} proxies generated):{c_rst}")
            for g in generated:
                print(f"    - {g}")
            return 0
        except Exception as e:
            c_red = COLOR_RED if use_color else ""
            c_rst = COLOR_RESET if use_color else ""
            print(f"{c_red}[ERROR] Batch failed: {e}{c_rst}", file=sys.stderr)
            return 1

    if args.export_sdk:
        target_dir = args.export_sdk
        target_dir.mkdir(parents=True, exist_ok=True)
        sdk_pkg_dir = Path(__file__).parent / "sdk"
        if not sdk_pkg_dir.is_dir():
            sdk_pkg_dir = Path(__file__).resolve().parent.parent.parent / "sdk"
        headers = list(sdk_pkg_dir.glob("*.hpp"))
        for h in headers:
            shutil.copy2(h, target_dir / h.name)
        c_grn = COLOR_GREEN if use_color else ""
        c_rst = COLOR_RESET if use_color else ""
        print(f"\n{c_grn}[+] Successfully exported {len(headers)} C++20 SDK headers to: {target_dir}{c_rst}")
        for h in headers:
            print(f"    - {h.name}")
        return 0

    if not args.dll:
        print("[ERROR] Target DLL, --batch configuration, or --export-sdk required.", file=sys.stderr)
        return 1

    try:
        resolved_path = resolve_dll_path(args.dll)
        parser = PeParser.from_file(resolved_path)
        info = parser.parse()
    except (FileNotFoundError, PeParseError) as e:
        c_red = COLOR_RED if use_color else ""
        c_rst = COLOR_RESET if use_color else ""
        print(f"{c_red}[ERROR] {e}{c_rst}", file=sys.stderr)
        return 1

    if args.json:
        data = export_info_to_dict(info)
        print(json.dumps(data, indent=2))
        return 0

    if args.diff:
        try:
            second_path = resolve_dll_path(args.diff)
            second_parser = PeParser.from_file(second_path)
            second_info = second_parser.parse()
            diff_res = diff_export_tables(info, second_info)
            print(diff_res.format_report(use_color=use_color))
            return 0
        except (FileNotFoundError, PeParseError) as e:
            c_red = COLOR_RED if use_color else ""
            c_rst = COLOR_RESET if use_color else ""
            print(f"{c_red}[ERROR] Diff target: {e}{c_rst}", file=sys.stderr)
            return 1

    if args.check_target:
        print(audit_target_imports(info, args.check_target, use_color=use_color))
        if args.dump_only:
            return 0

    if args.dump_only or args.filter or args.ordinal is not None:
        table_output = format_table(
            info,
            filter_query=args.filter,
            ordinal_filter=args.ordinal,
            use_color=use_color,
        )
        print(table_output)
        if args.dump_only:
            return 0

    out_dir = args.output_dir
    if out_dir is None:
        out_dir = Path.cwd() / f"{Path(info.dll_name).stem}_proxy"

    # Compute target DLL
    target_dll = args.target_dll
    if args.suffix:
        stem = Path(info.dll_name).stem
        target_dll = f"{stem}{args.suffix}.dll"

    if args.header_only:
        gen = CodeGenerator(
            info=info,
            mode=GeneratorMode.PRAGMA,
            target_dll=target_dll,
            enable_logging=not args.no_logging,
            enable_file_log=args.file_log,
            hooked_symbols=args.hook,
        )
        hdr_src = gen.generate_header_only_source()
        if args.output_dir:
            out_file = args.output_dir if args.output_dir.suffix == ".h" else args.output_dir / f"{Path(info.dll_name).stem}_forward.h"
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(hdr_src, encoding="utf-8")
            print(f"[+] Generated header-only forwarding file: {out_file}")
        else:
            print(hdr_src)
        return 0

    mode = GeneratorMode(args.mode)
    gen = CodeGenerator(
        info=info,
        mode=mode,
        target_dll=target_dll,
        enable_logging=not args.no_logging,
        enable_file_log=args.file_log,
        hooked_symbols=args.hook,
    )

    created_files = gen.emit_project(out_dir)

    c_grn = COLOR_GREEN if use_color else ""
    c_bld = COLOR_BOLD if use_color else ""
    c_rst = COLOR_RESET if use_color else ""

    print(f"\n{c_grn}{c_bld}[+] Generated {mode.value.upper()} proxy project in: {out_dir}{c_rst}")
    for f in created_files:
        print(f"    - {f.name} ({f.stat().st_size} bytes)")

    print("\nNext steps:")
    print(f"  cd {out_dir}")
    print("  build.bat  (or use CMake to build with Visual Studio / Ninja)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
