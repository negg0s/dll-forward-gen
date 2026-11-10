# dll-forward-gen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fast, zero-dependency PE (Portable Executable) export analyzer and C/C++ forwarding/stub generator for Windows that parses DLL export tables and generates build-ready proxy projects for API debugging, tracing, and instrumentation.

**Architecture:** Pure Python 3 core without external runtime dependencies (using `struct`, `dataclasses`, `pathlib`, `argparse`). Modular design split into a robust PE32/PE32+ binary parser, code generators (Linker Pragma, Module Definition `.def`, and Dynamic Trampoline wrapper with `DllMain`), and a formatted CLI.

**Tech Stack:** Python 3.12 (standard library only: `struct`, `dataclasses`, `pathlib`, `argparse`), C++20 / C templates, MSVC / Clang build scripts (`CMakeLists.txt`, `build.bat`), MASM (`ml64.exe` / `ml.exe`).

**Spec:** Zero-dependency Windows PE export parsing, supporting x86 and x64 DLLs, ordinal-only exports, forwarded exports, and multiple proxy stub generation modes. All code located strictly in `D:\dll-forward-gen`.

## Global Constraints

- Storage location: strictly `D:\dll-forward-gen` — no files or caches on `C:\`.
- Dependencies: Python 3 standard library only (`struct`, `dataclasses`, `typing`, `pathlib`, `argparse`, `hashlib`). No third-party packages required to run (`zero-deps`).
- Architectures supported: PE32 (x86 32-bit) and PE32+ (x64 64-bit).
- Edge cases handled: Ordinal-only exports (no name), pre-forwarded exports (`DLL.Symbol`), non-contiguous ordinal bases.

## Review Focus

1. Correct RVA-to-File-Offset calculation across multiple PE sections (handling VirtualSize vs SizeOfRawData).
2. Proper detection of forwarded exports whose RVA falls inside the Export Directory data directory range.
3. Safe handling of ordinal-only exports in `#pragma comment(linker, ...)` and `.def` formats.
4. Correct generation of `DllMain` and dynamic wrapper trampolines avoiding infinite recursion.
5. Windows file path quoting and casing in generated C++ pragmas and build scripts.
6. Register and stack preservation in MASM jump trampolines (`jmp qword ptr [...]`).

## Plan Tasks

### Phase 1: MVP Core (Completed)
- [x] Task 1: Scaffolding and PE Data Models
- [x] Task 2: Binary PE Parser (Zero-Dependency)
- [x] Task 3: Stub & Forwarding Code Generators (Pragma, Def, Trampoline)
- [x] Task 4: CLI Interface & Formatted Output
- [x] Task 5: End-to-End Verification & MSVC Compilation Test

### Phase 2: Enterprise-Grade Advanced Extensions
- [x] Task 6: Zero-Corruption MASM Assembly JMP Trampoline Generator (`masm` mode)
  - [x] Step 1: Write unit tests in `tests/test_masm_generator.py` testing generation of `.asm` file with direct `jmp qword ptr [...]` / `jmp dword ptr [...]`, `.def` file, and `dllmain.cpp`.
  - [x] Step 2: Implement MASM generator in `generator.py` and update `CMakeLists.txt` (`enable_language(ASM_MASM)`) and `build.bat` (`ml64.exe /c stubs.asm`).
  - [x] Step 3: Run generator tests and verify MASM syntax.
  - [x] Step 4: Commit task 6.

- [x] Task 7: Security Mitigations Audit & C++ Symbol Demangler
  - [x] Step 1: Add tests for DllCharacteristics parsing (ASLR, High-Entropy VA, DEP/NX, Control Flow Guard, SafeSEH) and SHA-256 calculation.
  - [x] Step 2: Add C++ decorated name demangling using Windows `dbghelp.dll` (`UnDecorateSymbolNameW`) fallback.
  - [x] Step 3: Run tests to verify parser extensions.
  - [x] Step 4: Commit task 7.

- [x] Task 8: Local App Modding Suffix Forwarding & Dedicated File Logging
  - [x] Step 1: Write tests for `--suffix` option (e.g. forward to `<dll_stem>_orig.dll` in app directory instead of `System32`).
  - [x] Step 2: Implement configurable target modes: `system` (default) vs `suffix` (local modding) and automatic runtime file logging (`proxy_log.txt`).
  - [x] Step 3: Verify with unit tests.
  - [x] Step 4: Commit task 8.

- [x] Task 9: Terminal ANSI Color UI & Interactive Search/Filtering
  - [x] Step 1: Implement `--filter <regex_or_query>` and `--ordinal <num>` in CLI.
  - [x] Step 2: Add ANSI color highlighting (green for forwarded, cyan for functions, yellow for ordinal-only, bold purple for mitigations).
  - [x] Step 3: Update `test_cli.py` with tests for filter and ordinal lookup.
  - [x] Step 4: Commit task 9.

- [x] Task 10: End-to-End MASM Compilation with `ml64.exe` & Documentation Update
  - [x] Step 1: Generate MASM proxy for `version.dll` and compile with `ml64.exe` + `cl.exe`.
  - [x] Step 2: Verify binary with `dll-forward-gen` parser.
  - [x] Step 3: Update `README.md` with MASM mode, security mitigations, and modding guide.
  - [x] Step 4: Final cleanup of disk C: and final git commit.

### Phase 3: Elite Reversing & Systems Tooling
- [x] Task 11: PE Import Directory Parser & Executable Compatibility Checker (`--check-target <exe>`)
  - [x] Step 1: Write unit tests in `tests/test_import_parser.py` parsing import tables of system binaries (e.g. `notepad.exe` or `cmd.exe`).
  - [x] Step 2: Implement `parse_imports()` in `src/dll_forward_gen/pe_parser.py` (both 32-bit and 64-bit INT/IAT).
  - [x] Step 3: Add `--check-target` flag to CLI to cross-reference target executable imports with DLL exports.
  - [x] Step 4: Run tests and commit.

- [x] Task 12: Export Table Diff Engine (`dll-forward-gen diff <dll1> <dll2>`)
  - [x] Step 1: Write unit tests in `tests/test_diff.py` for added, removed, ordinal-shifted, and modified exports.
  - [x] Step 2: Implement `diff_exports()` in `src/dll_forward_gen/diff.py`.
  - [x] Step 3: Add `diff` subcommand to CLI with visual colored diff table.
  - [x] Step 4: Run tests and commit.

- [x] Task 13: Selective Function Hooking Generator (`--hook <name>`)
  - [x] Step 1: Write unit tests in `tests/test_hooking.py` verifying selective detour emission for specified symbols while forwarding remaining symbols.
  - [x] Step 2: Implement selective detour stubs in `generator.py`.
  - [x] Step 3: Verify MSVC compilation of generated hook proxy.
  - [x] Step 4: Commit task 13.

- [x] Task 14: Native C++20 Header-Only Parser & Standalone CLI
  - [x] Step 1: Write `cpp/dll_forward_gen.hpp` with zero-dependency C++20 PE parser and generator.
  - [x] Step 2: Write `cpp/main.cpp` standalone CLI.
  - [x] Step 3: Test compilation with `cl.exe /std:c++20`.
  - [x] Step 4: Commit task 14.

- [x] Task 15: GitHub Actions CI Workflow, Documentation, & Final Disk C Cleanup
  - [x] Step 1: Add `.github/workflows/ci.yml` running unit tests and MSVC builds on Windows runner.
  - [x] Step 2: Update `README.md` with diffing, hook generation, and target verification examples.
  - [x] Step 3: Run full test suite, purge temp files, and commit.

### Phase 4: Full Modding & Instrumentation SDK
- [ ] Task 16: Zero-Dependency Native x64/x86 Inline Hooking Engine (`sdk/inline_hook.hpp`)
  - [ ] Step 1: Write header-only inline hooking engine with atomic byte patching and trampoline generation.
  - [ ] Step 2: Write unit test in C++ verifying memory patching and hook execution.
  - [ ] Step 3: Integrate with proxy generator template when `--inline-hook` is requested.
  - [ ] Step 4: Run tests and commit.

- [ ] Task 17: High-Performance Memory Pattern Scanner (`sdk/pattern_scan.hpp`)
  - [ ] Step 1: Implement IDA-style byte pattern scanner (`48 89 5C ? ? 48 83 EC`) across PE sections.
  - [ ] Step 2: Write test verifying pattern detection in memory buffers.
  - [ ] Step 3: Commit.

- [ ] Task 18: Embeddable Single-File Header-Only Forwarder (`--header-only`)
  - [ ] Step 1: Add `--header-only` option in `generator.py` and `cli.py` generating `<dll>_forward.h`.
  - [ ] Step 2: Write unit tests in `tests/test_header_only.py`.
  - [ ] Step 3: Commit.

- [ ] Task 19: Batch Proxy Generation (`--batch <config.json>`)
  - [ ] Step 1: Implement batch schema and runner in `src/dll_forward_gen/batch.py`.
  - [ ] Step 2: Write unit tests in `tests/test_batch.py`.
  - [ ] Step 3: Add CLI support and commit.

- [ ] Task 20: Full Verification, Documentation Overhaul, & Final C: Cleanup
  - [ ] Step 1: Run complete 40+ unit test suite.
  - [ ] Step 2: Update `README.md` with SDK guides and code snippets.
  - [ ] Step 3: Clean temporary cache on drive C: and final git commit.
