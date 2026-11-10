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
- [ ] Task 6: Zero-Corruption MASM Assembly JMP Trampoline Generator (`masm` mode)
  - [ ] Step 1: Write unit tests in `tests/test_masm_generator.py` testing generation of `.asm` file with direct `jmp qword ptr [...]` / `jmp dword ptr [...]`, `.def` file, and `dllmain.cpp`.
  - [ ] Step 2: Implement MASM generator in `generator.py` and update `CMakeLists.txt` (`enable_language(ASM_MASM)`) and `build.bat` (`ml64.exe /c stubs.asm`).
  - [ ] Step 3: Run generator tests and verify MASM syntax.
  - [ ] Step 4: Commit task 6.

- [ ] Task 7: Security Mitigations Audit & C++ Symbol Demangler
  - [ ] Step 1: Add tests for DllCharacteristics parsing (ASLR, High-Entropy VA, DEP/NX, Control Flow Guard, SafeSEH) and SHA-256 calculation.
  - [ ] Step 2: Add C++ decorated name demangling using Windows `dbghelp.dll` (`UnDecorateSymbolNameW`) fallback.
  - [ ] Step 3: Run tests to verify parser extensions.
  - [ ] Step 4: Commit task 7.

- [ ] Task 8: Local App Modding Suffix Forwarding & Dedicated File Logging
  - [ ] Step 1: Write tests for `--suffix` option (e.g. forward to `<dll_stem>_orig.dll` in app directory instead of `System32`).
  - [ ] Step 2: Implement configurable target modes: `system` (default) vs `suffix` (local modding) and automatic runtime file logging (`proxy_log.txt`).
  - [ ] Step 3: Verify with unit tests.
  - [ ] Step 4: Commit task 8.

- [ ] Task 9: Terminal ANSI Color UI & Interactive Search/Filtering
  - [ ] Step 1: Implement `--filter <regex_or_query>` and `--ordinal <num>` in CLI.
  - [ ] Step 2: Add ANSI color highlighting (green for forwarded, cyan for functions, yellow for ordinal-only, bold purple for mitigations).
  - [ ] Step 3: Update `test_cli.py` with tests for filter and ordinal lookup.
  - [ ] Step 4: Commit task 9.

- [ ] Task 10: End-to-End MASM Compilation with `ml64.exe` & Documentation Update
  - [ ] Step 1: Generate MASM proxy for `version.dll` and compile with `ml64.exe` + `cl.exe`.
  - [ ] Step 2: Verify binary with `dll-forward-gen` parser.
  - [ ] Step 3: Update `README.md` with MASM mode, security mitigations, and modding guide.
  - [ ] Step 4: Final cleanup of disk C: and final git commit.
