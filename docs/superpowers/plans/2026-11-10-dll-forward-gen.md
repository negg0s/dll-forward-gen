# dll-forward-gen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fast, zero-dependency PE (Portable Executable) export analyzer and C/C++ forwarding/stub generator for Windows that parses DLL export tables and generates build-ready proxy projects for API debugging, tracing, and instrumentation.

**Architecture:** Pure Python 3 core without external runtime dependencies (using `struct`, `dataclasses`, `pathlib`, `argparse`). Modular design split into a robust PE32/PE32+ binary parser, code generators (Linker Pragma, Module Definition `.def`, and Dynamic Trampoline wrapper with `DllMain`), and a formatted CLI.

**Tech Stack:** Python 3.12 (standard library only: `struct`, `dataclasses`, `pathlib`, `argparse`), C++20 / C templates, MSVC / Clang build scripts (`CMakeLists.txt`, `build.bat`).

**Spec:** Zero-dependency Windows PE export parsing, supporting x86 and x64 DLLs, ordinal-only exports, forwarded exports, and multiple proxy stub generation modes. All code located strictly in `D:\dll-forward-gen`.

## Global Constraints

- Storage location: strictly `D:\dll-forward-gen` — no files or caches on `C:\`.
- Dependencies: Python 3 standard library only (`struct`, `dataclasses`, `typing`, `pathlib`, `argparse`). No third-party packages required to run (`zero-deps`).
- Architectures supported: PE32 (x86 32-bit) and PE32+ (x64 64-bit).
- Edge cases handled: Ordinal-only exports (no name), pre-forwarded exports (`DLL.Symbol`), non-contiguous ordinal bases.

## Review Focus

1. Correct RVA-to-File-Offset calculation across multiple PE sections (handling VirtualSize vs SizeOfRawData).
2. Proper detection of forwarded exports whose RVA falls inside the Export Directory data directory range.
3. Safe handling of ordinal-only exports in `#pragma comment(linker, ...)` and `.def` formats.
4. Correct generation of `DllMain` and dynamic wrapper trampolines avoiding infinite recursion.
5. Windows file path quoting and casing in generated C++ pragmas and build scripts.

## Plan Tasks

### Task 1: Scaffolding and PE Data Models
- [ ] Step 1: Create project directory layout (`src/dll_forward_gen/`, `tests/`, `templates/`).
- [ ] Step 2: Define data models in `src/dll_forward_gen/models.py` (`PeArch`, `ExportSymbol`, `PeExportInfo`).
- [ ] Step 3: Write initial unit test in `tests/test_models.py` verifying data model behavior and string representations.
- [ ] Step 4: Run tests and ensure they pass.
- [ ] Step 5: Git commit task 1.

### Task 2: Binary PE Parser (Zero-Dependency)
- [ ] Step 1: Write failing unit tests in `tests/test_pe_parser.py` testing DOS header validation, PE signature, architecture detection, section header RVA translation, and export parsing on both synthetic buffers and `C:\Windows\System32\version.dll`.
- [ ] Step 2: Run tests to confirm failure.
- [ ] Step 3: Implement `src/dll_forward_gen/pe_parser.py`:
  - `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS32`, `IMAGE_NT_HEADERS64`
  - `IMAGE_SECTION_HEADER` and `rva_to_file_offset`
  - `IMAGE_EXPORT_DIRECTORY` parsing: `AddressOfFunctions`, `AddressOfNames`, `AddressOfNameOrdinals`
  - Handling of name-based exports, ordinal-only exports, and forwarded export strings
- [ ] Step 4: Run `pytest` or `unittest` to ensure all parser tests pass.
- [ ] Step 5: Git commit task 2.

### Task 3: Stub & Forwarding Code Generators
- [ ] Step 1: Write failing unit tests in `tests/test_generator.py` for:
  - Linker Pragma generator (`pragma` mode)
  - Module Definition generator (`def` mode)
  - Dynamic Trampoline wrapper generator (`trampoline` mode)
  - CMake and `build.bat` scaffolding
- [ ] Step 2: Run tests to verify failure.
- [ ] Step 3: Implement `src/dll_forward_gen/generator.py`:
  - Clean C++ template generation for MSVC pragma linking
  - Dynamic `LoadLibraryW` + function pointer trampoline dispatcher
  - Module definition `.def` writer
  - `CMakeLists.txt` and `build.bat` generation
- [ ] Step 4: Run generator tests and ensure they pass.
- [ ] Step 5: Git commit task 3.

### Task 4: CLI Interface & Formatted Output
- [ ] Step 1: Write unit tests in `tests/test_cli.py` for command-line arguments, system32 auto-resolution, dump-only mode, and error handling.
- [ ] Step 2: Implement `src/dll_forward_gen/cli.py` with formatted console output, export tables, and system DLL auto-lookup.
- [ ] Step 3: Configure `__main__.py` and `pyproject.toml` for easy invocation (`python -m dll_forward_gen` or `pip install -e .`).
- [ ] Step 4: Run all CLI tests and verify end-to-end functionality.
- [ ] Step 5: Git commit task 4.

### Task 5: End-to-End Verification & MSVC Compilation Test
- [ ] Step 1: Run the tool against `C:\Windows\System32\version.dll` and generate a proxy project in `D:\dll-forward-gen\examples\version_proxy`.
- [ ] Step 2: Test building the generated C++ project using `cl.exe` (MSVC) if available to verify zero syntax errors.
- [ ] Step 3: Document usage, examples, and technical notes in `README.md`.
- [ ] Step 4: Git commit task 5.
