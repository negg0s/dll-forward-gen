<div align="center">

# dll-forward-gen

**Fast, zero-dependency PE export forwarder & C++ proxy stub generator for Windows.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org/)
[![C++20](https://img.shields.io/badge/C++20-00599C?style=flat-square&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://learn.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)](#)

<p align="center">
  <i>Parse any PE32 / PE32+ DLL export directory and instantly generate production-ready<br/>forwarding proxies or intercepting C++ stubs with CMake and MSVC scaffolding.</i>
</p>

---

</div>

## ⚡ Overview

When debugging third-party applications, reverse engineering, writing modding loaders, or instrumenting graphics and audio pipelines (DirectX, Vulkan, WASAPI), developers frequently need to place a **Proxy DLL** next to a target executable.

Manually writing dozens of export forwarding directives or resolving hundreds of ordinals is error-prone and tedious. **`dll-forward-gen`** automates this in under 5 milliseconds:
- **Zero Dependencies:** Pure Python 3 standard library (`struct`, `pathlib`, `argparse`). No `pefile` or external binary wheels required.
- **Architectures:** Supports both **x86 (PE32)** and **x64 (PE32+)** binaries.
- **Ordinal-Only & Forwarded Exports:** Handles non-named ordinal exports (`#123`), sparse function index gaps, and nested forwarders (`DLL.Function`).
- **3 Forwarding Strategies:**
  1. **Linker Pragma (`pragma`):** Pure `#pragma comment(linker, "/export:...")` forwarding — zero runtime overhead, handled natively by Windows PE loader.
  2. **Module Definition (`def`):** Standard `.def` export files compatible with Clang, MinGW, and MSVC.
  3. **Dynamic Trampoline (`trampoline`):** Dynamic `LoadLibraryW` loader with resolved function pointers and intercepting wrapper stubs for API tracing and telemetry.
- **Ready to Build:** Automatically generates `CMakeLists.txt` and a one-click `build.bat` script for MSVC Developer Command Prompt.

---

## 🚀 Quick Start

### 1. Installation

Run directly with Python 3:
```bash
# Clone the repository
git clone https://github.com/negg0s/dll-forward-gen.git
cd dll-forward-gen

# Run directly via module
python -m dll_forward_gen --help

# Or install locally in editable mode
pip install -e .
```

### 2. Inspect Exports (Dump Mode)

Pass either a local file or a common Windows system DLL name:

```bash
python -m dll_forward_gen version.dll --dump-only
```

Output:
```text
==============================================================================
 PE EXPORT DIRECTORY: VERSION.dll
==============================================================================
 File Path:       C:\Windows\System32\version.dll
 Architecture:    X64
 Ordinal Base:    1
 Total Exports:   17 (Named: 17, Ordinal-only: 0, Forwarded: 2)
------------------------------------------------------------------------------
ORDINAL   RVA          TYPE           NAME / FORWARD TARGET
------------------------------------------------------------------------------
@1        0x000010F0   [FUNCTION]     GetFileVersionInfoA
@2        0x00001110   [FUNCTION]     GetFileVersionInfoByHandle
@3        0x00001AB0   [FUNCTION]     GetFileVersionInfoExA
@4        0x00001090   [FUNCTION]     GetFileVersionInfoExW
...
@14       0x00005F5C   [FORWARDED]    VerLanguageNameA -> KERNEL32.VerLanguageNameA
@15       0x00005F87   [FORWARDED]    VerLanguageNameW -> KERNEL32.VerLanguageNameW
@16       0x000010D0   [FUNCTION]     VerQueryValueA
@17       0x00001030   [FUNCTION]     VerQueryValueW
==============================================================================
```

### 3. Generate a Forwarding Proxy

```bash
# Generate zero-overhead linker pragma proxy for version.dll
python -m dll_forward_gen version.dll -o ./my_version_proxy -m pragma

# Or generate dynamic intercepting trampoline stubs
python -m dll_forward_gen d3d11.dll -o ./my_d3d11_proxy -m trampoline
```

### 4. Build the Generated DLL

```bash
cd my_version_proxy
build.bat
```
*(Or use `cmake -B build && cmake --build build --config Release`)*

---

## 🛠️ CLI Reference

```text
usage: dll-forward-gen [-h] [-o OUTPUT_DIR] [-m {pragma,def,trampoline}]
                       [-t TARGET_DLL] [--dump-only] [--json] [--no-logging]
                       [-v]
                       dll

Fast, zero-dependency PE export forwarder & C++ proxy stub generator for Windows.

positional arguments:
  dll                   Path to target DLL (or system DLL name like 'version.dll', 'dxgi.dll')

options:
  -h, --help            show this help message and exit
  -o, --output-dir OUTPUT_DIR
                        Destination directory for generated proxy project (default: ./<name>_proxy)
  -m, --mode {pragma,def,trampoline}
                        Forwarding strategy: 'pragma' (MSVC /export), 'def' (.def file), 'trampoline' (dynamic LoadLibrary wrapper)
  -t, --target-dll TARGET_DLL
                        Explicit path to original DLL to forward to (default: C:\Windows\System32\<dll_name>)
  --dump-only           Print export directory details and exit without generating files
  --json                Output parsed exports as structured JSON to stdout
  --no-logging          Disable OutputDebugString logging in generated proxy code
  -v, --version         show program's version number and exit
```

---

## 🔬 Forwarding Modes Explained

### Mode 1: `pragma` (Default & Recommended)
Leverages MSVC's `/export` linker directive to tell the Windows PE loader directly which DLL and function to forward to at load time:
```cpp
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\VERSION.GetFileVersionInfoW,@9")
```
* **Overhead:** Literally **0 CPU cycles**. The Windows OS loader sets up the redirection tables directly into memory.
* **Use case:** Game modding loaders, DLL proxying without modifying target function parameters.

### Mode 2: `trampoline` (Active Interception)
Loads the genuine target library via `LoadLibraryW` on `DLL_PROCESS_ATTACH`, dynamically binds all symbols with `GetProcAddress`, and provides C++ wrapper stubs:
```cpp
extern "C" void* __stdcall proxy_GetFileVersionInfoW() {
    if (!g_pfn_GetFileVersionInfoW) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoW\n");
    FARPROC pfn = g_pfn_GetFileVersionInfoW;
    return ((void* (__stdcall*)())pfn)();
}
```
* **Overhead:** Minimal jump overhead.
* **Use case:** API call logging, telemetry, modifying function arguments or return values, debugging graphics pipelines.

### Mode 3: `def` (Module Definition File)
Generates standard Windows Module Definition (`.def`) files:
```def
LIBRARY "VERSION.dll"
EXPORTS
    GetFileVersionInfoW=C:\Windows\System32\VERSION.GetFileVersionInfoW @9
```
* **Use case:** Cross-compiler setups with MinGW / GCC / Clang where `#pragma comment(linker)` is not supported.

---

## 🐍 Python API Usage

You can also use `dll-forward-gen` programmatically in Python scripts:

```python
from dll_forward_gen import PeParser, CodeGenerator, GeneratorMode

# Parse PE binary
parser = PeParser.from_file(r"C:\Windows\System32\version.dll")
info = parser.parse()

print(f"DLL: {info.dll_name} ({info.arch.value}) - {info.total_count} exports")

# Generate proxy project
gen = CodeGenerator(
    info=info,
    mode=GeneratorMode.PRAGMA,
    target_dll=r"C:\Windows\System32\version.dll"
)
gen.emit_project(Path("./output_proxy"))
```

---

## 🧪 Testing & Verification

Run the complete test suite with Python's standard `unittest`:

```bash
python -m unittest discover -s tests -v
```

All tests execute in milliseconds without external requirements.

---

## 📄 License

MIT License. Developed by [NEGG0](https://github.com/negg0s).
