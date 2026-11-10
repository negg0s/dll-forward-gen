<div align="center">

# dll-forward-gen

**Enterprise-grade, zero-dependency Windows PE export forwarder & C++/MASM proxy stub generator.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org/)
[![C++20](https://img.shields.io/badge/C++20-00599C?style=flat-square&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![MASM x64/x86](https://img.shields.io/badge/MASM-Assembly-red?style=flat-square)](#masm-assembly-trampolines-mode-masm)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://learn.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)](#)

<p align="center">
  <i>Parse any PE32 / PE32+ (x86 & x64) DLL export table and instantly generate build-ready<br/>forwarding proxies, register-preserving MASM jump stubs, or C++ telemetry hooks.</i>
</p>

---

</div>

## ⚡ Overview

When debugging third-party software, researching Windows internals, developing game modifications, or instrumenting graphics and audio pipelines (DirectX, Vulkan, WASAPI), developers frequently place a **Proxy DLL** alongside the target executable.

Writing export forwarding directives and resolving hundreds of ordinals by hand is error-prone and tedious. **`dll-forward-gen`** automates this entirely in milliseconds:

* **Zero External Dependencies:** Built with pure Python 3 standard library (`struct`, `dataclasses`, `pathlib`, `argparse`, `hashlib`). No heavy wheels or external packages.
* **Architectures:** Native support for both **x86 (PE32)** and **x64 (PE32+)** binaries.
* **Zero Register/Stack Corruption (MASM Mode):** Generates direct assembly jump stubs (`jmp qword ptr [...]`), preserving 100% of registers (RCX, RDX, R8, R9, XMM0-3) and calling convention fidelity without compiler prologue/epilogue interference.
* **Security Mitigations Audit:** Automatically inspects and displays PE DllCharacteristics: **ASLR**, **High Entropy 64-bit VA**, **DEP/NX**, **Control Flow Guard (CFG)**, and **NoSEH**.
* **Cryptographic Fingerprinting:** Computes SHA-256 binary hash on the fly.
* **C++ Symbol Demangling:** Demangles MSVC decorated symbols (`?Init@Engine@@...`) using native Windows `dbghelp.dll`.
* **Modding Suffix Mode:** Supports local renaming workflows (`--suffix _orig`) for seamless drop-in proxying.
* **Interactive TUI & Filters:** Colored terminal output with real-time symbol search (`--filter`) and ordinal inspection (`--ordinal`).
* **Automated Scaffolding:** Generates production `CMakeLists.txt` (with `ASM_MASM` support) and `build.bat` for one-click compilation via MSVC (`cl.exe` / `ml64.exe`).

---

## 🚀 Quick Start

### Installation

Clone and run directly via Python 3:
```bash
git clone https://github.com/negg0s/dll-forward-gen.git
cd dll-forward-gen

# Inspect CLI options
python -m dll_forward_gen --help
```

Or install locally in editable mode:
```bash
pip install -e .
```

---

## 🔬 CLI Usage & Examples

### 1. Inspect Exports & Security Mitigations (Dump Mode)
```bash
python -m dll_forward_gen version.dll --dump-only
```

Output:
```text
==================================================================================
 PE EXPORT DIRECTORY: VERSION.dll
==================================================================================
 File Path:       C:\Windows\System32\version.dll
 Architecture:    X64
 SHA-256:         d8383a8b4172f3e8f6e72c833ba38622...
 Mitigations:     ASLR, HighEntropyVA, DEP/NX, CFG
 Ordinal Base:    1
 Total Exports:   17 (Named: 17, Ordinal-only: 0, Forwarded: 2)
----------------------------------------------------------------------------------
ORDINAL   RVA          TYPE                    NAME / TARGET
----------------------------------------------------------------------------------
@1        0x000010F0   [FUNCTION]              GetFileVersionInfoA
@2        0x00001110   [FUNCTION]              GetFileVersionInfoByHandle
@3        0x00001AB0   [FUNCTION]              GetFileVersionInfoExA
@4        0x00001090   [FUNCTION]              GetFileVersionInfoExW
...
@14       0x00005F5C   [FORWARDED]             VerLanguageNameA -> KERNEL32.VerLanguageNameA
@15       0x00005F87   [FORWARDED]             VerLanguageNameW -> KERNEL32.VerLanguageNameW
@16       0x000010D0   [FUNCTION]              VerQueryValueA
@17       0x00001030   [FUNCTION]              VerQueryValueW
==================================================================================
```

### 2. Search and Filter Exports
```bash
# Filter symbols by name (case-insensitive regex / substring)
python -m dll_forward_gen version.dll --filter QueryValue

# Inspect a specific ordinal
python -m dll_forward_gen version.dll --ordinal 9
```

### 3. Generate MASM Assembly Stubs (Highest Fidelity)
```bash
# Generates stubs.asm (jmp qword ptr [...]) + dllmain.cpp loader
python -m dll_forward_gen version.dll -o ./version_masm -m masm --file-log
```

### 4. Game Modding Suffix Mode (Local Forwarding)
```bash
# Forwards to dxgi_orig.dll in the game folder instead of System32
python -m dll_forward_gen dxgi.dll -o ./dxgi_mod -m pragma --suffix _orig
```

---

## 🛠️ Forwarding Modes Compared

| Mode | Flag | Mechanism | Pros | Best For |
| :--- | :--- | :--- | :--- | :--- |
| **Pragma** | `-m pragma` | `#pragma comment(linker, "/export:...")` | 0 CPU cycles overhead; native Windows PE loader forwarding | Drop-in loaders without function modifications |
| **MASM** | `-m masm` | `stubs.asm` (`jmp [pfn]`) + `ml64.exe` | 100% register & stack preservation; zero ABI corruption | Low-latency audio, DirectX / Vulkan, complex APIs |
| **Trampoline** | `-m trampoline` | C++ wrapper functions + `GetProcAddress` | Easy to add C++ logic/telemetry before & after calls | API tracing, parameter inspection |
| **DEF** | `-m def` | Windows Module Definition (`.def`) file | Universal compiler compatibility (MinGW, Clang, GCC) | Cross-compilation environments |

---

## 📁 Generated Project Structure

When generating a project (e.g. `-m masm`), the output directory contains:

```text
version_proxy/
├── stubs.asm          # MASM direct assembly jump trampolines (x64 / x86)
├── dllmain.cpp        # Real DLL loader & function pointer binder
├── exports.def        # Export name-to-stub symbol mapping
├── CMakeLists.txt     # Multi-platform CMake build configuration
└── build.bat          # One-click batch build script for MSVC Developer Prompt
```

### One-Click Compilation
Open a **Visual Studio Developer Command Prompt** and run:
```bat
cd version_proxy
build.bat
```
Output DLL will be generated in `build/version.dll`.

---

## 🐍 Python Library Usage

```python
from dll_forward_gen import PeParser, CodeGenerator, GeneratorMode

# 1. Parse PE binary
parser = PeParser.from_file(r"C:\Windows\System32\version.dll")
info = parser.parse()

print(f"Loaded {info.dll_name} ({info.arch.value})")
print(f"SHA-256: {info.sha256}")
print(f"Mitigations: {info.mitigations.summary()}")

# 2. Generate MASM proxy project
gen = CodeGenerator(
    info=info,
    mode=GeneratorMode.MASM,
    target_dll="version_orig.dll",
    enable_file_log=True,
)
created_files = gen.emit_project(Path("./output_proxy"))
```

---

## 🧪 Test Suite

Run the full automated test suite with Python's built-in `unittest`:

```bash
$env:PYTHONPATH="src;."; python -m unittest discover -s tests -v
```

All 27 unit tests execute in ~0.05 seconds.

---

## 📄 License

MIT License. Developed by [NEGG0](https://github.com/negg0s).
