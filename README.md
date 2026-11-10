<div align="center">

# dll-forward-gen

**Enterprise-grade, zero-dependency Windows PE export forwarder, diff engine, & C++/MASM proxy generator.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org/)
[![C++20](https://img.shields.io/badge/C++20-00599C?style=flat-square&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![MASM x64/x86](https://img.shields.io/badge/MASM-Assembly-red?style=flat-square)](#masm-assembly-trampolines-mode-masm)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://learn.microsoft.com/)
[![CI](https://img.shields.io/badge/CI-Passing-brightgreen?style=flat-square)](https://github.com/negg0s/dll-forward-gen/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)](#)

<p align="center">
  <i>Parse any PE32 / PE32+ DLL, diff export tables across versions, audit target imports,<br/>and generate register-preserving MASM jump stubs, selective C++ detour hooks, or zero-overhead pragmas.</i>
</p>

---

</div>

## ⚡ Overview

When debugging third-party software, reverse engineering Windows internals, developing game modifications, or instrumenting graphics and audio pipelines (DirectX, Vulkan, WASAPI), developers frequently place a **Proxy DLL** alongside a target executable.

Writing export forwarding directives, resolving hundreds of ordinals by hand, and keeping calling conventions from corrupting registers is notoriously difficult. **`dll-forward-gen`** solves this in under 5 milliseconds:

* **Zero External Dependencies:** Built with pure Python 3 standard library and clean native C++20. No `pefile` or third-party wheels required.
* **Dual Engines:** Available both as a rich Python CLI and as a standalone native **C++20 binary** in `cpp/`.
* **Zero Register/Stack Corruption (MASM Mode):** Generates direct assembly jump stubs (`jmp qword ptr [...]`), preserving 100% of registers (RCX, RDX, R8, R9, XMM0-3) and calling convention fidelity without compiler prologue/epilogue overhead.
* **Selective Detour Hooking (`--hook <name>`):** Intercept 1 or 2 critical functions with custom C++ detour callbacks while forwarding the remaining hundreds of symbols untouched via MASM!
* **Target Import Audit (`--check-target <exe>`):** Scans any target `.exe` import table (IAT/INT) and cross-references it against the proxy DLL to verify 100% export coverage.
* **Export Diff Engine (`--diff <other.dll>`):** Compare export tables between two DLL versions to detect added, removed, ordinal-shifted, or modified exports.
* **Security Mitigations Audit:** Inspects and displays PE DllCharacteristics: **ASLR**, **High Entropy 64-bit VA**, **DEP/NX**, **Control Flow Guard (CFG)**, and **NoSEH**.
* **Cryptographic Fingerprinting:** Computes SHA-256 binary hash on the fly.
* **C++ Symbol Demangling:** Automatically demangles MSVC decorated symbols (`?Init@Engine@@...`) using native Windows `dbghelp.dll`.
* **Modding Suffix Mode:** Supports local renaming workflows (`--suffix _orig`) for drop-in game proxying.
* **Automated Scaffolding:** Generates production `CMakeLists.txt` and a one-click `build.bat` script for MSVC Developer Command Prompt (`cl.exe` / `ml64.exe`).

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

Or install in editable mode:
```bash
pip install -e .
```

Or compile and use the native C++20 engine:
```bash
cd cpp
build.bat
dll-forward-gen.exe version.dll
```

---

## 🔬 Practical Scenarios & CLI Usage

### 1. Inspect Exports, Security Mitigations & SHA-256
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

### 2. Audit Target Executable Compatibility (`--check-target`)
Ensure your proxy covers every function that your target game or application imports:

```bash
python -m dll_forward_gen ntdll.dll --check-target C:\Windows\System32\cmd.exe --dump-only
```

Output:
```text
==================================================================================
 TARGET IMPORT AUDIT: cmd.exe -> ntdll.dll
==================================================================================
 Imported Symbols: 10
----------------------------------------------------------------------------------
  [COVERED] RtlLookupFunctionEntry
  [COVERED] RtlVirtualUnwind
  [COVERED] NtOpenProcessToken
  [COVERED] NtClose
  ...
----------------------------------------------------------------------------------
 Result: 10 covered, 0 missing
==================================================================================
```

### 3. Compare Export Tables Between DLL Versions (`--diff`)
Detect API breaks, ordinal shifts, and new functions:

```bash
python -m dll_forward_gen game_v1.dll --diff game_v2.dll
```

Output:
```text
==================================================================================
 EXPORT TABLE DIFF: game_v1.dll <-> game_v2.dll
==================================================================================
 Summary: +2 added, -1 removed, ~1 modified, 45 identical
----------------------------------------------------------------------------------
  + [ADDED]    @48   CreateVulkanContext (RVA 0x0003F400)
  - [REMOVED]  @12   LegacyDirectDrawInit (RVA 0x00012000)
  ~ [MODIFIED] AudioEngineInit (Ordinal: @3 -> @5)
==================================================================================
```

### 4. Selective Detour Hooking (`--hook`)
Forward 99% of functions with zero-overhead MASM, but intercept specific functions with custom C++ logic:

```bash
python -m dll_forward_gen d3d11.dll -o ./d3d11_proxy -m masm --hook D3D11CreateDevice --file-log
```

Generated `dllmain.cpp` automatically exposes clean hook detours:
```cpp
extern "C" void* __stdcall Hook_D3D11CreateDevice() {
    OutputDebugStringA("[DETOUR HOOK] Intercepted D3D11CreateDevice\n");
    // Insert telemetry, Present hook injection, or parameter modifications here!
    
    FARPROC pfn = g_pfn_D3D11CreateDevice;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}
```

### 5. Game Modding Local Suffix Mode (`--suffix`)
```bash
# Forwards to dxgi_orig.dll in the game directory instead of System32
python -m dll_forward_gen dxgi.dll -o ./dxgi_proxy -m pragma --suffix _orig
```

---

## 🛠️ Forwarding Modes Compared

| Mode | Flag | Mechanism | Overhead | Best For |
| :--- | :--- | :--- | :--- | :--- |
| **Pragma** | `-m pragma` | `#pragma comment(linker, "/export:...")` | **0 CPU cycles** (PE loader handles redirect) | Fast drop-in loaders without function modifications |
| **MASM** | `-m masm` | `stubs.asm` (`jmp [pfn]`) + `ml64.exe` | **0 register/stack overhead** (100% ABI fidelity) | DirectX, Vulkan, audio engines, low-latency gaming |
| **Trampoline** | `-m trampoline` | C++ wrapper functions + `GetProcAddress` | Function call overhead | Quick C++ tracing and logging across all functions |
| **DEF** | `-m def` | Windows Module Definition (`.def`) | Linker level | MinGW, GCC, Clang cross-compilation |

---

## 📁 Generated Project Structure

When generating a project (e.g. `-m masm`), the output directory contains:

```text
my_proxy/
├── stubs.asm          # MASM direct assembly jump trampolines (x64 / x86)
├── dllmain.cpp        # Real DLL loader & function pointer binder
├── exports.def        # Export name-to-stub symbol mapping
├── CMakeLists.txt     # Multi-platform CMake build configuration
└── build.bat          # One-click batch build script for MSVC Developer Prompt
```

### One-Click Compilation
Open a **Visual Studio Developer Command Prompt** and run:
```bat
cd my_proxy
build.bat
```
Output DLL will be generated in `build/my_proxy.dll`.

---

## 🧪 Automated Testing

Run the comprehensive test suite with Python's built-in `unittest`:

```bash
$env:PYTHONPATH="src;."; python -m unittest discover -s tests -v
```

All 34 unit tests execute in ~0.13 seconds with zero external dependencies.

---

## 📄 License

MIT License. Developed by [NEGG0](https://github.com/negg0s).
