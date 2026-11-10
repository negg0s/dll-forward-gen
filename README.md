<div align="center">

# dll-forward-gen

**Enterprise-grade, zero-dependency Windows PE export forwarder, diff engine, & C++/MASM reverse engineering SDK.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org/)
[![C++20](https://img.shields.io/badge/C++20-00599C?style=flat-square&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![MASM x64/x86](https://img.shields.io/badge/MASM-Assembly-red?style=flat-square)](#masm-assembly-trampolines-mode-masm)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://learn.microsoft.com/)
[![CI](https://img.shields.io/badge/CI-Passing-brightgreen?style=flat-square)](https://github.com/negg0s/dll-forward-gen/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)](#)

<p align="center">
  <i>Parse any PE32 / PE32+ DLL, diff export tables, audit target executable imports,<br/>generate register-preserving MASM jump stubs, selective C++ detour hooks, or embeddable headers.</i>
</p>

---

</div>

## ⚡ Overview

When debugging third-party software, reverse engineering Windows internals, developing game modifications, or instrumenting graphics and audio pipelines (DirectX, Vulkan, WASAPI), developers frequently place a **Proxy DLL** alongside a target executable.

Writing export forwarding directives, resolving hundreds of ordinals by hand, and keeping calling conventions from corrupting registers is notoriously difficult. **`dll-forward-gen`** solves this in under 5 milliseconds:

* **Zero External Dependencies:** Built with pure Python 3 standard library and clean native C++20. No `pefile` or third-party wheels required.
* **Dual Engines:** Available both as a rich Python CLI and as a standalone native **C++20 binary** in `cpp/`.
* **Zero Register/Stack Corruption (MASM Mode):** Generates direct assembly jump stubs (`jmp qword ptr [...]`), preserving 100% of registers (RCX, RDX, R8, R9, XMM0-3) and calling convention fidelity without compiler prologue/epilogue overhead.
* **Header-Only Modding SDK (`sdk/`):**
  * `sdk/inline_hook.hpp`: Ultra-lightweight x64/x86 inline hooking engine (14-byte indirect JMP / 5-byte relative JMP) with automatic trampoline generation and RAII `ScopedHook`.
  * `sdk/pattern_scan.hpp`: High-performance IDA-style memory pattern scanner (`48 89 5C ? ? 48 83`) across loaded modules and specific PE sections.
* **Selective Detour Hooking (`--hook <name>`):** Intercept 1 or 2 critical functions with custom C++ detour callbacks while forwarding the remaining hundreds of symbols untouched via MASM!
* **Embeddable Single-File Header (`-H / --header-only`):** Generate a clean `#pragma once` header containing export forwarders to directly `#include` inside an existing C/C++ project.
* **Batch Multi-DLL Generation (`--batch config.json`):** Generate dozens of proxies across your entire toolchain from a single declarative JSON config.
* **Target Import Audit (`--check-target <exe>`):** Scans any target `.exe` import table (IAT/INT) and cross-references it against the proxy DLL to verify 100% export coverage.
* **Anti-Analysis & Security Heuristics Scanner:** Detects anti-debug tricks (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`), process injection (`VirtualProtect`, `WriteProcessMemory`, `CreateRemoteThread`), and timing evasion (`QueryPerformanceCounter`).
* **Resource & Manifest Extraction Engine (`--manifest`):** Traverses the PE `.rsrc` directory tree, extracts XML application manifests, and clones them into the generated proxy project (`app.manifest` + `version.rc`).
* **API Call Frequency Profiler (`-T / --trace`):** Injects lock-free atomic call counters into trampoline wrappers, dumping an aggregated `proxy_call_trace.csv` on process exit.
* **Universal MinGW / GCC / Clang Build Scaffolding (`--gcc`):** Emits GNU Assembler (`stubs.s`), a cross-platform `Makefile`, and `build_gcc.bat` for building proxies without Visual Studio.
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

### 2. Audit Target Executable Compatibility (`--check-target`)
Ensure your proxy covers every function that your target game or application imports:

```bash
python -m dll_forward_gen ntdll.dll --check-target C:\Windows\System32\cmd.exe --dump-only
```

### 3. Compare Export Tables Between DLL Versions (`--diff`)
Detect API breaks, ordinal shifts, and new functions:

```bash
python -m dll_forward_gen game_v1.dll --diff game_v2.dll
```

### 4. Entrypoint Disassembly & Byte Preview (`--disasm`)
Inspect a function's prologue bytes, detect indirect jump trampolines, and preview stack allocation:

```bash
python -m dll_forward_gen version.dll --disasm GetFileVersionInfoA
```

Output:
```
[+] Entrypoint Disassembly Preview: GetFileVersionInfoA (@1)
    RVA:             0x000010F0
    Virtual Address: 0x00000001800010F0
    File Offset:     0x000010F0
    Raw Bytes:       48 FF 25 D9 42 00 00 CC CC CC CC CC CC CC CC CC ...
    Pattern:         x64 Indirect JMP Trampoline -> [RIP + 0x42D9] (VA 0x00000001800053D0)
```

### 5. Selective Detour Hooking (`--hook`)
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

### 5. Generate Embeddable Single-File Header (`-H`)
Drop forwarding pragmas directly into your existing C/C++ solution without creating new projects:

```bash
python -m dll_forward_gen version.dll -H -o ./my_project/version_forward.h
```

### 6. Batch Multi-DLL Generation (`--batch`)
Configure multiple proxies in a single JSON file:

```json
{
  "output_dir": "./game_proxies",
  "proxies": [
    { "dll": "dxgi.dll", "mode": "masm", "suffix": "_orig", "file_log": true },
    { "dll": "dinput8.dll", "mode": "pragma", "suffix": "_orig" }
  ]
}
```
Run batch creation:
```bash
python -m dll_forward_gen --batch config.json
```

---

## 🧰 Native C++20 Modding SDK (`sdk/`)

The repository includes zero-dependency header-only utilities ready to `#include` in your mods or hooks.
You can export all SDK headers into your own project at any time:

```bash
python -m dll_forward_gen --export-sdk ./my_project/sdk
```

### Inline Hooking Engine (`sdk/inline_hook.hpp`)
```cpp
#include "sdk/inline_hook.hpp"

using Present_t = HRESULT (__stdcall*)(void*, void*, UINT, UINT);
Present_t g_OriginalPresent = nullptr;

HRESULT __stdcall MyPresentHook(void* swapchain, void* src, UINT sync, UINT flags) {
    // Custom frame overlay logic here!
    return g_OriginalPresent(swapchain, src, sync, flags);
}

void InstallHooks() {
    static dll_forward_gen::sdk::InlineHook hook;
    hook.Install(pRealPresentAddress, &MyPresentHook, (void**)&g_OriginalPresent);
}
```

### Memory Pattern Scanner (`sdk/pattern_scan.hpp`)
```cpp
#include "sdk/pattern_scan.hpp"

// Scan loaded game module for an IDA-style signature with wildcards
uint8_t* pfnTarget = dll_forward_gen::sdk::PatternScan::ScanModule(
    L"game.exe",
    "48 89 5C 24 ? 48 83 EC 20 48 8B 05 ? ? ? ?"
);
```

### IAT (Import Address Table) Hooking (`sdk/iat_hook.hpp`)
```cpp
#include "sdk/iat_hook.hpp"

// Hook target module's imported function atomically without modifying .text bytes
dll_forward_gen::hook::IATHook iatHook;
iatHook.Install(GetModuleHandleW(nullptr), "kernel32.dll", "CreateFileW", (void*)&MyCreateFileWHook);
```

### EAT (Export Address Table) Hooking (`sdk/eat_hook.hpp`)
```cpp
#include "sdk/eat_hook.hpp"

// Redirect GetProcAddress queries at runtime by patching target module's export table
dll_forward_gen::hook::EATHook eatHook;
eatHook.Install(hTargetModule, "VirtualAlloc", (void*)&MyVirtualAllocHook);
```

### Stealth Hardware Breakpoint Hooking (`sdk/veh_hook.hpp`)
```cpp
#include "sdk/veh_hook.hpp"

// Hook target function via CPU debug registers (DR0-DR3) + VEH
// Evades CRC32/SHA256 memory code scanners with zero patched bytes!
dll_forward_gen::hook::HardwareBreakpointHook::Instance().Install(
    (void*)pTargetFunction,
    (void*)DetourFunction,
    0 // DR0
);
```

### Memory Cloaking & PEB Unlinking (`sdk/stealth.hpp`)
```cpp
#include "sdk/stealth.hpp"

// Hide proxy DLL from EnumProcessModules, CreateToolhelp32Snapshot, and debuggers:
dll_forward_gen::stealth::UnlinkFromPEB(hProxyModule);
dll_forward_gen::stealth::WipeHeaders(hProxyModule);
dll_forward_gen::stealth::HideFromDebugger();
```

### In-Memory Manual PE Mapping Engine (`sdk/pe_loader.hpp`)
```cpp
#include "sdk/pe_loader.hpp"

// Manually map any PE binary in-memory without calling LoadLibrary (stealth module loading):
std::vector<uint8_t> dllBytes = ReadPayloadFile("payload.dll");
dll_forward_gen::loader::ManualPE module;

if (module.LoadFromMemory(dllBytes.data(), dllBytes.size())) {
    // Resolve exported functions directly from the manually mapped image:
    auto pfnInit = (void(*)())module.GetProcAddressManual("InitializePlugin");
    if (pfnInit) pfnInit();

    module.FreeManual();
}
```

### In-Memory Import Address Table Resolver (`sdk/iat_resolver.hpp`)
```cpp
#include "sdk/iat_resolver.hpp"

// Dynamically resolve and bind all imported DLLs and function pointers in an unmapped image:
bool success = dll_forward_gen::loader::IATResolver::ResolveAll(pMappedImageBase);

// Inspect if a specific import is already bound to a live procedure address:
bool isBound = dll_forward_gen::loader::IATResolver::IsBound(pMappedImageBase, "KERNEL32.dll", "CreateFileW");
```

### Base Relocation Processor (`sdk/reloc.hpp`)
```cpp
#include "sdk/reloc.hpp"

// Apply PE base relocations (.reloc) when manually mapping or rebasing an image in memory:
bool success = dll_forward_gen::loader::RelocProcessor::ApplyPreferred(pMappedImageBase);

// Or apply with an explicit delta offset (newBase - oldBase):
dll_forward_gen::loader::RelocProcessor::ApplyRelocations(pMappedImageBase, deltaOffset);

// Count total non-absolute relocation entries in a PE image:
size_t relocCount = dll_forward_gen::loader::RelocProcessor::CountRelocations(pMappedImageBase);
```

### Length Disassembler Engine (`sdk/lde.hpp`)
```cpp
#include "sdk/lde.hpp"

// Decode exact instruction length (1-15 bytes) to avoid splitting instructions:
size_t len = dll_forward_gen::hook::LengthDisassembler::DecodeInstruction(pCode, /*is64=*/true);

// Calculate exact stolen bytes needed for a safe hook trampoline:
size_t stolenBytes = dll_forward_gen::hook::LengthDisassembler::GetDisplacedLength(pCode, 14, true);
```

---

## 📦 Zero-Dependency COFF Import Library Generator (`.lib`)

`dll-forward-gen` includes an internal pure-Python COFF Short Import Library builder. You don't need MSVC `lib.exe` installed to create `.lib` files!

```bash
# Generate standalone .lib import library directly:
python -m dll_forward_gen version.dll --lib ./my_libs/version.lib
```

All generated proxy projects also automatically include the corresponding `.lib` import library ready for immediate linking.

---

## 📖 Known Ordinals Database

Game and system DLLs often export functions strictly by ordinal (`@1`, `@2`, etc.). `dll-forward-gen` includes a built-in ordinal database:
- **`ws2_32.dll` / `wsock32.dll`**: Winsock 1.1 / 2.0 API mappings (`accept`, `connect`, `socket`, `WSAStartup`...)
- **`oleaut32.dll`**: OLE Automation API mappings (`SysAllocString`, `VariantInit`...)
- **`xlive.dll`**: Games for Windows Live modding APIs (`XLiveInitialize`, `XLiveInput`...)
- **`binkw32.dll` / `bink2w64.dll`**: RAD Game Tools video APIs (`BinkOpen`, `BinkDoFrame`...)

When inspecting DLLs with `--dump` or generating proxies, ordinal exports are automatically annotated with their canonical names.

---

## ⚡ Native C++20 Standalone CLI (`cpp/`)

If you want a standalone binary without needing Python installed on the target machine:

```bash
cd cpp
build.bat
# Produces dll-forward-gen.exe (zero external dependencies)

# Use it directly:
dll-forward-gen.exe C:\Windows\System32\version.dll -m masm -o ./version_proxy
```

---

## 🛠️ Forwarding Modes Compared

| Mode | Flag | Mechanism | Overhead | Best For |
| :--- | :--- | :--- | :--- | :--- |
| **Pragma** | `-m pragma` | `#pragma comment(linker, "/export:...")` | **0 CPU cycles** (PE loader handles redirect) | Fast drop-in loaders without function modifications |
| **MASM (x64/x86/ARM64)** | `-m masm` | `stubs.asm` (`jmp [pfn]`) + `ml64.exe` / `armasm64.exe` | **0 register/stack overhead** (100% ABI fidelity) | DirectX, Vulkan, audio engines, low-latency gaming, WoA |
| **Trampoline** | `-m trampoline` | C++ wrapper functions + `GetProcAddress` | Function call overhead | Quick C++ tracing and logging across all functions |
| **DEF** | `-m def` | Windows Module Definition (`.def`) | Linker level | MinGW, GCC, Clang cross-compilation |

---

## 🧪 Automated Testing

Run the comprehensive test suite with Python's built-in `unittest`:

```bash
$env:PYTHONPATH="src;."; python -m unittest discover -s tests -v
```

All 62 unit tests execute in ~0.50 seconds with zero external dependencies.

---

## 📄 License

MIT License. Developed by [NEGG0](https://github.com/negg0s).
