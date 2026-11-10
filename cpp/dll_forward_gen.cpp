// ============================================================================
// dll_forward_gen.cpp - Native C++20 PE Export Forwarder & Analyzer CLI
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Zero-dependency native Windows C++20 tool for PE export parsing & proxying.
// Supports: Pragma, MASM (x64/x86/ARM64), Trampoline, and DEF modes.
// Compile with MSVC: cl /O2 /std:c++20 /W4 dll_forward_gen.cpp /Fe:dll-forward-gen.exe
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <string_view>
#include <filesystem>
#include <iomanip>
#include <algorithm>
#include <cstdint>
#include <optional>
#include <regex>

namespace fs = std::filesystem;

enum class Mode {
    Pragma,
    Masm,
    Trampoline,
    Def
};

struct ExportEntry {
    uint32_t ordinal = 0;
    uint32_t rva = 0;
    std::string name;
    bool is_forwarded = false;
    std::string forward_name;

    [[nodiscard]] bool is_ordinal_only() const noexcept {
        return name.empty();
    }

    [[nodiscard]] std::string safe_name() const {
        if (!name.empty()) {
            std::string s = name;
            for (char& c : s) {
                if (c == '?' || c == '@') c = '_';
            }
            return s;
        }
        return "Ordinal_" + std::to_string(ordinal);
    }
};

struct PeInfo {
    fs::path filepath;
    std::string dll_name;
    std::string arch;
    uint32_t timestamp = 0;
    uint32_t ordinal_base = 1;
    std::vector<ExportEntry> symbols;
};

class NativePeParser {
public:
    static bool Parse(const fs::path& path, PeInfo& out_info, std::string& err) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            err = "Failed to open file: " + path.string();
            return false;
        }

        const auto size = static_cast<size_t>(file.tellg());
        if (size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
            err = "File too small to be a valid PE binary.";
            return false;
        }

        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            err = "Failed to read binary into memory.";
            return false;
        }

        // 1. DOS Header
        const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
            err = "Invalid DOS header signature (not 'MZ').";
            return false;
        }

        if (static_cast<size_t>(dos_hdr->e_lfanew) + sizeof(DWORD) > size) {
            err = "Corrupt e_lfanew offset.";
            return false;
        }

        // 2. NT Signature
        const auto* nt_sig = reinterpret_cast<const DWORD*>(buffer.data() + dos_hdr->e_lfanew);
        if (*nt_sig != IMAGE_NT_SIGNATURE) {
            err = "Invalid NT signature (not 'PE\\0\\0').";
            return false;
        }

        const auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(buffer.data() + dos_hdr->e_lfanew + sizeof(DWORD));
        const uint16_t num_sections = file_hdr->NumberOfSections;
        const auto* opt_hdr_raw = buffer.data() + dos_hdr->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        const uint16_t opt_magic = *reinterpret_cast<const uint16_t*>(opt_hdr_raw);

        out_info.filepath = path;
        out_info.dll_name = path.filename().string();
        out_info.timestamp = file_hdr->TimeDateStamp;

        if (file_hdr->Machine == 0xAA64) {
            out_info.arch = "ARM64";
        } else if (file_hdr->Machine == 0x8664) {
            out_info.arch = "X64";
        } else if (file_hdr->Machine == 0x014C) {
            out_info.arch = "X86";
        } else {
            out_info.arch = "UNKNOWN";
        }

        DWORD export_rva = 0;
        DWORD export_size = 0;

        if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            const auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(opt_hdr_raw);
            export_rva = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_size = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            const auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(opt_hdr_raw);
            export_rva = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_size = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else {
            err = "Unsupported optional header magic.";
            return false;
        }

        // 3. Section Headers
        const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(opt_hdr_raw + file_hdr->SizeOfOptionalHeader);

        auto rva_to_offset = [&](DWORD rva) -> std::optional<size_t> {
            for (uint16_t i = 0; i < num_sections; ++i) {
                const auto& sec = sections[i];
                const DWORD span = (std::max)(sec.Misc.VirtualSize, sec.SizeOfRawData);
                if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + span) {
                    const DWORD delta = rva - sec.VirtualAddress;
                    if (delta < sec.SizeOfRawData) {
                        return static_cast<size_t>(sec.PointerToRawData + delta);
                    }
                }
            }
            return std::nullopt;
        };

        if (export_rva == 0 || export_size == 0) {
            return true; // No exports
        }

        const auto export_off = rva_to_offset(export_rva);
        if (!export_off || *export_off + sizeof(IMAGE_EXPORT_DIRECTORY) > size) {
            err = "Failed to resolve Export Directory RVA to physical file offset.";
            return false;
        }

        const auto* exp_dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(buffer.data() + *export_off);
        out_info.ordinal_base = exp_dir->Base;

        const auto name_off = rva_to_offset(exp_dir->Name);
        if (name_off && *name_off < size) {
            out_info.dll_name = reinterpret_cast<const char*>(buffer.data() + *name_off);
        }

        const auto funcs_off = rva_to_offset(exp_dir->AddressOfFunctions);
        const auto names_off = rva_to_offset(exp_dir->AddressOfNames);
        const auto ords_off = rva_to_offset(exp_dir->AddressOfNameOrdinals);

        if (!funcs_off) {
            err = "AddressOfFunctions table not found.";
            return false;
        }

        // Map function index to name
        std::vector<std::string> index_to_name(exp_dir->NumberOfFunctions);
        if (names_off && ords_off) {
            const auto* name_rvas = reinterpret_cast<const DWORD*>(buffer.data() + *names_off);
            const auto* ord_indices = reinterpret_cast<const WORD*>(buffer.data() + *ords_off);

            for (DWORD i = 0; i < exp_dir->NumberOfNames; ++i) {
                const WORD fn_idx = ord_indices[i];
                if (fn_idx < exp_dir->NumberOfFunctions) {
                    const auto sym_name_off = rva_to_offset(name_rvas[i]);
                    if (sym_name_off && *sym_name_off < size) {
                        index_to_name[fn_idx] = reinterpret_cast<const char*>(buffer.data() + *sym_name_off);
                    }
                }
            }
        }

        const auto* func_rvas = reinterpret_cast<const DWORD*>(buffer.data() + *funcs_off);
        for (DWORD idx = 0; idx < exp_dir->NumberOfFunctions; ++idx) {
            const DWORD fn_rva = func_rvas[idx];
            if (fn_rva == 0) continue; // Unused slot

            ExportEntry entry;
            entry.ordinal = exp_dir->Base + idx;
            entry.rva = fn_rva;
            entry.name = index_to_name[idx];

            if (fn_rva >= export_rva && fn_rva < export_rva + export_size) {
                entry.is_forwarded = true;
                const auto fwd_off = rva_to_offset(fn_rva);
                if (fwd_off && *fwd_off < size) {
                    entry.forward_name = reinterpret_cast<const char*>(buffer.data() + *fwd_off);
                }
            }

            out_info.symbols.push_back(std::move(entry));
        }

        return true;
    }
};

void PrintTable(const PeInfo& info) {
    std::cout << "\n==============================================================================\n";
    std::cout << " PE EXPORT DIRECTORY (C++20 Engine): " << info.dll_name << "\n";
    std::cout << "==============================================================================\n";
    std::cout << " File Path:       " << info.filepath.string() << "\n";
    std::cout << " Architecture:    " << info.arch << "\n";
    std::cout << " Ordinal Base:    " << info.ordinal_base << "\n";
    std::cout << " Total Exports:   " << info.symbols.size() << "\n";
    std::cout << "------------------------------------------------------------------------------\n";
    std::cout << std::left << std::setw(9) << "ORDINAL"
              << std::setw(12) << "RVA"
              << std::setw(14) << "TYPE"
              << "NAME / TARGET\n";
    std::cout << "------------------------------------------------------------------------------\n";

    for (const auto& sym : info.symbols) {
        std::string ord_str = "@" + std::to_string(sym.ordinal);
        std::stringstream ss;
        ss << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << sym.rva;
        std::string rva_str = ss.str();

        std::string type_str = "[FUNCTION]";
        std::string target_str = sym.name;
        if (sym.is_forwarded) {
            type_str = "[FORWARDED]";
            target_str = (sym.name.empty() ? "<ordinal>" : sym.name) + " -> " + sym.forward_name;
        } else if (sym.is_ordinal_only()) {
            type_str = "[ORDINAL-ONLY]";
            target_str = "<Ordinal_" + std::to_string(sym.ordinal) + ">";
        }

        std::cout << std::left << std::setw(9) << ord_str
                  << std::setw(12) << rva_str
                  << std::setw(14) << type_str
                  << target_str << "\n";
    }
    std::cout << "==============================================================================\n";
}

// ============================================================================
// Code Generator Implementations (C++20)
// ============================================================================

std::string EscapePath(const std::string& path) {
    std::string result;
    for (char c : path) {
        if (c == '\\') result += "\\\\";
        else result += c;
    }
    return result;
}

std::string GeneratePragmaSource(const PeInfo& info, const std::string& target_dll, bool logging, bool file_log) {
    std::ostringstream ss;
    ss << "// ===========================================================================\n";
    ss << "// Linker Pragma Export Forwarding Proxy for " << info.dll_name << "\n";
    ss << "// Architecture: " << info.arch << " | Total exports: " << info.symbols.size() << "\n";
    ss << "// Generated by dll-forward-gen (C++20 Engine)\n";
    ss << "// ===========================================================================\n";
    ss << "#define WIN32_LEAN_AND_MEAN\n";
    ss << "#include <windows.h>\n";
    ss << "#include <stdio.h>\n\n";

    fs::path p(target_dll);
    std::string target_stem = p.stem().string();

    ss << "// --- Linker Forwarding Directives ---\n";
    for (const auto& sym : info.symbols) {
        if (sym.is_ordinal_only()) {
            ss << "#pragma comment(linker, \"/export:Ordinal_" << sym.ordinal << "="
               << target_stem << ".#" << sym.ordinal << ",@" << sym.ordinal << ",NONAME\")\n";
        } else {
            ss << "#pragma comment(linker, \"/export:" << sym.name << "="
               << target_stem << "." << sym.name << ",@" << sym.ordinal << "\")\n";
        }
    }
    ss << "\n";

    ss << "static void OnProcessAttach(HMODULE hModule) {\n";
    ss << "    DisableThreadLibraryCalls(hModule);\n";
    if (file_log) {
        ss << "    FILE* fLog = NULL;\n";
        ss << "    if (fopen_s(&fLog, \"proxy_log.txt\", \"a\") == 0 && fLog) {\n";
        ss << "        fprintf(fLog, \"[dll-forward-gen] Attached to process: " << info.dll_name << "\\n\");\n";
        ss << "        fclose(fLog);\n";
        ss << "    }\n";
    }
    if (logging) {
        ss << "    OutputDebugStringA(\"[dll-forward-gen] Initialized proxy for " << info.dll_name << "\\n\");\n";
    }
    ss << "}\n\n";

    ss << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n";
    ss << "    (void)lpReserved;\n";
    ss << "    switch (ul_reason_for_call) {\n";
    ss << "    case DLL_PROCESS_ATTACH:\n";
    ss << "        OnProcessAttach(hModule);\n";
    ss << "        break;\n";
    ss << "    case DLL_PROCESS_DETACH:\n";
    ss << "    case DLL_THREAD_ATTACH:\n";
    ss << "    case DLL_THREAD_DETACH:\n";
    ss << "        break;\n";
    ss << "    }\n";
    ss << "    return TRUE;\n";
    ss << "}\n";

    return ss.str();
}

std::string GenerateHeaderOnlySource(const PeInfo& info, const std::string& target_dll) {
    std::ostringstream ss;
    ss << "#pragma once\n";
    ss << "// ===========================================================================\n";
    ss << "// Standalone Forwarding Header for " << info.dll_name << " (" << info.arch << ")\n";
    ss << "// Generated by dll-forward-gen (C++20 Engine)\n";
    ss << "// ===========================================================================\n";
    ss << "#define WIN32_LEAN_AND_MEAN\n";
    ss << "#include <windows.h>\n\n";

    fs::path p(target_dll);
    std::string target_stem = p.stem().string();

    ss << "// --- Linker Export Forwarding Directives ---\n";
    for (const auto& sym : info.symbols) {
        if (sym.is_ordinal_only()) {
            ss << "#pragma comment(linker, \"/export:Ordinal_" << sym.ordinal << "="
               << target_stem << ".#" << sym.ordinal << ",@" << sym.ordinal << ",NONAME\")\n";
        } else {
            ss << "#pragma comment(linker, \"/export:" << sym.name << "="
               << target_stem << "." << sym.name << ",@" << sym.ordinal << "\")\n";
        }
    }
    return ss.str();
}

std::string GenerateDefSource(const PeInfo& info, const std::string& target_dll) {
    std::ostringstream ss;
    ss << "; Module Definition File for " << info.dll_name << "\n";
    ss << "LIBRARY \"" << info.dll_name << "\"\n";
    ss << "EXPORTS\n";

    fs::path p(target_dll);
    std::string target_stem = p.stem().string();

    for (const auto& sym : info.symbols) {
        if (sym.is_ordinal_only()) {
            ss << "    " << sym.safe_name() << "=" << target_stem << ".#" << sym.ordinal
               << " @" << sym.ordinal << " NONAME\n";
        } else {
            ss << "    " << sym.name << "=" << target_stem << "." << sym.name
               << " @" << sym.ordinal << "\n";
        }
    }
    return ss.str();
}

std::string GenerateMasmAssembly(const PeInfo& info) {
    std::ostringstream ss;
    const bool is_arm64 = (info.arch == "ARM64");
    const bool is_64 = (info.arch == "X64" || info.arch == "ARM64");
    const std::string ptr_type = is_64 ? "qword" : "dword";

    if (is_arm64) {
        ss << "; ===========================================================================\n";
        ss << "; ARM64 Assembly JMP Trampoline Stubs for " << info.dll_name << "\n";
        ss << "; Architecture: ARM64 | armasm64 syntax\n";
        ss << "; Zero-overhead forwarding using AAPCS64 IP0 (X16)\n";
        ss << "; ===========================================================================\n";
        ss << "    AREA |.text|, CODE, READONLY\n";
        ss << "    ALIGN 4\n\n";
        for (const auto& sym : info.symbols) {
            ss << "    IMPORT g_pfn_" << sym.safe_name() << "\n";
        }
        ss << "\n";
        for (const auto& sym : info.symbols) {
            ss << "    EXPORT proxy_" << sym.safe_name() << "\n";
            ss << "proxy_" << sym.safe_name() << " PROC\n";
            ss << "    adrp    x16, g_pfn_" << sym.safe_name() << "\n";
            ss << "    ldr     x16, [x16, :lo12:g_pfn_" << sym.safe_name() << "]\n";
            ss << "    br      x16\n";
            ss << "proxy_" << sym.safe_name() << " ENDP\n\n";
        }
        ss << "    END\n";
    } else {
        ss << "; ===========================================================================\n";
        ss << "; MASM Assembly JMP Trampoline Stubs for " << info.dll_name << "\n";
        ss << "; Architecture: " << info.arch << " | Pointer: " << ptr_type << "\n";
        ss << "; ===========================================================================\n";
        if (!is_64) {
            ss << ".386\n.model flat, c\n";
        }
        ss << ".code\n\n";
        for (const auto& sym : info.symbols) {
            ss << "extern g_pfn_" << sym.safe_name() << " : " << ptr_type << "\n";
        }
        ss << "\n";
        for (const auto& sym : info.symbols) {
            ss << "proxy_" << sym.safe_name() << " proc\n";
            ss << "    jmp " << ptr_type << " ptr [g_pfn_" << sym.safe_name() << "]\n";
            ss << "proxy_" << sym.safe_name() << " endp\n\n";
        }
        ss << "end\n";
    }
    return ss.str();
}

std::string GenerateMasmLoader(const PeInfo& info, const std::string& target_dll, bool logging, bool file_log) {
    std::ostringstream ss;
    ss << "// ===========================================================================\n";
    ss << "// MASM Loader & Symbol Resolver for " << info.dll_name << "\n";
    ss << "// ===========================================================================\n";
    ss << "#define WIN32_LEAN_AND_MEAN\n";
    ss << "#include <windows.h>\n";
    ss << "#include <stdio.h>\n\n";

    ss << "static HMODULE g_hRealDll = NULL;\n";
    ss << "extern \"C\" {\n";
    for (const auto& sym : info.symbols) {
        ss << "    FARPROC g_pfn_" << sym.safe_name() << " = NULL;\n";
    }
    ss << "}\n\n";

    std::string escaped_target = EscapePath(target_dll);

    ss << "static BOOL LoadRealLibrary() {\n";
    ss << "    if (g_hRealDll != NULL) return TRUE;\n\n";
    ss << "    const wchar_t* targetPath = L\"" << escaped_target << "\";\n";
    ss << "    g_hRealDll = LoadLibraryW(targetPath);\n";
    ss << "    if (!g_hRealDll) {\n";
    ss << "        wchar_t sysDir[MAX_PATH];\n";
    ss << "        if (GetSystemDirectoryW(sysDir, MAX_PATH)) {\n";
    ss << "            wchar_t fullPath[MAX_PATH];\n";
    ss << "            swprintf_s(fullPath, MAX_PATH, L\"%s\\\\" << info.dll_name.c_str() << "\", sysDir);\n";
    ss << "            g_hRealDll = LoadLibraryW(fullPath);\n";
    ss << "        }\n";
    ss << "    }\n";
    ss << "    if (!g_hRealDll) return FALSE;\n\n";

    for (const auto& sym : info.symbols) {
        if (sym.is_ordinal_only()) {
            ss << "    g_pfn_" << sym.safe_name() << " = GetProcAddress(g_hRealDll, MAKEINTRESOURCEA(" << sym.ordinal << "));\n";
        } else {
            ss << "    g_pfn_" << sym.safe_name() << " = GetProcAddress(g_hRealDll, \"" << sym.name << "\");\n";
        }
    }
    ss << "    return TRUE;\n";
    ss << "}\n\n";

    ss << "static void OnProcessAttach(HMODULE hModule) {\n";
    ss << "    DisableThreadLibraryCalls(hModule);\n";
    ss << "    LoadRealLibrary();\n";
    if (file_log) {
        ss << "    FILE* fLog = NULL;\n";
        ss << "    if (fopen_s(&fLog, \"proxy_log.txt\", \"a\") == 0 && fLog) {\n";
        ss << "        fprintf(fLog, \"[dll-forward-gen] Attached MASM proxy for " << info.dll_name << "\\n\");\n";
        ss << "        fclose(fLog);\n";
        ss << "    }\n";
    }
    if (logging) {
        ss << "    OutputDebugStringA(\"[dll-forward-gen] Initialized MASM proxy for " << info.dll_name << "\\n\");\n";
    }
    ss << "}\n\n";

    ss << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n";
    ss << "    (void)lpReserved;\n";
    ss << "    switch (ul_reason_for_call) {\n";
    ss << "    case DLL_PROCESS_ATTACH:\n";
    ss << "        OnProcessAttach(hModule);\n";
    ss << "        break;\n";
    ss << "    case DLL_PROCESS_DETACH:\n";
    ss << "        if (g_hRealDll) { FreeLibrary(g_hRealDll); g_hRealDll = NULL; }\n";
    ss << "        break;\n";
    ss << "    }\n";
    ss << "    return TRUE;\n";
    ss << "}\n";

    return ss.str();
}

std::string GenerateMasmDef(const PeInfo& info) {
    std::ostringstream ss;
    ss << "; Module Definition File for MASM Proxy\n";
    ss << "LIBRARY \"" << info.dll_name << "\"\n";
    ss << "EXPORTS\n";
    for (const auto& sym : info.symbols) {
        if (sym.is_ordinal_only()) {
            ss << "    " << sym.safe_name() << "=proxy_" << sym.safe_name() << " @" << sym.ordinal << " NONAME\n";
        } else {
            ss << "    " << sym.name << "=proxy_" << sym.safe_name() << " @" << sym.ordinal << "\n";
        }
    }
    return ss.str();
}

std::string GenerateBuildBat(const PeInfo& info, const std::string& target_stem, bool has_asm) {
    std::ostringstream ss;
    std::string asm_tool = "ml64.exe";
    std::string arch_flag = "X64";
    if (info.arch == "ARM64") {
        asm_tool = "armasm64.exe";
        arch_flag = "ARM64";
    } else if (info.arch == "X86") {
        asm_tool = "ml.exe";
        arch_flag = "X86";
    }

    ss << "@echo off\n";
    ss << "setlocal enabledelayedexpansion\n";
    ss << "echo [dll-forward-gen] Building " << info.dll_name << " proxy (" << info.arch << ")...\n\n";
    ss << "where cl.exe >nul 2>nul\n";
    ss << "if %ERRORLEVEL% NEQ 0 (\n";
    ss << "    echo [ERROR] MSVC cl.exe not found in PATH!\n";
    ss << "    exit /b 1\n";
    ss << ")\n\n";
    ss << "if not exist build mkdir build\n";
    ss << "pushd build\n\n";

    if (has_asm) {
        ss << "echo [dll-forward-gen] Assembling stubs.asm with " << asm_tool << "...\n";
        ss << asm_tool << " /c /nologo /Fo:stubs.obj ..\\stubs.asm\n";
        ss << "if %ERRORLEVEL% NEQ 0 ( popd & exit /b 1 )\n";
        ss << "cl.exe /nologo /O2 /W4 /LD ..\\dllmain.cpp stubs.obj /DEF:..\\exports.def /Fe:"
           << target_stem << ".dll /link /MACHINE:" << arch_flag << "\n";
    } else {
        ss << "cl.exe /nologo /O2 /W4 /LD ..\\dllmain.cpp /Fe:" << target_stem << ".dll /link /MACHINE:" << arch_flag << "\n";
    }

    ss << "if %ERRORLEVEL% EQU 0 (\n";
    ss << "    echo [SUCCESS] Built " << target_stem << ".dll successfully!\n";
    ss << ") else (\n";
    ss << "    echo [ERROR] Compilation failed!\n";
    ss << ")\n";
    ss << "popd\nendlocal\n";

    return ss.str();
}

// ============================================================================
// Main CLI Entrypoint
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "dll-forward-gen (Native C++20 CLI Engine)\n";
        std::cout << "Usage: dll-forward-gen.exe <target.dll> [options]\n\n";
        std::cout << "Options:\n";
        std::cout << "  --dump                   Print export directory inspection table\n";
        std::cout << "  -m, --mode <mode>        Proxy mode: pragma (default), masm, trampoline, def\n";
        std::cout << "  -o, --output <dir>       Output directory for generated proxy project\n";
        std::cout << "  -H, --header-only <file> Generate single embeddable C/C++ header (.h)\n";
        std::cout << "  --suffix <str>           Redirect to custom DLL name (e.g. version_orig.dll)\n";
        std::cout << "  --filter <str>           Filter symbols by substring or regex\n";
        std::cout << "  --file-log               Enable runtime call logging to proxy_log.txt\n";
        std::cout << "  --logging                Enable OutputDebugString logging\n";
        return 1;
    }

    fs::path target_path = argv[1];
    if (!fs::exists(target_path)) {
        fs::path sys32 = "C:\\Windows\\System32";
        if (fs::exists(sys32 / target_path)) {
            target_path = sys32 / target_path;
        } else {
            std::cerr << "[ERROR] Cannot locate DLL: " << argv[1] << "\n";
            return 1;
        }
    }

    PeInfo info;
    std::string err;
    if (!NativePeParser::Parse(target_path, info, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 1;
    }

    bool dump_mode = false;
    bool file_log = false;
    bool logging = false;
    Mode mode = Mode::Pragma;
    fs::path output_dir;
    fs::path header_only_path;
    std::string suffix;
    std::string filter_pattern;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--dump") {
            dump_mode = true;
        } else if (arg == "--file-log") {
            file_log = true;
        } else if (arg == "--logging") {
            logging = true;
        } else if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
            std::string m = argv[++i];
            if (m == "masm") mode = Mode::Masm;
            else if (m == "trampoline") mode = Mode::Trampoline;
            else if (m == "def") mode = Mode::Def;
            else mode = Mode::Pragma;
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_dir = argv[++i];
        } else if ((arg == "-H" || arg == "--header-only") && i + 1 < argc) {
            header_only_path = argv[++i];
        } else if (arg == "--suffix" && i + 1 < argc) {
            suffix = argv[++i];
        } else if (arg == "--filter" && i + 1 < argc) {
            filter_pattern = argv[++i];
        }
    }

    // Apply symbol filter if requested
    if (!filter_pattern.empty()) {
        std::vector<ExportEntry> filtered;
        for (const auto& sym : info.symbols) {
            if (sym.name.find(filter_pattern) != std::string::npos ||
                std::to_string(sym.ordinal) == filter_pattern) {
                filtered.push_back(sym);
            }
        }
        info.symbols = std::move(filtered);
    }

    std::string target_dll = info.filepath.string();
    if (!suffix.empty()) {
        target_dll = (info.filepath.parent_path() / (info.filepath.stem().string() + suffix + info.filepath.extension().string())).string();
    }

    if (dump_mode || (output_dir.empty() && header_only_path.empty())) {
        PrintTable(info);
        if (output_dir.empty() && header_only_path.empty()) {
            return 0;
        }
    }

    // Header-only generation
    if (!header_only_path.empty()) {
        std::string hdr = GenerateHeaderOnlySource(info, target_dll);
        std::ofstream out(header_only_path);
        if (!out) {
            std::cerr << "[ERROR] Failed to write header file: " << header_only_path.string() << "\n";
            return 1;
        }
        out << hdr;
        std::cout << "[+] Generated header-only forwarding file: " << header_only_path.string() << "\n";
        return 0;
    }

    // Project directory emission
    if (!output_dir.empty()) {
        fs::create_directories(output_dir);
        std::string target_stem = fs::path(info.dll_name).stem().string();

        if (mode == Mode::Pragma) {
            std::string src = GeneratePragmaSource(info, target_dll, logging, file_log);
            std::ofstream out(output_dir / "dllmain.cpp");
            out << src;

            std::ofstream bat(output_dir / "build.bat");
            bat << GenerateBuildBat(info, target_stem, false);
            std::cout << "[+] Generated PRAGMA proxy project in: " << output_dir.string() << "\n";
        } else if (mode == Mode::Masm) {
            std::string asm_code = GenerateMasmAssembly(info);
            std::ofstream out_asm(output_dir / "stubs.asm");
            out_asm << asm_code;

            std::string cpp_code = GenerateMasmLoader(info, target_dll, logging, file_log);
            std::ofstream out_cpp(output_dir / "dllmain.cpp");
            out_cpp << cpp_code;

            std::string def_code = GenerateMasmDef(info);
            std::ofstream out_def(output_dir / "exports.def");
            out_def << def_code;

            std::ofstream bat(output_dir / "build.bat");
            bat << GenerateBuildBat(info, target_stem, true);
            std::cout << "[+] Generated MASM proxy project in: " << output_dir.string() << "\n";
        } else if (mode == Mode::Def) {
            std::string def_code = GenerateDefSource(info, target_dll);
            std::ofstream out_def(output_dir / "exports.def");
            out_def << def_code;

            std::string src = GeneratePragmaSource(info, target_dll, logging, file_log);
            std::ofstream out_cpp(output_dir / "dllmain.cpp");
            out_cpp << src;

            std::ofstream bat(output_dir / "build.bat");
            bat << GenerateBuildBat(info, target_stem, false);
            std::cout << "[+] Generated DEF proxy project in: " << output_dir.string() << "\n";
        }
    }

    return 0;
}
