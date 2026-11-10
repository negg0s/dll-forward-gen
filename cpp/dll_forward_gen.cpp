// ============================================================================
// dll_forward_gen.cpp - Native C++20 PE Export Forwarder & Analyzer CLI
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Zero-dependency native Windows C++20 tool for PE export parsing & proxying.
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

namespace fs = std::filesystem;

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

        bool is_64 = false;
        DWORD export_rva = 0;
        DWORD export_size = 0;

        if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            is_64 = true;
            out_info.arch = "X64";
            const auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(opt_hdr_raw);
            export_rva = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_size = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            is_64 = false;
            out_info.arch = "X86";
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

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "dll-forward-gen (Native C++20 CLI)\n";
        std::cout << "Usage: dll-forward-gen.exe <target.dll> [--dump] [--pragma] [--output <dir>]\n";
        return 1;
    }

    fs::path target_path = argv[1];
    if (!fs::exists(target_path)) {
        // Search System32
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

    PrintTable(info);
    return 0;
}
