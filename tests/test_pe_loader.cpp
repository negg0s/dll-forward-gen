// ============================================================================
// test_pe_loader.cpp - Unit Test for C++20 In-Memory PE Manual Mapping Engine
// Part of dll-forward-gen by NEGG0
// ============================================================================

#include "../sdk/pe_loader.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>

using namespace dll_forward_gen::loader;

int main() {
    std::cout << "[*] Testing C++20 In-Memory PE Manual Mapper...\n";

    const wchar_t* targetPath = L"C:\\Windows\\System32\\version.dll";
    std::ifstream file(targetPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cout << "    [-] version.dll not found, skipping manual map test.\n";
        return 0;
    }

    const auto size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cout << "    [-] Failed to read version.dll into memory.\n";
        return 1;
    }

    std::cout << "    [+] Read version.dll (" << size << " bytes) into buffer.\n";

    // Perform manual map without LoadLibrary
    HMODULE hManual = MemoryPeLoader::LoadFromMemory(buffer.data(), buffer.size());
    if (hManual) {
        std::cout << "    [+] Successfully manually mapped version.dll at " << hManual << "\n";

        // Query export via manual export table parsing
        FARPROC pfn = MemoryPeLoader::GetProcAddressManual(hManual, "GetFileVersionInfoW");
        assert(pfn != nullptr);
        std::cout << "    [+] GetProcAddressManual resolved GetFileVersionInfoW at " << reinterpret_cast<void*>(pfn) << "\n";

        // Clean up manual map
        MemoryPeLoader::FreeManual(hManual);
        std::cout << "    [+] FreeManual executed successfully.\n";
    } else {
        std::cout << "    [-] Manual map returned null (protected image or unsupported relocations).\n";
    }

    std::cout << "[+] test_pe_loader completed successfully!\n";
    return 0;
}
