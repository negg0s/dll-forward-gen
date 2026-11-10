// ===========================================================================
// tests/test_api_hash.cpp - Unit test for C++20 ApiHash & Resolver SDK
// Part of dll-forward-gen
// ===========================================================================

#include "../sdk/api_hash.hpp"
#include <iostream>
#include <cassert>

using namespace dll_forward_gen::crypto;

int main() {
    std::cout << "[*] Testing C++20 ApiHash SDK...\n";

    // 1. Compile-time constexpr hash calculation checks
    constexpr uint32_t rorHash = ApiHash::ROR13("GetFileVersionInfoA");
    static_assert(rorHash == 0x9D1DF4B3, "ROR13 constexpr hash mismatch");

    constexpr uint32_t djbHash = ApiHash::DJB2("GetFileVersionInfoA");
    static_assert(djbHash == 0xD574F958, "DJB2 constexpr hash mismatch");

    constexpr uint32_t fnvHash = ApiHash::FNV1a("GetFileVersionInfoA");
    static_assert(fnvHash == 0x42D7EAD2, "FNV1a constexpr hash mismatch");

    constexpr uint32_t crcHash = ApiHash::CRC32("GetFileVersionInfoA");
    static_assert(crcHash == 0x5DE9D9BD, "CRC32 constexpr hash mismatch");

    std::cout << "    [+] All static_assert constexpr hash calculations PASSED!\n";
    std::cout << "        ROR13: 0x" << std::hex << rorHash << "\n";
    std::cout << "        DJB2:  0x" << djbHash << "\n";
    std::cout << "        FNV1a: 0x" << fnvHash << "\n";
    std::cout << "        CRC32: 0x" << crcHash << std::dec << "\n";

    // 2. Runtime in-memory EAT resolution from live module
    HMODULE hVersion = LoadLibraryW(L"version.dll");
    assert(hVersion != nullptr);

    // Resolve GetFileVersionInfoA via ROR13
    FARPROC pfnDirect = GetProcAddress(hVersion, "GetFileVersionInfoA");
    assert(pfnDirect != nullptr);

    FARPROC pfnHashed = ApiHash::GetProcAddressByHash(hVersion, rorHash, HashAlgorithm::ROR13);
    assert(pfnHashed != nullptr);
    assert(pfnHashed == pfnDirect);
    std::cout << "    [+] GetProcAddressByHash(ROR13) resolved correctly: " << pfnHashed << "\n";

    // Resolve via DJB2
    FARPROC pfnDjb = ApiHash::GetProcAddressByHash(hVersion, djbHash, HashAlgorithm::DJB2);
    assert(pfnDjb == pfnDirect);
    std::cout << "    [+] GetProcAddressByHash(DJB2) resolved correctly: " << pfnDjb << "\n";

    // Resolve via FNV1a
    FARPROC pfnFnv = ApiHash::GetProcAddressByHash(hVersion, fnvHash, HashAlgorithm::FNV1a);
    assert(pfnFnv == pfnDirect);
    std::cout << "    [+] GetProcAddressByHash(FNV1a) resolved correctly: " << pfnFnv << "\n";

    // Resolve via CRC32
    FARPROC pfnCrc = ApiHash::GetProcAddressByHash(hVersion, crcHash, HashAlgorithm::CRC32);
    assert(pfnCrc == pfnDirect);
    std::cout << "    [+] GetProcAddressByHash(CRC32) resolved correctly: " << pfnCrc << "\n";

    // 3. Forwarded export resolution test: VerLanguageNameA -> KERNEL32.VerLanguageNameA
    constexpr uint32_t fwdRor = ApiHash::ROR13("VerLanguageNameA");
    FARPROC pfnFwdDirect = GetProcAddress(hVersion, "VerLanguageNameA");
    FARPROC pfnFwdHashed = ApiHash::GetProcAddressByHash(hVersion, fwdRor, HashAlgorithm::ROR13);
    assert(pfnFwdHashed != nullptr);
    assert(pfnFwdHashed == pfnFwdDirect);
    std::cout << "    [+] Forwarded export VerLanguageNameA resolved via hash: " << pfnFwdHashed << "\n";

    // 4. Null safety checks
    assert(ApiHash::GetProcAddressByHash(nullptr, 0x1234) == nullptr);
    assert(ApiHash::GetProcAddressByHash(hVersion, 0xDEADBEEF) == nullptr);

    std::cout << "[+] test_api_hash completed successfully!\n";
    return 0;
}
