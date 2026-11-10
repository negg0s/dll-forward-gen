// ===========================================================================
// tests/test_syscall.cpp - Unit test for C++20 SyscallResolver SDK
// Part of dll-forward-gen
// ===========================================================================

#include "../sdk/syscall.hpp"
#include <iostream>
#include <cassert>

using namespace dll_forward_gen::syscall;

int main() {
    std::cout << "[*] Testing C++20 SyscallResolver SDK...\n";

    // 1. Resolve well-known Windows system calls
    int32_t ssnAlloc = SyscallResolver::GetSyscallNumber("NtAllocateVirtualMemory");
    std::cout << "    [+] NtAllocateVirtualMemory SSN: 0x" << std::hex << ssnAlloc << std::dec << " (" << ssnAlloc << ")\n";
    assert(ssnAlloc >= 0);

    int32_t ssnProtect = SyscallResolver::GetSyscallNumber("NtProtectVirtualMemory");
    std::cout << "    [+] NtProtectVirtualMemory SSN:  0x" << std::hex << ssnProtect << std::dec << " (" << ssnProtect << ")\n";
    assert(ssnProtect >= 0);

    int32_t ssnQuery = SyscallResolver::GetSyscallNumber("NtQueryInformationProcess");
    std::cout << "    [+] NtQueryInformationProcess SSN: 0x" << std::hex << ssnQuery << std::dec << " (" << ssnQuery << ")\n";
    assert(ssnQuery >= 0);

    // 2. Locate in-ntdll indirect syscall gadget (syscall; ret)
#if defined(_M_X64)
    const void* pGadget = SyscallResolver::GetSyscallGadget();
    std::cout << "    [+] In-ntdll 'syscall; ret' gadget found at: " << pGadget << "\n";
    assert(pGadget != nullptr);
    const auto* pBytes = reinterpret_cast<const uint8_t*>(pGadget);
    assert(pBytes[0] == 0x0F && pBytes[1] == 0x05 && pBytes[2] == 0xC3);
#endif

    // 3. Null safety checks
    assert(SyscallResolver::GetSyscallNumber(nullptr) == -1);
    assert(SyscallResolver::GetSyscallNumber("NonExistentFunction12345") == -1);

    std::cout << "[+] test_syscall completed successfully!\n";
    return 0;
}
