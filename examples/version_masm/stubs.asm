; ===========================================================================
; MASM Assembly JMP Trampoline Stubs for VERSION.dll
; Architecture: x64 | Ptr Size: qword
; Zero-overhead, zero-register corruption assembly forwarding.
; ===========================================================================
.code

; --- External Function Pointer Declarations ---
extern g_pfn_GetFileVersionInfoA : qword
extern g_pfn_GetFileVersionInfoByHandle : qword
extern g_pfn_GetFileVersionInfoExA : qword
extern g_pfn_GetFileVersionInfoExW : qword
extern g_pfn_GetFileVersionInfoSizeA : qword
extern g_pfn_GetFileVersionInfoSizeExA : qword
extern g_pfn_GetFileVersionInfoSizeExW : qword
extern g_pfn_GetFileVersionInfoSizeW : qword
extern g_pfn_GetFileVersionInfoW : qword
extern g_pfn_VerFindFileA : qword
extern g_pfn_VerFindFileW : qword
extern g_pfn_VerInstallFileA : qword
extern g_pfn_VerInstallFileW : qword
extern g_pfn_VerLanguageNameA : qword
extern g_pfn_VerLanguageNameW : qword
extern g_pfn_VerQueryValueA : qword
extern g_pfn_VerQueryValueW : qword

; --- Direct Assembly Jump Stubs ---
proxy_GetFileVersionInfoA proc
    jmp qword ptr [g_pfn_GetFileVersionInfoA]
proxy_GetFileVersionInfoA endp

proxy_GetFileVersionInfoByHandle proc
    jmp qword ptr [g_pfn_GetFileVersionInfoByHandle]
proxy_GetFileVersionInfoByHandle endp

proxy_GetFileVersionInfoExA proc
    jmp qword ptr [g_pfn_GetFileVersionInfoExA]
proxy_GetFileVersionInfoExA endp

proxy_GetFileVersionInfoExW proc
    jmp qword ptr [g_pfn_GetFileVersionInfoExW]
proxy_GetFileVersionInfoExW endp

proxy_GetFileVersionInfoSizeA proc
    jmp qword ptr [g_pfn_GetFileVersionInfoSizeA]
proxy_GetFileVersionInfoSizeA endp

proxy_GetFileVersionInfoSizeExA proc
    jmp qword ptr [g_pfn_GetFileVersionInfoSizeExA]
proxy_GetFileVersionInfoSizeExA endp

proxy_GetFileVersionInfoSizeExW proc
    jmp qword ptr [g_pfn_GetFileVersionInfoSizeExW]
proxy_GetFileVersionInfoSizeExW endp

proxy_GetFileVersionInfoSizeW proc
    jmp qword ptr [g_pfn_GetFileVersionInfoSizeW]
proxy_GetFileVersionInfoSizeW endp

proxy_GetFileVersionInfoW proc
    jmp qword ptr [g_pfn_GetFileVersionInfoW]
proxy_GetFileVersionInfoW endp

proxy_VerFindFileA proc
    jmp qword ptr [g_pfn_VerFindFileA]
proxy_VerFindFileA endp

proxy_VerFindFileW proc
    jmp qword ptr [g_pfn_VerFindFileW]
proxy_VerFindFileW endp

proxy_VerInstallFileA proc
    jmp qword ptr [g_pfn_VerInstallFileA]
proxy_VerInstallFileA endp

proxy_VerInstallFileW proc
    jmp qword ptr [g_pfn_VerInstallFileW]
proxy_VerInstallFileW endp

proxy_VerLanguageNameA proc
    jmp qword ptr [g_pfn_VerLanguageNameA]
proxy_VerLanguageNameA endp

proxy_VerLanguageNameW proc
    jmp qword ptr [g_pfn_VerLanguageNameW]
proxy_VerLanguageNameW endp

proxy_VerQueryValueA proc
    jmp qword ptr [g_pfn_VerQueryValueA]
proxy_VerQueryValueA endp

proxy_VerQueryValueW proc
    jmp qword ptr [g_pfn_VerQueryValueW]
proxy_VerQueryValueW endp

end
