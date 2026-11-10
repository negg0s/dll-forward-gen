// ===========================================================================
// MASM DLL Loader & Function Pointer Binder for VERSION.dll
// ===========================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

// Global handle to real loaded library
static HMODULE g_hRealDll = NULL;

// Function pointer storage accessed by MASM assembly
extern "C" {
    FARPROC g_pfn_GetFileVersionInfoA = NULL;
    FARPROC g_pfn_GetFileVersionInfoByHandle = NULL;
    FARPROC g_pfn_GetFileVersionInfoExA = NULL;
    FARPROC g_pfn_GetFileVersionInfoExW = NULL;
    FARPROC g_pfn_GetFileVersionInfoSizeA = NULL;
    FARPROC g_pfn_GetFileVersionInfoSizeExA = NULL;
    FARPROC g_pfn_GetFileVersionInfoSizeExW = NULL;
    FARPROC g_pfn_GetFileVersionInfoSizeW = NULL;
    FARPROC g_pfn_GetFileVersionInfoW = NULL;
    FARPROC g_pfn_VerFindFileA = NULL;
    FARPROC g_pfn_VerFindFileW = NULL;
    FARPROC g_pfn_VerInstallFileA = NULL;
    FARPROC g_pfn_VerInstallFileW = NULL;
    FARPROC g_pfn_VerLanguageNameA = NULL;
    FARPROC g_pfn_VerLanguageNameW = NULL;
    FARPROC g_pfn_VerQueryValueA = NULL;
    FARPROC g_pfn_VerQueryValueW = NULL;
}

// Real library loader and symbol resolver
static BOOL LoadRealLibrary() {
    if (g_hRealDll != NULL) return TRUE;

    const wchar_t* targetPath = L"C:\\Windows\\System32\\VERSION.dll";
    g_hRealDll = LoadLibraryW(targetPath);
    if (!g_hRealDll) {
        wchar_t sysDir[MAX_PATH];
        if (GetSystemDirectoryW(sysDir, MAX_PATH)) {
            wchar_t fallbackPath[MAX_PATH];
            swprintf_s(fallbackPath, MAX_PATH, L"%s\\VERSION.dll", sysDir);
            g_hRealDll = LoadLibraryW(fallbackPath);
        }
    }

    if (!g_hRealDll) {
        OutputDebugStringA("[FATAL] Failed to load real VERSION.dll\n");
        return FALSE;
    }

    // Bind all original function pointers
    g_pfn_GetFileVersionInfoA = GetProcAddress(g_hRealDll, "GetFileVersionInfoA");
    g_pfn_GetFileVersionInfoByHandle = GetProcAddress(g_hRealDll, "GetFileVersionInfoByHandle");
    g_pfn_GetFileVersionInfoExA = GetProcAddress(g_hRealDll, "GetFileVersionInfoExA");
    g_pfn_GetFileVersionInfoExW = GetProcAddress(g_hRealDll, "GetFileVersionInfoExW");
    g_pfn_GetFileVersionInfoSizeA = GetProcAddress(g_hRealDll, "GetFileVersionInfoSizeA");
    g_pfn_GetFileVersionInfoSizeExA = GetProcAddress(g_hRealDll, "GetFileVersionInfoSizeExA");
    g_pfn_GetFileVersionInfoSizeExW = GetProcAddress(g_hRealDll, "GetFileVersionInfoSizeExW");
    g_pfn_GetFileVersionInfoSizeW = GetProcAddress(g_hRealDll, "GetFileVersionInfoSizeW");
    g_pfn_GetFileVersionInfoW = GetProcAddress(g_hRealDll, "GetFileVersionInfoW");
    g_pfn_VerFindFileA = GetProcAddress(g_hRealDll, "VerFindFileA");
    g_pfn_VerFindFileW = GetProcAddress(g_hRealDll, "VerFindFileW");
    g_pfn_VerInstallFileA = GetProcAddress(g_hRealDll, "VerInstallFileA");
    g_pfn_VerInstallFileW = GetProcAddress(g_hRealDll, "VerInstallFileW");
    g_pfn_VerLanguageNameA = GetProcAddress(g_hRealDll, "VerLanguageNameA");
    g_pfn_VerLanguageNameW = GetProcAddress(g_hRealDll, "VerLanguageNameW");
    g_pfn_VerQueryValueA = GetProcAddress(g_hRealDll, "VerQueryValueA");
    g_pfn_VerQueryValueW = GetProcAddress(g_hRealDll, "VerQueryValueW");

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)lpReserved;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        LoadRealLibrary();
        {
            FILE* f = NULL;
            if (fopen_s(&f, "proxy_log.txt", "a") == 0 && f) {
                fprintf(f, "[MASM PROXY] Attached: VERSION.dll\n");
                fclose(f);
            }
        }
        break;
    case DLL_PROCESS_DETACH:
        if (g_hRealDll) {
            FreeLibrary(g_hRealDll);
            g_hRealDll = NULL;
        }
        break;
    }
    return TRUE;
}
