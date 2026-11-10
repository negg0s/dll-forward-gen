// ===========================================================================
// Dynamic Intercepting Trampoline Proxy for VERSION.dll
// Architecture: x64 | Total exports: 17
// ===========================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

// Global handle to real loaded library
static HMODULE g_hRealDll = NULL;

// Function pointer storage
static FARPROC g_pfn_GetFileVersionInfoA = NULL;
static FARPROC g_pfn_GetFileVersionInfoByHandle = NULL;
static FARPROC g_pfn_GetFileVersionInfoExA = NULL;
static FARPROC g_pfn_GetFileVersionInfoExW = NULL;
static FARPROC g_pfn_GetFileVersionInfoSizeA = NULL;
static FARPROC g_pfn_GetFileVersionInfoSizeExA = NULL;
static FARPROC g_pfn_GetFileVersionInfoSizeExW = NULL;
static FARPROC g_pfn_GetFileVersionInfoSizeW = NULL;
static FARPROC g_pfn_GetFileVersionInfoW = NULL;
static FARPROC g_pfn_VerFindFileA = NULL;
static FARPROC g_pfn_VerFindFileW = NULL;
static FARPROC g_pfn_VerInstallFileA = NULL;
static FARPROC g_pfn_VerInstallFileW = NULL;
static FARPROC g_pfn_VerLanguageNameA = NULL;
static FARPROC g_pfn_VerLanguageNameW = NULL;
static FARPROC g_pfn_VerQueryValueA = NULL;
static FARPROC g_pfn_VerQueryValueW = NULL;

// Real library loader and symbol resolver
static BOOL LoadRealLibrary() {
    if (g_hRealDll != NULL) return TRUE;

    const wchar_t* targetPath = L"C:\\Windows\\System32\\VERSION.dll";
    g_hRealDll = LoadLibraryW(targetPath);
    if (!g_hRealDll) {
        // Fallback: try loading from Windows System Directory directly
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

    // Resolve all target functions
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

// --- Proxy Wrapper Stubs ---
extern "C" void* __stdcall proxy_GetFileVersionInfoA() {
    if (!g_pfn_GetFileVersionInfoA) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoA\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_GetFileVersionInfoA;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_GetFileVersionInfoByHandle() {
    if (!g_pfn_GetFileVersionInfoByHandle) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoByHandle\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_GetFileVersionInfoByHandle;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_GetFileVersionInfoExA() {
    if (!g_pfn_GetFileVersionInfoExA) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoExA\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_GetFileVersionInfoExA;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_GetFileVersionInfoExW() {
    if (!g_pfn_GetFileVersionInfoExW) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoExW\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_GetFileVersionInfoExW;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_GetFileVersionInfoSizeA() {
    if (!g_pfn_GetFileVersionInfoSizeA) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoSizeA\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_GetFileVersionInfoSizeA;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_GetFileVersionInfoSizeExA() {
    if (!g_pfn_GetFileVersionInfoSizeExA) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoSizeExA\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_GetFileVersionInfoSizeExA;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_GetFileVersionInfoSizeExW() {
    if (!g_pfn_GetFileVersionInfoSizeExW) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoSizeExW\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_GetFileVersionInfoSizeExW;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_GetFileVersionInfoSizeW() {
    if (!g_pfn_GetFileVersionInfoSizeW) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoSizeW\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_GetFileVersionInfoSizeW;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_GetFileVersionInfoW() {
    if (!g_pfn_GetFileVersionInfoW) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: GetFileVersionInfoW\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_GetFileVersionInfoW;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_VerFindFileA() {
    if (!g_pfn_VerFindFileA) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: VerFindFileA\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_VerFindFileA;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_VerFindFileW() {
    if (!g_pfn_VerFindFileW) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: VerFindFileW\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_VerFindFileW;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_VerInstallFileA() {
    if (!g_pfn_VerInstallFileA) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: VerInstallFileA\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_VerInstallFileA;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_VerInstallFileW() {
    if (!g_pfn_VerInstallFileW) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: VerInstallFileW\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_VerInstallFileW;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_VerLanguageNameA() {
    if (!g_pfn_VerLanguageNameA) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: VerLanguageNameA\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_VerLanguageNameA;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_VerLanguageNameW() {
    if (!g_pfn_VerLanguageNameW) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: VerLanguageNameW\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_VerLanguageNameW;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_VerQueryValueA() {
    if (!g_pfn_VerQueryValueA) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: VerQueryValueA\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_VerQueryValueA;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

extern "C" void* __stdcall proxy_VerQueryValueW() {
    if (!g_pfn_VerQueryValueW) LoadRealLibrary();
    OutputDebugStringA("[PROXY TRACE] Call: VerQueryValueW\n");
    // Dispatch to resolved original function
    FARPROC pfn = g_pfn_VerQueryValueW;
    if (!pfn) return NULL;
    return ((void* (__stdcall*)())pfn)();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)lpReserved;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        LoadRealLibrary();
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
