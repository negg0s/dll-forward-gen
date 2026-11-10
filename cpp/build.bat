@echo off
setlocal

echo [dll-forward-gen] Building Native C++20 CLI Engine...

where cl.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] MSVC cl.exe not found in PATH!
    echo Please run this from a Visual Studio Developer Command Prompt (x64/x86).
    exit /b 1
)

cl.exe /nologo /O2 /W4 /std:c++20 /EHsc dll_forward_gen.cpp /Fe:dll-forward-gen.exe

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Built dll-forward-gen.exe successfully!
) else (
    echo [ERROR] Compilation failed!
)

endlocal
