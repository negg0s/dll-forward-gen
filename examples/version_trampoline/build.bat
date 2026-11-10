@echo off
setlocal enabledelayedexpansion

echo [dll-forward-gen] Building VERSION.dll proxy (x64)...

where cl.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] MSVC cl.exe not found in PATH!
    echo Please run this from a Visual Studio Developer Command Prompt (x64/x86).
    exit /b 1
)

if not exist build mkdir build
pushd build

if exist ..\exports.def (
    cl.exe /nologo /O2 /W4 /LD ..\dllmain.cpp /DEF:..\exports.def /Fe:VERSION.dll /link /MACHINE:X64
) else (
    cl.exe /nologo /O2 /W4 /LD ..\dllmain.cpp /Fe:VERSION.dll /link /MACHINE:X64
)

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Built VERSION.dll successfully!
    echo Output: %CD%\VERSION.dll
) else (
    echo [ERROR] Compilation failed!
)

popd
endlocal
