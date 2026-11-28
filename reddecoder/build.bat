@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "BUILD_ALL=0"

:parse_args
if "%~1"=="" goto done_args
if /I "%~1"=="--all" (
    set "BUILD_ALL=1"
    shift
    goto parse_args
)
if /I "%~1"=="-h" goto show_help
if /I "%~1"=="--help" goto show_help
echo Unknown option: %~1 >&2
exit /b 1

:show_help
echo Usage: build.bat [--all]
echo   Default : Builds red_decode.exe (builds pbd_fastdec.dll only if missing)
echo   --all   : Rebuilds both red_decode.exe and pbd_fastdec.dll
exit /b 0

:done_args
set "NEED_VCVARS=0"
if /I not "%VSCMD_ARG_TGT_ARCH%"=="x64" set "NEED_VCVARS=1"
if not defined INCLUDE set "NEED_VCVARS=1"
where cl >nul 2>nul
if errorlevel 1 set "NEED_VCVARS=1"

if "%NEED_VCVARS%"=="1" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    if not exist "!VCVARS!" (
        echo ERROR: vcvars64.bat not found at "!VCVARS!" >&2
        exit /b 1
    )
    call "!VCVARS!" >nul
    if errorlevel 1 (
        echo ERROR: Failed to initialize MSVC x64 environment >&2
        exit /b 1
    )
)

pushd "%SCRIPT_DIR%" >nul
set "ERR=0"

echo Building red_decode.exe...
cl /nologo /W4 /O2 /EHsc /std:c++17 "red_decode.cpp" /Fe:"red_decode.exe" /Fo:"red_decode.obj"
if errorlevel 1 (
    set "ERR=1"
)
del /q "red_decode.obj" "red_decode.exp" "red_decode.lib" 2>nul

if "!ERR!"=="0" (
    if "!BUILD_ALL!"=="1" (
        echo Building pbd_fastdec.dll...
        cl /nologo /W4 /O2 /LD "pbd_fastdec.c" /Fe:"pbd_fastdec.dll" /Fo:"pbd_fastdec.obj"
        if errorlevel 1 set "ERR=1"
        del /q "pbd_fastdec.obj" "pbd_fastdec.exp" "pbd_fastdec.lib" 2>nul
    ) else if not exist "pbd_fastdec.dll" (
        echo pbd_fastdec.dll missing; building pbd_fastdec.dll...
        cl /nologo /W4 /O2 /LD "pbd_fastdec.c" /Fe:"pbd_fastdec.dll" /Fo:"pbd_fastdec.obj"
        if errorlevel 1 set "ERR=1"
        del /q "pbd_fastdec.obj" "pbd_fastdec.exp" "pbd_fastdec.lib" 2>nul
    ) else (
        echo Skipping pbd_fastdec.dll ^(already present; pass --all to rebuild^).
    )
)

popd >nul
exit /b %ERR%
