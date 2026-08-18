@echo off
setlocal

title Remetria EXE Builder

REM ------------------------------------------------------------
REM Remetria EXE Builder
REM ------------------------------------------------------------
REM Builds:
REM     src\remetria\analyser.py
REM
REM Into:
REM     dist\remetria.exe
REM ------------------------------------------------------------

cd /d "%~dp0\.."

set "SOURCE_FILE=src\remetria\analyser.py"
set "EXE_NAME=remetria"
set "DIST_DIR=dist"
set "WORK_DIR=build\pyinstaller"
set "SPEC_DIR=build\pyinstaller"

echo.
echo Build Remetria EXE
echo ==================

echo.
echo Source Check
echo ------------
echo [*] Checking source file
echo     [i] Source: %SOURCE_FILE%

if not exist "%SOURCE_FILE%" (
    echo     [X] Source file not found
    echo.
    pause
    exit /b 1
)

echo     [+] Source file found

echo.
echo Python Check
echo ------------
echo [*] Checking Python runtime

where python.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo     [X] Python was not found
    echo.
    echo Install Python, then rerun:
    echo build\build_exe.bat
    echo.
    pause
    exit /b 1
)

echo     [+] Python runtime found

echo.
echo Dependency Check
echo ----------------
echo [*] Checking PyInstaller

python -m pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo     [i] PyInstaller not found
    echo     [*] Installing build dependency
    echo.

    python -m pip install -r requirements.txt

    if %errorlevel% neq 0 (
        echo.
        echo     [X] Failed to install build dependency
        echo.
        pause
        exit /b 1
    )
)

echo     [+] PyInstaller available

echo.
echo Build Preparation
echo -----------------
echo [*] Preparing build workspace
echo     [i] Previous executable: %DIST_DIR%\%EXE_NAME%.exe
echo     [i] Build workspace: %WORK_DIR%
echo     [i] Spec folder: %SPEC_DIR%

if not exist "%DIST_DIR%" (
    mkdir "%DIST_DIR%" >nul 2>&1
)

if exist "%DIST_DIR%\%EXE_NAME%.exe" (
    del /f /q "%DIST_DIR%\%EXE_NAME%.exe" >nul 2>&1
)

if exist "%WORK_DIR%" (
    rmdir /s /q "%WORK_DIR%" >nul 2>&1
)

mkdir "%WORK_DIR%" >nul 2>&1
type nul > "%WORK_DIR%\.gitkeep"

if exist "%SPEC_DIR%\%EXE_NAME%.spec" (
    del /f /q "%SPEC_DIR%\%EXE_NAME%.spec" >nul 2>&1
)

echo     [+] Build workspace prepared

echo.
echo Executable Build
echo ----------------
echo [*] Building Remetria executable
echo     [i] Source: %SOURCE_FILE%
echo     [i] Output: %DIST_DIR%\%EXE_NAME%.exe

python -m PyInstaller ^
    --onefile ^
    --clean ^
    --console ^
    --log-level WARN ^
    --name "%EXE_NAME%" ^
    --paths "src" ^
    --distpath "%DIST_DIR%" ^
    --workpath "%WORK_DIR%" ^
    --specpath "%SPEC_DIR%" ^
    "%SOURCE_FILE%"

if %errorlevel% neq 0 (
    echo.
    echo     [X] Build failed
    echo.
    pause
    exit /b 1
)

echo     [+] Executable build finished

echo.
echo Output Verification
echo -------------------
echo [*] Verifying executable output
echo     [i] Executable: %DIST_DIR%\%EXE_NAME%.exe

if not exist "%DIST_DIR%\%EXE_NAME%.exe" (
    echo     [X] Executable was not found
    echo.
    pause
    exit /b 1
)

if not exist "%WORK_DIR%\.gitkeep" (
    type nul > "%WORK_DIR%\.gitkeep"
)

echo     [+] Executable verified

echo.
echo [+] Build completed
echo.
pause
exit /b 0