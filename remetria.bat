@echo off
setlocal

title Remetria Launcher

REM ------------------------------------------------------------
REM Remetria Launcher
REM ------------------------------------------------------------
REM Runs the analyser executable by default.
REM Falls back to Python source mode when the executable is unavailable.
REM
REM Input:
REM     data\runtime         - active analysis workset
REM
REM Archive:
REM     data\collected       - persistent scan archive
REM
REM Output:
REM     results\json         - generated JSON analysis output
REM     results\reports      - generated Markdown reports
REM     results\tables       - generated CSV tables
REM ------------------------------------------------------------

cd /d "%~dp0"

set "EXE_PATH=dist\remetria.exe"
set "PY_MODULE=remetria.analyser"
set "PYTHONPATH=%CD%\src"
set "SOURCE_FILE=src\remetria\analyser.py"

set "COLLECTED_DIR=data\collected"
set "PRE_UPDATE_DIR=data\collected\pre-update"
set "POST_UPDATE_DIR=data\collected\post-update"
set "RUNTIME_DIR=data\runtime"

set "JSON_DIR=results\json"
set "REPORTS_DIR=results\reports"
set "TABLES_DIR=results\tables"

REM ------------------------------------------------------------
REM PAUSE HELPER
REM ------------------------------------------------------------

goto main

:wait_to_close
echo Press any key to close
pause >nul
exit /b 0


REM ------------------------------------------------------------
REM MAIN WORKFLOW
REM ------------------------------------------------------------

:main

REM ------------------------------------------------------------
REM WINDOWS CHECK
REM ------------------------------------------------------------

if /i not "%OS%"=="Windows_NT" (
    echo [X] This analyser must be run on Windows
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM REQUIRED DIRECTORY PREPARATION
REM ------------------------------------------------------------

if not exist "%COLLECTED_DIR%" (
    mkdir "%COLLECTED_DIR%" >nul 2>&1
)

if not exist "%PRE_UPDATE_DIR%" (
    mkdir "%PRE_UPDATE_DIR%" >nul 2>&1
)

if not exist "%POST_UPDATE_DIR%" (
    mkdir "%POST_UPDATE_DIR%" >nul 2>&1
)

if not exist "%RUNTIME_DIR%" (
    mkdir "%RUNTIME_DIR%" >nul 2>&1
)

if not exist "%JSON_DIR%" (
    mkdir "%JSON_DIR%" >nul 2>&1
)

if not exist "%REPORTS_DIR%" (
    mkdir "%REPORTS_DIR%" >nul 2>&1
)

if not exist "%TABLES_DIR%" (
    mkdir "%TABLES_DIR%" >nul 2>&1
)

REM ------------------------------------------------------------
REM ANALYSER EXECUTION
REM ------------------------------------------------------------

if exist "%EXE_PATH%" (
    "%EXE_PATH%"

    if %errorlevel% neq 0 (
        echo.
        echo [X] Remetria failed
        echo.
        pause
        exit /b 1
    )

    call :wait_to_close
)

where python.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Remetria executable was not found:
    echo     %EXE_PATH%
    echo.
    echo [X] Python fallback is unavailable because Python was not found
    echo.
    echo Build the executable first using:
    echo build\build_exe.bat
    echo.
    pause
    exit /b 1
)

if not exist "%SOURCE_FILE%" (
    echo [X] Source file was not found:
    echo     %SOURCE_FILE%
    echo.
    pause
    exit /b 1
)

python -m "%PY_MODULE%"

if %errorlevel% neq 0 (
    echo.
    echo [X] Remetria failed
    echo.
    pause
    exit /b 1
)

call :wait_to_close