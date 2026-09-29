@echo off
title PQC Forensics & DLT Command Platform (SIH26237)
cls
echo ======================================================================
echo   AIR-GAPPED POST-QUANTUM FORENSICS & DLT PLATFORM (SIH26237)
echo ======================================================================
echo   Strict Tech Stack: C, C++, HTML, JS, Tauri (ZERO PYTHON)
echo   Features: 5-Panel Commander + Recipient Portal + 2D-DCT + DLT Ledger
echo ======================================================================
echo.
echo [1] Start Sovereign Air-Gapped Platform (Commander & Recipient Portal)
echo [2] Run C/C++ Native Forensic & PQC Test Pipeline (offline_core.exe)
echo [3] Run C++ 176-Pass 2D-DCT Steganography Engine (sih_dct_engine.exe)
echo [4] Run C Acoustic Signal Engine (sih_signal_engine.exe)
echo [5] Exit
echo.
set /p choice="Select Option (1-5): "

if "%choice%"=="1" goto start_platform
if "%choice%"=="2" goto run_core
if "%choice%"=="3" goto run_dct
if "%choice%"=="4" goto run_signal
if "%choice%"=="5" goto end

:start_platform
cls
echo [INFO] Starting Air-Gapped Platform on http://127.0.0.1:8080...
echo [INFO] Opening Commander Console and Recipient Portal...
start http://127.0.0.1:8080
start http://127.0.0.1:8080/portal.html
node server.js
pause
goto end

:run_core
cls
echo [INFO] Executing Native C/C++ PQC & Anti-Crop Forensic Pipeline...
offline_core.exe
pause
goto end

:run_dct
cls
echo [INFO] Executing C++ 176-Pass 2D-DCT Steganography Engine...
sih_dct_engine.exe
pause
goto end

:run_signal
cls
echo [INFO] Executing C Acoustic Pulse Signal Engine...
sih_signal_engine.exe
pause
goto end

:end
