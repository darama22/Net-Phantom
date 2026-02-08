@echo off
:: Net-Phantom Launcher - Automatically runs as Administrator

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
    echo.
    echo Starting Net-Phantom...
    echo.
    python main.py
) else (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %CD% && python main.py && pause' -Verb RunAs"
)
