@echo off
:: Net-Phantom Launcher
set "APPDIR=%~dp0"

net session >nul 2>&1
if %errorLevel% == 0 (
    echo Starting Net-Phantom...
    cd /d "%APPDIR%"
    python main.py
) else (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/k cd /d ""%APPDIR%"" && python main.py' -Verb RunAs"
)
