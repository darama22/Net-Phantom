@echo off
:: Solicita elevación automáticamente
powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %~dp0 && python main.py && pause' -Verb RunAs"
