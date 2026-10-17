@echo off
setlocal
cd /d "%~dp0"
go build -ldflags="-H windowsgui -s -w" -o mullvad-fastest.exe .
if errorlevel 1 exit /b 1
echo Built mullvad-fastest.exe
