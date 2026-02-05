@echo off
setlocal
title Network Project Setup

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. 
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b
)

echo [+] Python detected.

echo [*] Upgrading pip...
python -m pip install --upgrade pip

echo [*] Installing Scapy...
pip install -r requirements.txt

echo.
echo [!] IMPORTANT: This project requires Npcap to capture packets.
echo If you don't have it, download it here: https://npcap.com/dist/npcap-1.79.exe
echo.
set /p install_npcap="Would you like to open the Npcap download page? (y/n): "
if /i "%install_npcap%"=="y" (
    start https://npcap.com/#download
)

echo.
echo [+] Setup process complete!
echo [!] Remember to run your script as ADMINISTRATOR.
pause