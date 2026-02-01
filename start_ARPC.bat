@echo off
cd /d %~dp0
powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/k python "%~dp0ARPC.py" & pause' -Verb RunAs"
exit /b
