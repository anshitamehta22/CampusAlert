@echo off
REM Sends a quick test alert to the Hostel zone from the command line.
cd /d "%~dp0"
set PY=python
where python >nul 2>&1 || set PY=py
%PY% campusalert.py send --server 127.0.0.1 -l critical -z hostel -t "Fire alarm" -m "Evacuate now via the nearest exit"
echo.
pause
