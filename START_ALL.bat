@echo off
REM ===== CampusAlert: one double-click start =====
REM Change the PIN below if you want a different operator PIN.
set PIN=4321

cd /d "%~dp0"
set PY=python
where python >nul 2>&1 || set PY=py

echo Starting CampusAlert hub...
start "CampusAlert Server" cmd /k %PY% campusalert.py server --pin %PIN%
timeout /t 3 /nobreak >nul

echo Starting a test listener (Lab PC, Hostel zone)...
start "CampusAlert Listener" cmd /k %PY% campusalert.py listen --server 127.0.0.1 --name "Lab PC" --zone hostel
timeout /t 1 /nobreak >nul

echo Opening dashboard and phone page in your browser...
start "" http://127.0.0.1:8080/
start "" http://127.0.0.1:8080/client

echo.
echo Done. For maam's phone, use the "Phone client" link printed in the Server window.
echo (It starts with your laptop's IP, not 127.0.0.1.)
timeout /t 8 >nul
