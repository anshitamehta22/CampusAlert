@echo off
REM Closes the CampusAlert server and listener windows.
taskkill /F /FI "WINDOWTITLE eq CampusAlert*" >nul 2>&1
echo CampusAlert stopped.
timeout /t 3 >nul
