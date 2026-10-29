@echo off
REM Runs the automated self-test (expects 11/11 checks passed).
cd /d "%~dp0"
set PY=python
where python >nul 2>&1 || set PY=py
%PY% campusalert.py demo
echo.
pause
