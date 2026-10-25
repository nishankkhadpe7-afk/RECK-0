@echo off
setlocal
cd /d "%~dp0"

echo ==========================================
echo   RECK-0 Investigator Console
echo   Local development launcher
echo ==========================================

if not exist ".venv\Scripts\python.exe" (
    echo [SETUP] Creating Python virtual environment...
    where py >nul 2>nul
    if %errorlevel%==0 (
        py -3 -m venv .venv
    ) else (
        python -m venv .venv
    )
    if errorlevel 1 goto :error
)

echo [SETUP] Installing required packages...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :error

echo.
echo RECK-0 will be available at http://127.0.0.1:8000
echo Keep this window open while using the app. Press Ctrl+C to stop.
echo.
".venv\Scripts\python.exe" -m uvicorn server:app --host 127.0.0.1 --port 8000
if errorlevel 1 goto :error
goto :eof

:error
echo.
echo Startup failed. Check the error above and ensure Python 3.10+ is installed.
pause
exit /b 1
