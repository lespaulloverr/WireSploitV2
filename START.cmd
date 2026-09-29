@echo off
cd /d "%~dp0"
start "WireSploit Server" cmd /k "python -m uvicorn main:app --host 127.0.0.1 --port 8765"
timeout /t 2 >nul
start "" http://127.0.0.1:8765/
