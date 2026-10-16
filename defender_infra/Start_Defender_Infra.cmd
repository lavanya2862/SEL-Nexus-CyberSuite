@echo off
title Defender ^& Infrastructure
rem Starts the Defender & Infrastructure module of SEL Nexus CyberSuite from this folder.
rem Normally called by ..\Start_All.cmd. Started on its own, it also starts the shared sign-in page (port 8000) if that
rem is not running yet, because people sign in there.
rem Any other copy already using the same ports (8800 portal, 8700 fixing, 8900 alert triage) is stopped first.
cd /d "%~dp0Unified_Cyber_Portal"

echo Stopping any other copy that is running...
powershell -NoProfile -Command "foreach ($p in 8800,8700,8900) { Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue } }"
timeout /t 2 /nobreak >nul

echo Starting Defender ^& Infrastructure...
start "Defender & Infrastructure (keep open)" /min .venv\Scripts\python.exe -m portal serve --port 8800

powershell -NoProfile -Command "$ok=$false; for ($i=0; $i -lt 40 -and -not $ok; $i++) { try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8800/api/health -TimeoutSec 2 | Out-Null; $ok=$true } catch { Start-Sleep -Milliseconds 500 } }; if (-not $ok) { exit 1 }"
if errorlevel 1 (
  echo Defender ^& Infrastructure did not start. Open the minimised "Defender & Infrastructure" window to see why.
  pause
  exit /b 1
)

rem The shared sign-in page, when this script is started on its own
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/api/health -TimeoutSec 2 | Out-Null } catch { exit 1 }"
if errorlevel 1 if exist "%~dp0..\login\.venv\Scripts\python.exe" (
  echo Starting the SEL Nexus CyberSuite sign-in page...
  start "SEL Nexus CyberSuite sign-in (keep open)" /min /d "%~dp0..\login" "%~dp0..\login\.venv\Scripts\python.exe" server.py
)

if not "%CC_NO_BROWSER%"=="1" start "" http://127.0.0.1:8000
echo.
echo Defender ^& Infrastructure is running at http://127.0.0.1:8800 (sign in at http://127.0.0.1:8000)
echo To stop it, double-click Stop_Defender_Infra.cmd
if not "%CC_NO_BROWSER%"=="1" timeout /t 5 >nul
