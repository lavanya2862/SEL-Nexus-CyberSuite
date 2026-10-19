@echo off
title SEL Nexus CyberSuite
rem Starts the whole SEL Nexus CyberSuite and opens the sign-in page in the browser:
rem   login\                  shared sign-in page        http://127.0.0.1:8000
rem   defender_infra\         Defender & Infrastructure  http://127.0.0.1:8800
rem   ApplicationVulnerabilities\  Application Vulnerabilities  http://127.0.0.1:8500
set "SUITE=%~dp0"
set CC_NO_BROWSER=1

echo Stopping any sign-in page that is already running...
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"
timeout /t 1 /nobreak >nul

if not exist "%SUITE%login\.venv\Scripts\python.exe" (
  echo Setting up the sign-in page, first time only...
  python -m venv "%SUITE%login\.venv" && "%SUITE%login\.venv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check -r "%SUITE%login\requirements.txt"
)

echo Starting the sign-in page...
start "SEL Nexus CyberSuite sign-in (keep open)" /min /d "%SUITE%login" "%SUITE%login\.venv\Scripts\python.exe" server.py
powershell -NoProfile -Command "$ok=$false; for ($i=0; $i -lt 40 -and -not $ok; $i++) { try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/api/health -TimeoutSec 2 | Out-Null; $ok=$true } catch { Start-Sleep -Milliseconds 500 } }; if (-not $ok) { exit 1 }"
if errorlevel 1 (
  echo The sign-in page did not start. Open the minimised "SEL Nexus CyberSuite sign-in" window to see why.
  pause
  exit /b 1
)

echo.
echo ---- Defender ^& Infrastructure
call "%SUITE%defender_infra\Start_Defender_Infra.cmd"

if exist "%SUITE%ApplicationVulnerabilities\Start_Application_Vulnerabilities.cmd" (
  echo.
  echo ---- Application Vulnerabilities
  call "%SUITE%ApplicationVulnerabilities\Start_Application_Vulnerabilities.cmd"
)

start "" http://127.0.0.1:8000
echo.
echo SEL Nexus CyberSuite is running. Sign in at http://127.0.0.1:8000
echo To stop it, double-click Stop_All.cmd
timeout /t 5 >nul
