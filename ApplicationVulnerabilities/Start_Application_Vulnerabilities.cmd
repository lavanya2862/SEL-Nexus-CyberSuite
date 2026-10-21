@echo off
title Application Vulnerabilities
rem Starts the Application Vulnerabilities module of SEL Nexus CyberSuite from this folder (http://127.0.0.1:8500).
rem Normally called by ..\Start_All.cmd. Started on its own, it also starts the shared sign-in page (port 8000) if that
rem is not running yet, because people sign in there.
rem The first start sets things up by itself: a Python environment (.venv) and the web app (web\dist). Later starts are quick.
cd /d "%~dp0"
rem The Python that makes the .venv: the py launcher when there is one, because "python" can be the Microsoft Store shortcut
set "PY=python"
where py >nul 2>nul && set "PY=py -3"

echo Stopping any other copy that is running...
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8500 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"

if not exist ".venv\Scripts\python.exe" (
  echo Setting up Python for Application Vulnerabilities, first time only...
  %PY% -m venv .venv || goto :failed
  ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt || goto :failed
)
if not exist "web\dist\index.html" (
  echo Building the web app, first time only...
  pushd web
  if not exist node_modules call npm ci --no-audit --no-fund || (popd & goto :failed)
  call npm run build || (popd & goto :failed)
  popd
)

rem Scan history and settings stay in this folder; sign-in is checked against the shared sign-in page's key.
set "DATA_DIR=%~dp0data"
set "SUITE_LOGIN_URL=http://127.0.0.1:8000"
set "SUITE_AUTH_DIR=%~dp0..\login\data\auth"

echo Starting Application Vulnerabilities...
start "Application Vulnerabilities (keep open)" /min .venv\Scripts\python.exe -m uvicorn remediation.api:app --host 127.0.0.1 --port 8500 --no-access-log

powershell -NoProfile -Command "$ok=$false; for ($i=0; $i -lt 60 -and -not $ok; $i++) { try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8500/health -TimeoutSec 2 | Out-Null; $ok=$true } catch { Start-Sleep -Milliseconds 500 } }; if (-not $ok) { exit 1 }"
if errorlevel 1 (
  echo Application Vulnerabilities did not start. Open the minimised "Application Vulnerabilities" window to see why.
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
echo Application Vulnerabilities is running at http://127.0.0.1:8500 (sign in at http://127.0.0.1:8000)
echo To stop it, double-click Stop_Application_Vulnerabilities.cmd
if not "%CC_NO_BROWSER%"=="1" timeout /t 5 >nul
exit /b 0

:failed
echo Setting up Application Vulnerabilities failed. See the messages above. It needs Python 3.11+ and Node.js 22+.
pause
exit /b 1
