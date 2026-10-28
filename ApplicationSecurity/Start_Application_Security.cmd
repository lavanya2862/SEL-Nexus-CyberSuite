@echo off
title Application Security
rem Starts the Application Security module of SEL Nexus CyberSuite from this folder (http://127.0.0.1:8500).
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
  echo Setting up Python for Application Security, first time only...
  %PY% -m venv .venv || goto :failed
  ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt || goto :failed
  copy /y requirements.txt .venv\requirements.installed >nul
)
rem After an update: install the Python packages it added
fc /b requirements.txt .venv\requirements.installed >nul 2>nul || (
  echo Installing updated Python packages...
  ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt || goto :failed
  copy /y requirements.txt .venv\requirements.installed >nul
)
rem Optional scanners: scans still run without them. Semgrep gets its own environment because its packages clash with the app's.
if not exist ".venv\Scripts\bandit.exe" (
  echo Installing Bandit, first time only...
  ".venv\Scripts\python.exe" -m pip install --quiet bandit || echo Bandit could not be installed; scans run without it.
)
if not exist "tools\semgrep\Scripts\semgrep.exe" (
  echo Installing Semgrep in tools\semgrep, first time only...
  %PY% -m venv tools\semgrep && "tools\semgrep\Scripts\python.exe" -m pip install --quiet semgrep || echo Semgrep could not be installed; scans run without it.
)
rem The web app is built on the first start, and again whenever an update changed it (else the old pages stay)
set "WEB_BUILD=0"
if not exist "web\dist\index.html" set "WEB_BUILD=1"
if "%WEB_BUILD%"=="0" powershell -NoProfile -Command "$built = (Get-Item 'web\dist\index.html').LastWriteTime; if (Get-ChildItem 'web\src', 'web\public', 'web\index.html', 'web\package.json', 'web\package-lock.json', 'web\vite.config.ts' -Recurse -File | Where-Object { $_.LastWriteTime -gt $built } | Select-Object -First 1) { exit 1 }" || set "WEB_BUILD=1"
if "%WEB_BUILD%"=="1" (
  echo Building the web app...
  pushd web
  if not exist node_modules call npm ci --no-audit --no-fund || (popd & goto :failed)
  call npm run build || (popd & goto :failed)
  popd
)

rem Scan history and settings stay in this folder; sign-in is checked against the shared sign-in page's key.
set "DATA_DIR=%~dp0data"
set "SUITE_LOGIN_URL=http://127.0.0.1:8000"
set "SUITE_AUTH_DIR=%~dp0..\login\data\auth"
rem Each person's own GitHub token and AI key are encrypted with this key, kept apart from the data folder
set "CREDENTIALS_KEY_FILE=%~dp0secrets\credentials.key"

echo Starting Application Security...
start "Application Security (keep open)" /min .venv\Scripts\python.exe -m uvicorn remediation.api:app --host 127.0.0.1 --port 8500 --no-access-log

powershell -NoProfile -Command "$ok=$false; for ($i=0; $i -lt 60 -and -not $ok; $i++) { try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8500/health -TimeoutSec 2 | Out-Null; $ok=$true } catch { Start-Sleep -Milliseconds 500 } }; if (-not $ok) { exit 1 }"
if errorlevel 1 (
  echo Application Security did not start. Open the minimised "Application Security" window to see why.
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
echo Application Security is running at http://127.0.0.1:8500 (sign in at http://127.0.0.1:8000)
echo To stop it, double-click Stop_Application_Security.cmd
if not "%CC_NO_BROWSER%"=="1" timeout /t 5 >nul
exit /b 0

:failed
echo Setting up Application Security failed. See the messages above. It needs Python 3.11+ and Node.js 22+.
pause
exit /b 1
