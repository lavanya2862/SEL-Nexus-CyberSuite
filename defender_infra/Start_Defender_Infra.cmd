@echo off
title Defender ^& Infrastructure
rem Starts the Defender & Infrastructure module of SEL Nexus CyberSuite from this folder.
rem Normally called by ..\Start_All.cmd. Started on its own, it also starts the shared sign-in page (port 8000) if that
rem is not running yet, because people sign in there.
rem Any other copy already using the same ports (8800 portal, 8700 fixing, 8900 alert triage) is stopped first.
rem The first start sets things up by itself: a Python environment (.venv) per tool and the portal's website (web\dist).
rem Each tool still needs its own .env (copy config\settings.example.env) to show data.
set "DI=%~dp0"
cd /d "%DI%Unified_Cyber_Portal"

echo Stopping any other copy that is running...
powershell -NoProfile -Command "foreach ($p in 8800,8700,8900) { Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue } }"
timeout /t 2 /nobreak >nul

call :setup Unified_Cyber_Portal portal || goto :failed
call :setup UC1_Threat_Intel_Hunting_Agent uc1 || goto :failed
call :setup UC3_MDE_Vuln_Extraction uc3 || goto :failed
call :setup UC4_Alert_Triage_Agent uc4 || goto :failed
if not exist "web\dist\index.html" (
  echo Building the Defender ^& Infrastructure website, first time only...
  pushd web
  if not exist node_modules call npm ci --no-audit --no-fund || (popd & goto :failed)
  call npm run build || (popd & goto :failed)
  popd
)

rem People sign in on the shared sign-in page; the portal checks the same session key (also settable in config\portal.env).
if not defined PORTAL_LOGIN_URL set "PORTAL_LOGIN_URL=http://127.0.0.1:8000"
if not defined PORTAL_AUTH_DIR set "PORTAL_AUTH_DIR=..\..\login\data\auth"

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
if errorlevel 1 if exist "%DI%..\login\.venv\Scripts\python.exe" (
  echo Starting the SEL Nexus CyberSuite sign-in page...
  start "SEL Nexus CyberSuite sign-in (keep open)" /min /d "%DI%..\login" "%DI%..\login\.venv\Scripts\python.exe" server.py
)

if not "%CC_NO_BROWSER%"=="1" start "" http://127.0.0.1:8000
echo.
echo Defender ^& Infrastructure is running at http://127.0.0.1:8800 (sign in at http://127.0.0.1:8000)
echo To stop it, double-click Stop_Defender_Infra.cmd
if not "%CC_NO_BROWSER%"=="1" timeout /t 5 >nul
exit /b 0

rem ---- :setup <tool folder> <package>: its own .venv with the requirements, and the package's src folder on the path
rem (a .pth file, so it also works on Python 3.11)
:setup
if exist "%DI%%~1\.venv\Scripts\python.exe" exit /b 0
echo Setting up %~1, first time only...
python -m venv "%DI%%~1\.venv" || exit /b 1
"%DI%%~1\.venv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check -r "%DI%%~1\requirements.txt" || exit /b 1
(echo %DI%%~1\src)>"%DI%%~1\.venv\Lib\site-packages\%~2.pth"
exit /b 0

:failed
echo Setting up Defender ^& Infrastructure failed. See the messages above. It needs Python 3.11+ and Node.js 22+.
pause
exit /b 1
