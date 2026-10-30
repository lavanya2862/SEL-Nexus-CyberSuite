@echo off
title Infrastructure Security
rem Starts the Infrastructure Security module of SEL Nexus CyberSuite from this folder.
rem Normally called by ..\Start_All.cmd. Started on its own, it also starts the shared sign-in page (port 8000) if that
rem is not running yet, because people sign in there.
rem Any other copy already using the same ports (8800 dashboard, 8700 fixing, 8900 alert triage) is stopped first.
rem The first start sets things up by itself: a Python environment (.venv) per agent and the dashboard's website (web\dist).
rem Every agent reads the one suite .env at the repository root (copy .env.example) to show data.
rem Layout: agents\<agent>, dashboard (see docs\ARCHITECTURE.md).
set "DI=%~dp0"
cd /d "%DI%dashboard"
rem The Python that makes each .venv: the py launcher when there is one, because "python" can be the Microsoft Store shortcut
set "PY=python"
where py >nul 2>nul && set "PY=py -3"

rem Settings for every module live in the one suite .env; the first start makes it from .env.example
if not exist "%DI%..\.env" if exist "%DI%..\.env.example" (
  copy /y "%DI%..\.env.example" "%DI%..\.env" >nul
  echo Created .env from .env.example. Fill in your keys there, then start again to see data.
)

echo Stopping any other copy that is running...
powershell -NoProfile -Command "foreach ($p in 8800,8700,8900) { Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue } }"
timeout /t 2 /nobreak >nul

rem A copy pulled from git after the restructure still has its data in the old folders (git leaves them behind)
call :move_data Unified_Cyber_Portal dashboard
call :move_data UC1_Threat_Intel_Hunting_Agent agents\threat_intel
call :move_data UC3_MDE_Vuln_Extraction agents\vulnerability
call :move_data UC4_Alert_Triage_Agent agents\alert_triage

call :setup dashboard dashboard || goto :failed
call :setup agents\threat_intel threat_intel || goto :failed
call :setup agents\vulnerability vulnerability || goto :failed
call :setup agents\alert_triage alert_triage || goto :failed
call :setup agents\attack_detection attack_detection || goto :failed
rem Data from before the agents were renamed: each database file takes its agent's name
for %%a in ("threat_intel uc1" "vulnerability uc3" "alert_triage uc4") do call :rename_db %%~a
rem (Re)build the website when it is missing or older than its source files
powershell -NoProfile -Command "$d='web\dist\index.html'; if (-not (Test-Path $d)) { exit 1 }; $t=(Get-Item $d).LastWriteTime; if (Get-ChildItem web\src -Recurse -File | Where-Object { $_.LastWriteTime -gt $t } | Select-Object -First 1) { exit 1 }"
if errorlevel 1 (
  echo Building the Infrastructure Security website...
  pushd web
  if not exist node_modules call npm ci --no-audit --no-fund || (popd & goto :failed)
  call npm run build || (popd & goto :failed)
  popd
)

rem People sign in on the shared sign-in page; the dashboard checks the same session key (also settable in the suite .env).
if not defined PORTAL_LOGIN_URL set "PORTAL_LOGIN_URL=http://127.0.0.1:8000"
if not defined PORTAL_AUTH_DIR set "PORTAL_AUTH_DIR=..\..\login\data\auth"

echo Starting Infrastructure Security...
start "Infrastructure Security (keep open)" /min .venv\Scripts\python.exe -m dashboard serve --port 8800

powershell -NoProfile -Command "$ok=$false; for ($i=0; $i -lt 40 -and -not $ok; $i++) { try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8800/api/health -TimeoutSec 2 | Out-Null; $ok=$true } catch { Start-Sleep -Milliseconds 500 } }; if (-not $ok) { exit 1 }"
if errorlevel 1 (
  echo Infrastructure Security did not start. Open the minimised "Infrastructure Security" window to see why.
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
echo Infrastructure Security is running at http://127.0.0.1:8800 (sign in at http://127.0.0.1:8000)
echo To stop it, double-click Stop_Infrastructure_Security.cmd
if not "%CC_NO_BROWSER%"=="1" timeout /t 5 >nul
exit /b 0

rem ---- :move_data <old folder> <new folder>: its data and logs folders move once to the new folder
:move_data
if not exist "%DI%%~1" exit /b 0
for %%s in (data logs) do if exist "%DI%%~1\%%s" if not exist "%DI%%~2\%%s" (
  echo Moving %~1\%%s to %~2\%%s...
  move "%DI%%~1\%%s" "%DI%%~2\%%s" >nul
)
exit /b 0

rem ---- :rename_db <agent> <old name>: data\<old name>.duckdb becomes data\<agent>.duckdb
:rename_db
if exist "%DI%agents\%1\data\%2.duckdb" if not exist "%DI%agents\%1\data\%1.duckdb" ren "%DI%agents\%1\data\%2.duckdb" "%1.duckdb"
if exist "%DI%agents\%1\data\%2.duckdb.wal" if not exist "%DI%agents\%1\data\%1.duckdb.wal" ren "%DI%agents\%1\data\%2.duckdb.wal" "%1.duckdb.wal"
exit /b 0

rem ---- :setup <folder> <package>: its own .venv with the requirements, and the package's src folder and the shared
rem infra_core library on the path (.pth files, so it also works on Python 3.11)
:setup
if exist "%DI%%~1\.venv\Scripts\python.exe" if not exist "%DI%%~1\.venv\Lib\site-packages\infra_core.pth" (
  (echo %DI%shared\infra_core\src)>"%DI%%~1\.venv\Lib\site-packages\infra_core.pth"
)
if exist "%DI%%~1\.venv\Scripts\python.exe" exit /b 0
echo Setting up %~1, first time only...
%PY% -m venv "%DI%%~1\.venv" || exit /b 1
"%DI%%~1\.venv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check -r "%DI%%~1\requirements.txt" || exit /b 1
(echo %DI%%~1\src)>"%DI%%~1\.venv\Lib\site-packages\%~2.pth"
(echo %DI%shared\infra_core\src)>"%DI%%~1\.venv\Lib\site-packages\infra_core.pth"
exit /b 0

:failed
echo Setting up Infrastructure Security failed. See the messages above. It needs Python 3.11+ and Node.js 22+.
pause
exit /b 1
