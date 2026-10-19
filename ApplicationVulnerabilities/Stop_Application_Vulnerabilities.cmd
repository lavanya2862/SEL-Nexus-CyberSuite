@echo off
rem Stops the Application Vulnerabilities module (port 8500).
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8500 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"
echo Application Vulnerabilities is stopped.
if not "%CC_NO_BROWSER%"=="1" timeout /t 3 >nul
