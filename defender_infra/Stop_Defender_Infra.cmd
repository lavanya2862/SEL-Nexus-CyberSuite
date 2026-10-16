@echo off
rem Stops the Defender & Infrastructure module and its two background services (ports 8800, 8700, 8900).
powershell -NoProfile -Command "foreach ($p in 8800,8700,8900) { Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue } }"
echo Defender ^& Infrastructure is stopped.
if not "%CC_NO_BROWSER%"=="1" timeout /t 3 >nul
