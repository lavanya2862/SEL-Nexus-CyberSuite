@echo off
rem Stops the whole SEL Nexus CyberSuite: the shared sign-in page and every module.
set "SUITE=%~dp0"
set CC_NO_BROWSER=1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"
echo The sign-in page is stopped.
call "%SUITE%InfrastructureSecurity\Stop_Infrastructure_Security.cmd"
if exist "%SUITE%ApplicationSecurity\Stop_Application_Security.cmd" call "%SUITE%ApplicationSecurity\Stop_Application_Security.cmd"
echo SEL Nexus CyberSuite is stopped.
timeout /t 3 >nul
