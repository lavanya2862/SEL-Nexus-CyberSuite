@echo off
rem Stops the whole SEL Nexus CyberSuite: the shared sign-in page and every module.
set "SUITE=%~dp0"
set CC_NO_BROWSER=1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"
echo The sign-in page is stopped.
call "%SUITE%defender_infra\Stop_Defender_Infra.cmd"
if exist "%SUITE%code_vulnerabilities\Stop_Code_Vulnerabilities.cmd" call "%SUITE%code_vulnerabilities\Stop_Code_Vulnerabilities.cmd"
echo SEL Nexus CyberSuite is stopped.
timeout /t 3 >nul
