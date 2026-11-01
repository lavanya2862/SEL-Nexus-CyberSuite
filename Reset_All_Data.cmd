@echo off
rem Clears all Infrastructure Security data (every agent's data and logs, the dashboard's run history) for a fresh start.
rem Removed items go to the Recycle Bin. Kept: settings (.env, config), sign-in accounts, the GUIDE practice dataset.
set "SUITE=%~dp0"
echo.
echo  This clears ALL Infrastructure Security data and logs (they go to the Recycle Bin).
echo  Kept: settings (.env, config), sign-in accounts and the GUIDE practice dataset.
echo  The suite is stopped first. Start it again with Start_All.cmd.
echo.
set "ANSWER="
set /p "ANSWER=Type YES to continue: "
if /i not "%ANSWER%"=="YES" (
  echo Cancelled. Nothing was changed.
  pause
  exit /b 1
)
call "%SUITE%Stop_All.cmd"
powershell -NoProfile -ExecutionPolicy Bypass -File "%SUITE%InfrastructureSecurity\Reset_Infrastructure_Data.ps1"
echo.
echo Next: double-click Start_All.cmd, then run the agents from the Agents page.
pause
