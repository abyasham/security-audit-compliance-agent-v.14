@echo off
cd /d %~dp0..
echo This will stop all servers, clear all data, and restart fresh.
echo.
set /p CONFIRM="Type YES to confirm: "
if /I not "%CONFIRM%"=="YES" (
    echo Cancelled.
    pause
    exit /b
)
node scripts\reset.js
pause
