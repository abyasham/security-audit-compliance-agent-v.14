@echo off
chcp 65001 >nul
echo ════════════════════════════════════════
echo  SACA — FULL RESET
echo ════════════════════════════════════════
echo.
echo  This will:
echo   1. Stop all SACA servers
echo   2. Delete ALL uploaded files (pcap, pdf, etc.)
echo   3. Delete ALL session data, findings, graphs
echo   4. Restart fresh
echo.
set /p CONFIRM="Type YES to confirm: "
if /I not "%CONFIRM%"=="YES" (
    echo Cancelled.
    pause
    exit /b
)

echo.
echo [1/4] Stopping servers...
taskkill /F /IM node.exe 2>nul
taskkill /F /IM tsx.exe 2>nul
timeout /t 2 /nobreak >nul

echo [2/4] Clearing uploads folder...
if exist "%~dp0..\backend\uploads" (
    rmdir /S /Q "%~dp0..\backend\uploads"
    mkdir "%~dp0..\backend\uploads"
    echo        ✓ Uploads cleared
) else (
    mkdir "%~dp0..\backend\uploads"
)

echo [3/4] Clearing data folder (sessions, graphs, findings)...
if exist "%~dp0..\backend\data" (
    rmdir /S /Q "%~dp0..\backend\data"
    mkdir "%~dp0..\backend\data"
    echo        ✓ Data cleared
) else (
    mkdir "%~dp0..\backend\data"
)

echo [4/4] Restarting servers...
start "SACA Backend" cmd /k "cd /d %~dp0..\backend && npx tsx src/index.ts"
timeout /t 3 /nobreak >nul
start "SACA Frontend" cmd /k "cd /d %~dp0..\frontend && npx vite --port 5173"

echo.
echo ════════════════════════════════════════
echo  ✅ SACA reset complete — fresh start!
echo  Backend:  http://localhost:3001
echo  Frontend: http://localhost:5173
echo ════════════════════════════════════════
pause
