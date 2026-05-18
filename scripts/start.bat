@echo off
chcp 65001 >nul
echo ════════════════════════════════════════
echo  SACA — Starting Servers
echo ════════════════════════════════════════
echo.

:: Start backend in a new window
echo [1/2] Starting Backend on http://localhost:3001 ...
start "SACA Backend" cmd /k "cd /d %~dp0..\backend && echo [Backend] Starting... && npx tsx src/index.ts"

:: Wait a bit for backend to init
timeout /t 3 /nobreak >nul

:: Start frontend dev server in a new window
echo [2/2] Starting Frontend dev server ...
start "SACA Frontend" cmd /k "cd /d %~dp0..\frontend && echo [Frontend] Starting... && npx vite --port 5173"

echo.
echo ✅ Both servers started!
echo    Backend:  http://localhost:3001
echo    Frontend: http://localhost:5173
echo.
echo    Close the terminal windows to stop, or run scripts\stop.bat
pause
