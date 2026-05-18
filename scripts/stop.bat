@echo off
chcp 65001 >nul
echo ════════════════════════════════════════
echo  SACA — Stopping Servers
echo ════════════════════════════════════════
echo.

echo Killing Node.js processes (backend + frontend)...
taskkill /F /IM node.exe 2>nul
taskkill /F /IM tsx.exe 2>nul

echo.
echo ✅ All SACA servers stopped.
pause
