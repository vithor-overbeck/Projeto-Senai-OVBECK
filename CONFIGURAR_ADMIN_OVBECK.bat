@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js 22.16.0 ou mais recente nao foi encontrado.
  pause
  exit /b 1
)
node scripts/configure-local-admin.js
if errorlevel 1 (
  echo.
  echo Nao foi possivel configurar o administrador.
  pause
  exit /b 1
)
pause
endlocal
