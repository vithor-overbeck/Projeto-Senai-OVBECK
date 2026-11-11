@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title Iniciar OVBECK
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo Node.js 22.16.0 ou mais recente nao foi encontrado.
  echo Instale pelo site oficial: https://nodejs.org/
  echo Durante a instalacao, mantenha a opcao de adicionar ao PATH.
  echo Depois feche esta janela e execute este arquivo novamente.
  echo.
  start "" "https://nodejs.org/"
  pause
  exit /b 1
)
node "%~dp0scripts\configure-local-admin.js"
if errorlevel 1 (
  echo.
  echo A configuracao inicial do administrador nao foi concluida.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0iniciar.ps1"
if errorlevel 1 (
  echo.
  echo O OVBECK nao iniciou corretamente. Leia a mensagem acima.
  pause
  exit /b 1
)
endlocal
