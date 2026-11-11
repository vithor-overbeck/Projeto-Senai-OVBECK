@echo off
chcp 65001 >nul
title Recuperar administrador - OVBECK
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0RECUPERAR_ADMIN.ps1"
echo.
if errorlevel 1 (
  echo A recuperacao nao foi concluida. Leia a mensagem acima.
) else (
  echo A recuperacao terminou. Voce ja pode iniciar a OVBECK.
)
echo.
pause
