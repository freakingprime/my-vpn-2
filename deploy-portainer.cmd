@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy-portainer.ps1" %*
pause
