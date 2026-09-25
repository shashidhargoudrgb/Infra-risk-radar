@echo off
set ROOT=%~dp0
start "Infra Risk Radar Backend" cmd /k "cd /d "%ROOT%backend" && if not exist node_modules npm install --no-audit --no-fund && npm start"
:wait
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing http://localhost:5000/api/health -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }"
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto wait
)
start "Infra Risk Radar Frontend" cmd /k "cd /d "%ROOT%frontend" && if not exist node_modules npm install --no-audit --no-fund && npm run dev"
timeout /t 5 /nobreak >nul
start http://localhost:3000/map
