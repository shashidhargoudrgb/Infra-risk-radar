@echo off
cd /d "%~dp0frontend"
if not exist node_modules call npm install --no-audit --no-fund
npm run dev
