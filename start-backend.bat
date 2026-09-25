@echo off
cd /d "%~dp0backend"
if not exist node_modules call npm install --no-audit --no-fund
npm start
