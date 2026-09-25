@echo off
setlocal
cd /d "%~dp0"
echo Installing frontend dependencies...
cd frontend
call npm install --no-audit --no-fund
if errorlevel 1 goto fail
cd ..
if exist backend\package.json (
  echo Installing backend dependencies...
  cd backend
  call npm install --no-audit --no-fund
  if errorlevel 1 goto fail
)
cd ..
echo.
echo Setup complete. Run start-all.bat
pause
exit /b 0
:fail
echo.
echo Setup failed. Check Node.js 18+ and internet access.
pause
exit /b 1
