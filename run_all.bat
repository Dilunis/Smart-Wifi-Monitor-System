@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM Fast one-click launcher. Optional: run_all.bat --install  (force pip/npm refresh)

set "DO_INSTALL=0"
if /I "%~1"=="--install" set "DO_INSTALL=1"
if /I "%~1"=="/install" set "DO_INSTALL=1"

echo ============================================================
echo   Smart WiFi Monitor - Instant Start
echo ============================================================
echo   Admin  - admin  / Admin@123
echo   Client - client / Client@123
echo   API    - http://127.0.0.1:5000
echo   UI     - http://127.0.0.1:3000
echo ============================================================
echo.

REM --- Python venv: create only if missing ---
if not exist "backend\.venv\Scripts\python.exe" (
  echo [setup] Creating backend\.venv ...
  python -m venv backend\.venv
  if errorlevel 1 (
    echo ERROR: Could not create venv. Is Python on PATH?
    pause
    exit /b 1
  )
  set "DO_INSTALL=1"
) else (
  echo [skip] backend\.venv already exists
)

REM --- pip: only on first setup or --install ---
if "%DO_INSTALL%"=="1" (
  echo [setup] pip install -r backend\requirements.txt ...
  backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt -q
  if errorlevel 1 (
    echo ERROR: pip install failed.
    pause
    exit /b 1
  )
) else (
  echo [skip] pip install ^(pass --install to refresh deps^)
)

REM --- npm: only if node_modules missing or --install ---
if "%DO_INSTALL%"=="1" goto :npm_install
if not exist "frontend\node_modules\" goto :npm_install
echo [skip] frontend\node_modules already exists
goto :launch

:npm_install
echo [setup] npm install in frontend ...
pushd frontend
call npm install --no-fund --no-audit
if errorlevel 1 (
  echo ERROR: npm install failed.
  popd
  pause
  exit /b 1
)
popd

:launch
echo.
echo [launch] Starting Flask + React in parallel...
start "SmartWiFi-Backend" /MIN cmd /c "cd /d "%~dp0backend" && .venv\Scripts\python.exe app.py"
start "SmartWiFi-Frontend" /MIN cmd /c "cd /d "%~dp0frontend" && set BROWSER=none&& set GENERATE_SOURCEMAP=false&& npm start"

echo.
echo Servers launching now ^(no wait^). Open http://127.0.0.1:3000 in a few seconds.
echo Tip: first CRA compile may take ~10-20s; later starts are faster.
echo Re-run with:  run_all.bat --install   if dependencies change.
echo.
exit /b 0
