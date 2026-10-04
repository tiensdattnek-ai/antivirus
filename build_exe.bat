@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ==========================================================
echo   SentinelX Antivirus 2.0  -  DONG GOI THANH FILE .EXE
echo ==========================================================

echo [1/4] Build engine C++ (sentinelx_core.dll)...
pushd core
call build.bat
popd

echo [2/4] Cai dat PyInstaller neu thieu...
python -m pip install --upgrade pyinstaller >nul 2>nul

echo [3/4] Dong goi...
python -m PyInstaller --clean -y sentinelx.spec
if errorlevel 1 ( echo [!] Dong goi that bai. & pause & exit /b 1 )

echo [4/4] Hoan tat!
if exist dist\SentinelX.exe (
  echo [+] File: %cd%\dist\SentinelX.exe
  for %%A in (dist\SentinelX.exe) do echo [+] Kich thuoc: %%~zA bytes
) else ( echo [!] Khong thay dist\SentinelX.exe )
pause
