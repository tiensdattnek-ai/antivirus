@echo off
cd /d "%~dp0"
if not exist core\sentinelx_core.dll ( echo [*] Dang build engine C++... & pushd core & call build.bat & popd )
python app\main.py
pause
