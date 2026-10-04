@echo off
REM ====== Build SentinelX Core (Windows) ======
REM Cach 1: MinGW-w64 (g++)
where g++ >nul 2>nul && (
  echo [*] Building with MinGW g++ ...
  g++ -O3 -std=c++17 -shared -static -static-libgcc -static-libstdc++ engine.cpp -o sentinelx_core.dll
  if exist sentinelx_core.dll echo [+] OK: sentinelx_core.dll & exit /b 0
)
REM Cach 2: MSVC (chay trong "x64 Native Tools Command Prompt")
where cl >nul 2>nul && (
  echo [*] Building with MSVC ...
  cl /LD /O2 /EHsc /std:c++17 engine.cpp /Fe:sentinelx_core.dll
  if exist sentinelx_core.dll echo [+] OK: sentinelx_core.dll & exit /b 0
)
echo [!] Khong tim thay g++ hoac cl. Cai MinGW-w64 hoac Visual Studio Build Tools.
echo [i] Bo qua cung duoc: app se tu dong dung engine Python fallback.
