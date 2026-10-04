# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — SentinelX Antivirus 2.0
Build:  pyinstaller --clean -y sentinelx.spec
Kết quả: dist/SentinelX.exe  (một file duy nhất, có icon, yêu cầu quyền Admin)
"""
import os, sys
from pathlib import Path

ROOT = Path(os.path.abspath(SPECPATH))
IS_WIN = sys.platform.startswith("win")

# ---- tài nguyên đóng gói kèm -------------------------------------------------
datas = [(str(ROOT / "data" / "signatures.json"), "data")]
binaries = []
for lib in ("core/sentinelx_core.dll", "core/libsentinelx_core.so", "core/libsentinelx_core.dylib"):
    p = ROOT / lib
    if p.exists():
        binaries.append((str(p), "core"))

icon = str(ROOT / "assets" / "sentinelx.ico")
if not Path(icon).exists():
    icon = None

a = Analysis(
    [str(ROOT / "app" / "main.py")],
    pathex=[str(ROOT / "app")],
    binaries=binaries,
    datas=datas,
    hiddenimports=["core_services", "engine_bridge", "tkinter", "tkinter.ttk",
                   "tkinter.filedialog", "tkinter.messagebox"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["numpy", "matplotlib", "pandas", "PIL", "scipy", "pytest",
              "PyQt5", "PySide6", "setuptools", "pip"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="SentinelX",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,                     # nén UPX nếu có sẵn
    upx_exclude=["vcruntime140.dll", "python3*.dll"],
    runtime_tmpdir=None,
    console=False,                # ứng dụng GUI, không hiện cửa sổ đen
    disable_windowed_traceback=False,
    icon=icon,
    uac_admin=True,               # tự xin quyền Administrator (cần để xoá malware)
    version=str(ROOT / "version_info.txt") if IS_WIN and (ROOT / "version_info.txt").exists() else None,
)
