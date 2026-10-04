"""SentinelX - cập nhật CSDL chữ ký trực tuyến (từ GitHub) + tiện ích hệ thống."""
from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.request
from pathlib import Path

SIG_URL = ("https://raw.githubusercontent.com/tiensdattnek-ai/antivirus/main/data/signatures.json")
TIMEOUT = 15


def fetch_signatures(url: str = SIG_URL) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelX/2.1"})
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def update_signatures(local: Path, logger=None) -> tuple[bool, str]:
    remote = fetch_signatures()
    if not remote or "patterns" not in remote:
        return False, "Không kết nối được máy chủ cập nhật."
    try:
        cur = json.loads(Path(local).read_text(encoding="utf-8"))
    except Exception:
        cur = {"version": "0", "hashes": {}, "patterns": []}
    rv, cv = str(remote.get("version", "0")), str(cur.get("version", "0"))
    n_new = len(remote.get("patterns", [])) + len(remote.get("hashes", {}))
    n_old = len(cur.get("patterns", [])) + len(cur.get("hashes", {}))
    if rv <= cv and n_new <= n_old:
        return False, f"CSDL đã là mới nhất ({cv}, {n_old} chữ ký)."
    Path(local).write_text(json.dumps(remote, indent=2, ensure_ascii=False), encoding="utf-8")
    if logger: logger.info(f"Cập nhật CSDL chữ ký: {cv} -> {rv} ({n_new} chữ ký)")
    return True, f"Đã cập nhật {cv} → {rv} ({n_new} chữ ký)."


# --------------------------------------------------------------- Windows
def set_run_at_startup(enable: bool, exe_path: str | None = None) -> tuple[bool, str]:
    """Bật/tắt khởi động cùng Windows qua registry HKCU\\...\\Run."""
    if os.name != "nt":
        return False, "Chỉ hỗ trợ trên Windows."
    try:
        import winreg  # type: ignore
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                             winreg.KEY_SET_VALUE)
        if enable:
            target = exe_path or (sys.executable if getattr(sys, "frozen", False)
                                  else f'"{sys.executable}" "{Path(__file__).resolve().parent / "main.py"}"')
            winreg.SetValueEx(key, "SentinelX", 0, winreg.REG_SZ, f'"{target}"' if not target.startswith('"') else target)
            msg = "Đã bật khởi động cùng Windows."
        else:
            try: winreg.DeleteValue(key, "SentinelX")
            except FileNotFoundError: pass
            msg = "Đã tắt khởi động cùng Windows."
        winreg.CloseKey(key)
        return True, msg
    except Exception as e:
        return False, f"Lỗi registry: {e}"


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
