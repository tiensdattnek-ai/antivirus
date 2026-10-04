"""
SentinelX - SIÊU BẢO MẬT APP (Application Lock)
================================================
Người dùng chọn các ứng dụng cần bảo vệ. Mỗi khi ứng dụng đó được mở:
  1. SentinelX phát hiện tiến trình mới -> kết thúc tiến trình ngay lập tức
  2. Bật cửa sổ yêu cầu nhập mật khẩu (SentinelX tự nổi lên trước)
  3. Nhập ĐÚNG  -> ứng dụng được khởi chạy lại bình thường
     Nhập SAI   -> KHOÁ ứng dụng đó trong 3 phút, mọi lần mở đều bị chặn

Mật khẩu được băm bằng PBKDF2-HMAC-SHA256 (200k vòng, salt ngẫu nhiên 16 byte)
-> không bao giờ lưu dạng rõ.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

IS_WIN = os.name == "nt"
PENALTY_SECONDS = 180          # khoá 3 phút khi nhập sai
GRACE_SECONDS = 25             # sau khi mở khoá, cho phép app chạy không bị hỏi lại
POLL_INTERVAL = 0.8


# --------------------------------------------------------------- mật khẩu
def hash_password(pw: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200_000)
    return {"salt": base64.b64encode(salt).decode(),
            "hash": base64.b64encode(dk).decode(),
            "algo": "pbkdf2_sha256_200k"}


def verify_password(pw: str, rec: dict) -> bool:
    if not rec: return False
    try:
        salt = base64.b64decode(rec["salt"])
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200_000)
        return secrets.compare_digest(base64.b64encode(dk).decode(), rec["hash"])
    except Exception:
        return False


# --------------------------------------------------------------- tiến trình
def list_processes() -> dict[int, str]:
    """Trả về {pid: tên tiến trình (chữ thường)}."""
    out: dict[int, str] = {}
    if IS_WIN:
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            raw = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"],
                                          startupinfo=si, text=True,
                                          errors="ignore", timeout=10)
            for line in raw.splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    try: out[int(parts[1])] = parts[0].lower()
                    except ValueError: pass
        except Exception:
            pass
    else:  # Linux/macOS – dùng cho phát triển & kiểm thử
        for d in Path("/proc").iterdir() if Path("/proc").exists() else []:
            if d.name.isdigit():
                try: out[int(d.name)] = (d / "comm").read_text().strip().lower()
                except OSError: pass
    return out


def kill_pid(pid: int) -> bool:
    try:
        if IS_WIN:
            si = subprocess.STARTUPINFO(); si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           startupinfo=si, capture_output=True, timeout=10)
        else:
            os.kill(pid, 9)
        return True
    except Exception:
        return False


def launch(path: str) -> bool:
    try:
        if IS_WIN:
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            subprocess.Popen([path], start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


# --------------------------------------------------------------- quản lý
class AppLockManager:
    """
    Cấu trúc data/applock.json:
      {
        "password": {...pbkdf2...},
        "apps": { "notepad.exe": {"path": "C:\\Windows\\notepad.exe",
                                  "label": "Notepad", "added": "..."} },
        "enabled": true
      }
    """

    def __init__(self, data_dir: Path, logger, prompt_cb, notify_cb=None):
        self.file = Path(data_dir) / "applock.json"
        self.log = logger
        self.prompt_cb = prompt_cb        # gọi về GUI để hiện hộp nhập mật khẩu
        self.notify_cb = notify_cb or (lambda *a, **k: None)
        self.db = {"password": None, "apps": {}, "enabled": False}
        if self.file.exists():
            try: self.db.update(json.loads(self.file.read_text(encoding="utf-8")))
            except Exception: pass
        self.locked_until: dict[str, float] = {}   # app -> hết hạn phạt
        self.granted_until: dict[str, float] = {}  # app -> hết hạn ân hạn
        self.pending: set[str] = set()             # đang hiện hộp mật khẩu
        self._known: set[int] = set()
        self._stop = threading.Event()
        self._thread = None
        self.active = False
        self.blocked_count = 0
        self.unlocked_count = 0

    # ---------------------------------------------------------- lưu trữ
    def save(self):
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.file.write_text(json.dumps(self.db, indent=2, ensure_ascii=False), encoding="utf-8")

    @property
    def has_password(self) -> bool:
        return bool(self.db.get("password"))

    def set_password(self, new_pw: str, old_pw: str | None = None) -> tuple[bool, str]:
        if self.has_password and not verify_password(old_pw or "", self.db["password"]):
            return False, "Mật khẩu hiện tại không đúng."
        if len(new_pw) < 4:
            return False, "Mật khẩu phải có ít nhất 4 ký tự."
        self.db["password"] = hash_password(new_pw)
        self.save()
        self.log.info("Đã đặt/đổi mật khẩu Siêu bảo mật App")
        return True, "Đã lưu mật khẩu."

    def check(self, pw: str) -> bool:
        return verify_password(pw, self.db.get("password"))

    # ---------------------------------------------------------- danh sách app
    def add_app(self, path: str, label: str = "") -> tuple[bool, str]:
        p = Path(path)
        if not p.exists():
            return False, "Không tìm thấy tệp thực thi."
        key = p.name.lower()
        self.db["apps"][key] = {"path": str(p), "label": label or p.stem,
                                "added": time.strftime("%Y-%m-%d %H:%M:%S")}
        self.save()
        self.log.info(f"Siêu bảo mật: đã thêm {key}")
        return True, f"Đã bảo vệ {p.name}"

    def remove_app(self, key: str):
        if self.db["apps"].pop(key, None):
            self.locked_until.pop(key, None); self.granted_until.pop(key, None)
            self.save(); self.log.warn(f"Siêu bảo mật: đã gỡ bảo vệ {key}")

    def apps(self) -> dict:
        return self.db["apps"]

    def status_of(self, key: str) -> str:
        now = time.time()
        if self.locked_until.get(key, 0) > now:
            return f"■ BỊ KHOÁ còn {int(self.locked_until[key]-now)}s"
        if self.granted_until.get(key, 0) > now:
            return "✔ Đang mở khoá"
        return "● Đang bảo vệ"

    # ---------------------------------------------------------- giám sát
    def start(self):
        if self.active: return
        if not self.has_password:
            self.log.warn("Siêu bảo mật: chưa đặt mật khẩu — không thể bật")
            return
        self._stop.clear()
        self._known = set(list_processes().keys())
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.active = True
        self.db["enabled"] = True; self.save()
        self.log.info(f"Siêu bảo mật App: BẬT ({len(self.db['apps'])} ứng dụng)")

    def stop(self):
        self._stop.set(); self.active = False
        self.db["enabled"] = False; self.save()
        self.log.warn("Siêu bảo mật App: TẮT")

    def _loop(self):
        while not self._stop.is_set():
            try:
                procs = list_processes()
                now = time.time()
                for pid, name in procs.items():
                    if pid in self._known:
                        continue
                    app = self.db["apps"].get(name)
                    if not app:
                        continue
                    # Tiến trình MỚI của ứng dụng được bảo vệ
                    if self.granted_until.get(name, 0) > now:
                        continue                                   # đang trong thời gian ân hạn
                    kill_pid(pid)
                    if self.locked_until.get(name, 0) > now:
                        self.blocked_count += 1
                        remain = int(self.locked_until[name] - now)
                        self.log.threat(f"Siêu bảo mật: CHẶN {name} — còn bị khoá {remain}s")
                        self.notify_cb("locked", {"app": name, "remain": remain})
                        continue
                    if name in self.pending:
                        continue
                    self.pending.add(name)
                    self.blocked_count += 1
                    self.log.warn(f"Siêu bảo mật: chặn {name}, yêu cầu mật khẩu")
                    self.prompt_cb(name, app)                      # GUI sẽ gọi resolve()
                self._known = set(procs.keys())
            except Exception as e:
                self.log.err(f"AppLock loop: {e}")
            self._stop.wait(POLL_INTERVAL)

    # ---------------------------------------------------------- kết quả nhập mật khẩu
    def resolve(self, name: str, ok: bool):
        """GUI gọi lại sau khi người dùng nhập mật khẩu."""
        self.pending.discard(name)
        app = self.db["apps"].get(name)
        if ok:
            self.granted_until[name] = time.time() + GRACE_SECONDS
            self.locked_until.pop(name, None)
            self.unlocked_count += 1
            self.log.info(f"Siêu bảo mật: mở khoá {name} — đang khởi chạy lại")
            if app: launch(app["path"])
            self.notify_cb("unlocked", {"app": name})
        else:
            self.locked_until[name] = time.time() + PENALTY_SECONDS
            self.log.threat(f"Siêu bảo mật: SAI MẬT KHẨU — khoá {name} trong {PENALTY_SECONDS//60} phút")
            self.notify_cb("penalty", {"app": name, "seconds": PENALTY_SECONDS})

    def unlock_now(self, key: str):
        self.locked_until.pop(key, None)
