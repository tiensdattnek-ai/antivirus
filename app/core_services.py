"""
SentinelX - các dịch vụ lõi phía Python:
  * Config      : cấu hình JSON có lưu đĩa
  * Logger      : ghi log xoay vòng
  * Quarantine  : cách ly file (mã hoá XOR + metadata, có thể phục hồi)
  * Remediator  : xử lý mối đe doạ (xoá vĩnh viễn / cách ly)
  * RealtimeGuard : giám sát thời gian thực (watchdog nếu có, không thì polling)
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path

import sys as _sys

FROZEN = getattr(_sys, "frozen", False)
# BUNDLE = nơi chứa tài nguyên chỉ-đọc đóng gói kèm (signatures, core dll)
BUNDLE = Path(getattr(_sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
# ROOT = nơi ghi dữ liệu (cạnh file .exe khi đã đóng gói)
ROOT = Path(_sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
QDIR = ROOT / "quarantine"
LOGDIR = ROOT / "logs"
for d in (DATA, QDIR, LOGDIR):
    d.mkdir(parents=True, exist_ok=True)

# Lần chạy đầu sau khi đóng gói: sao chép CSDL chữ ký ra thư mục ghi được
_sig = DATA / "signatures.json"
if not _sig.exists():
    _src = BUNDLE / "data" / "signatures.json"
    if _src.exists():
        import shutil as _sh
        _sh.copy2(_src, _sig)

DEFAULTS = {
    "auto_delete": True,              # tự động xử lý ngay khi phát hiện
    "action": "quarantine",           # quarantine | delete
    "realtime": True,
    "heuristics": True,
    "scan_archives": False,
    "threads": 0,                     # 0 = auto
    "max_file_mb": 256,
    "watch_paths": [],                # mặc định sẽ tự điền khi khởi động
    "exclusions": [],
    "theme": "dark",
    "sound": True,
    "schedule_enabled": False,
    "schedule_time": "02:00",
}


class Config(dict):
    path = DATA / "config.json"

    def __init__(self):
        super().__init__(DEFAULTS)
        if self.path.exists():
            try:
                self.update(json.loads(self.path.read_text(encoding="utf-8")))
            except Exception:
                pass
        if not self["watch_paths"]:
            home = Path.home()
            cands = [home / "Downloads", home / "Desktop", home / "Documents",
                     Path(os.environ.get("TEMP", "/tmp"))]
            self["watch_paths"] = [str(c) for c in cands if c.exists()]
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self, indent=2, ensure_ascii=False), encoding="utf-8")


class Logger:
    def __init__(self, name="sentinelx"):
        self.file = LOGDIR / f"{name}.log"
        self.lock = threading.Lock()
        self.listeners = []

    def log(self, level, msg):
        line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [{level:<7}] {msg}"
        with self.lock:
            try:
                if self.file.exists() and self.file.stat().st_size > 4_000_000:
                    self.file.rename(self.file.with_suffix(".log.1"))
                with self.file.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass
        for cb in list(self.listeners):
            try: cb(level, msg)
            except Exception: pass
        return line

    info = lambda self, m: self.log("INFO", m)
    warn = lambda self, m: self.log("WARN", m)
    err = lambda self, m: self.log("ERROR", m)
    threat = lambda self, m: self.log("THREAT", m)


class Quarantine:
    """File bị cách ly được XOR bằng key ngẫu nhiên -> vô hại, vẫn phục hồi được."""
    index_path = QDIR / "index.json"

    def __init__(self, logger: Logger):
        self.log = logger
        self.index = {}
        if self.index_path.exists():
            try: self.index = json.loads(self.index_path.read_text(encoding="utf-8"))
            except Exception: self.index = {}

    def _save(self):
        self.index_path.write_text(json.dumps(self.index, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        kl = len(key)
        return bytes(b ^ key[i % kl] for i, b in enumerate(data))

    def add(self, path: str, threat_name: str, sha: str = "") -> str | None:
        p = Path(path)
        try:
            data = p.read_bytes()
        except OSError as e:
            self.log.err(f"Không đọc được {path}: {e}")
            return None
        key = secrets.token_bytes(32)
        qid = f"{int(time.time()*1000)}_{secrets.token_hex(4)}"
        qfile = QDIR / f"{qid}.sxq"
        try:
            qfile.write_bytes(self._xor(data, key))
            os.remove(p)
        except OSError as e:
            self.log.err(f"Cách ly thất bại {path}: {e}")
            qfile.unlink(missing_ok=True)
            return None
        self.index[qid] = {
            "original": str(p), "threat": threat_name, "sha256": sha,
            "size": len(data), "key": key.hex(),
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._save()
        self.log.threat(f"ĐÃ CÁCH LY: {p.name}  ({threat_name})")
        return qid

    def restore(self, qid) -> bool:
        m = self.index.get(qid)
        if not m: return False
        qfile = QDIR / f"{qid}.sxq"
        try:
            data = self._xor(qfile.read_bytes(), bytes.fromhex(m["key"]))
            dst = Path(m["original"])
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            qfile.unlink(missing_ok=True)
        except OSError as e:
            self.log.err(f"Phục hồi thất bại: {e}")
            return False
        del self.index[qid]; self._save()
        self.log.warn(f"ĐÃ PHỤC HỒI: {m['original']}")
        return True

    def delete(self, qid) -> bool:
        if qid not in self.index: return False
        (QDIR / f"{qid}.sxq").unlink(missing_ok=True)
        m = self.index.pop(qid); self._save()
        self.log.info(f"Đã xoá vĩnh viễn khỏi khu cách ly: {m['original']}")
        return True

    def empty(self):
        for qid in list(self.index): self.delete(qid)


class Remediator:
    def __init__(self, cfg: Config, q: Quarantine, logger: Logger):
        self.cfg, self.q, self.log = cfg, q, logger

    def handle(self, path, threat, sha="") -> str:
        """Trả về hành động đã thực hiện: deleted | quarantined | failed | skipped"""
        if any(str(path).lower().startswith(str(e).lower()) for e in self.cfg["exclusions"]):
            return "skipped"
        if self.cfg["action"] == "delete":
            try:
                # ghi đè 1 lượt trước khi xoá để chống khôi phục
                size = os.path.getsize(path)
                with open(path, "r+b") as f:
                    f.write(secrets.token_bytes(min(size, 1 << 20)))
                os.remove(path)
                self.log.threat(f"ĐÃ XOÁ NGAY: {path}  ({threat})")
                return "deleted"
            except OSError as e:
                self.log.err(f"Xoá thất bại {path}: {e}")
                return "failed"
        return "quarantined" if self.q.add(path, threat, sha) else "failed"


class RealtimeGuard:
    """Giám sát thời gian thực. Dùng watchdog nếu đã cài, nếu không thì quét
    theo chu kỳ dựa trên mtime (không cần cài thêm thư viện)."""

    def __init__(self, engine, cfg: Config, rem: Remediator, logger: Logger, on_event=None):
        self.engine, self.cfg, self.rem, self.log = engine, cfg, rem, logger
        self.on_event = on_event or (lambda *a: None)
        self._stop = threading.Event()
        self._thread = None
        self._seen = {}
        self.active = False
        self.checked = 0
        self.blocked = 0

    def start(self):
        if self.active: return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.active = True
        self.log.info("Bảo vệ thời gian thực: BẬT  (" + ", ".join(self.cfg["watch_paths"]) + ")")

    def stop(self):
        self._stop.set(); self.active = False
        self.log.warn("Bảo vệ thời gian thực: TẮT")

    def _inspect(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return
        key = str(path)
        sig = (st.st_mtime_ns, st.st_size)
        if self._seen.get(key) == sig:
            return
        self._seen[key] = sig
        if st.st_size == 0 or st.st_size > self.cfg["max_file_mb"] * 1024 * 1024:
            return
        res = self.engine.scan_one(path)
        self.checked += 1
        if res:
            p, verdict, name, sev, sha = (res.split("|") + ["", "", "", "", ""])[:5]
            self.on_event("detect", {"path": p, "verdict": verdict, "name": name,
                                     "severity": sev, "sha": sha, "source": "realtime"})
            if self.cfg["auto_delete"] and verdict == "INFECTED":
                act = self.rem.handle(p, name, sha)
                self.blocked += 1
                self.on_event("action", {"path": p, "action": act, "name": name})

    def _loop(self):
        # nạp trạng thái ban đầu để không báo động toàn bộ file cũ
        first = True
        while not self._stop.is_set():
            for root in self.cfg["watch_paths"]:
                if self._stop.is_set(): break
                for dp, dns, fns in os.walk(root):
                    dns[:] = [d for d in dns if not d.startswith(".")]
                    if self._stop.is_set(): break
                    for fn in fns:
                        fp = os.path.join(dp, fn)
                        if first:
                            try: self._seen[fp] = (os.stat(fp).st_mtime_ns, os.stat(fp).st_size)
                            except OSError: pass
                        else:
                            self._inspect(fp)
            first = False
            self._stop.wait(2.0)
