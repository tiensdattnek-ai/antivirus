"""
SentinelX - cầu nối Python <-> engine C++ (ctypes).
Nếu không tìm thấy DLL/SO đã biên dịch, tự động fallback sang engine Python
thuần (chậm hơn nhưng vẫn đầy đủ tính năng) để phần mềm luôn chạy được.
"""
from __future__ import annotations

import ctypes
import hashlib
import math
import os
import queue
import re
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_BUNDLE = Path(getattr(sys, "_MEIPASS", ROOT))
_EXEDIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else ROOT
LIB_NAMES = ["sentinelx_core.dll", "libsentinelx_core.so", "libsentinelx_core.dylib"]


def _find_lib():
    for d in (_BUNDLE / "core", _BUNDLE, _EXEDIR / "core", _EXEDIR, ROOT / "core", ROOT, Path.cwd()):
        for n in LIB_NAMES:
            p = d / n
            if p.exists():
                return str(p)
    return None


class _Base:
    backend = "?"

    def add_hash_sig(self, sha, name): ...
    def add_pattern_sig(self, pat, is_ascii, name, sev): ...
    def add_whitelist(self, sha): ...
    def add_exclusion(self, path): ...
    def reset_signatures(self): ...
    def set_heuristics(self, on): ...
    def scan_start(self, roots, threads=0): ...
    def scan_stop(self): ...
    def is_running(self) -> bool: ...
    def stats(self): ...
    def next_result(self): ...
    def scan_one(self, path): ...


# ----------------------------------------------------------------- C++ backend
class NativeEngine(_Base):
    backend = "C++ native"

    def __init__(self, path):
        self.lib = ctypes.CDLL(path)
        L = self.lib
        L.sx_version.restype = ctypes.c_char_p
        L.sx_add_hash_sig.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        L.sx_add_whitelist.argtypes = [ctypes.c_char_p]
        L.sx_add_exclusion.argtypes = [ctypes.c_char_p]
        L.sx_is_excluded.argtypes = [ctypes.c_char_p]
        L.sx_add_pattern_sig.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        L.sx_set_heuristics.argtypes = [ctypes.c_int]
        L.sx_set_max_size.argtypes = [ctypes.c_longlong]
        L.sx_scan_start.argtypes = [ctypes.c_char_p, ctypes.c_int]
        L.sx_scanned.restype = ctypes.c_longlong
        L.sx_threats.restype = ctypes.c_longlong
        L.sx_bytes.restype = ctypes.c_longlong
        L.sx_next_result.argtypes = [ctypes.c_char_p, ctypes.c_int]
        L.sx_scan_one.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        L.sx_entropy_file.argtypes = [ctypes.c_char_p]
        L.sx_entropy_file.restype = ctypes.c_double
        self.version = L.sx_version().decode()

    def _b(self, s): return str(s).encode("utf-8", "surrogateescape")

    def reset_signatures(self): self.lib.sx_reset_signatures()
    def add_hash_sig(self, sha, name): self.lib.sx_add_hash_sig(self._b(sha), self._b(name))
    def add_whitelist(self, sha): self.lib.sx_add_whitelist(self._b(sha))
    def add_exclusion(self, path): self.lib.sx_add_exclusion(self._b(path))
    def clear_exclusions(self): self.lib.sx_clear_exclusions()
    def is_excluded(self, path): return bool(self.lib.sx_is_excluded(self._b(path)))
    def add_pattern_sig(self, pat, is_ascii, name, sev):
        self.lib.sx_add_pattern_sig(self._b(pat), 1 if is_ascii else 0, self._b(name), int(sev))
    def set_heuristics(self, on): self.lib.sx_set_heuristics(1 if on else 0)
    def set_max_size_mb(self, mb): self.lib.sx_set_max_size(int(mb))
    def scan_start(self, roots, threads=0):
        self.lib.sx_scan_start(self._b(";".join(str(r) for r in roots)), int(threads))
    def scan_stop(self): self.lib.sx_scan_stop()
    def is_running(self): return bool(self.lib.sx_is_running())
    def stats(self): return self.lib.sx_scanned(), self.lib.sx_threats(), self.lib.sx_bytes()

    def next_result(self):
        buf = ctypes.create_string_buffer(8192)
        if self.lib.sx_next_result(buf, 8192):
            return buf.value.decode("utf-8", "replace")
        return None

    def scan_one(self, path):
        buf = ctypes.create_string_buffer(8192)
        if self.lib.sx_scan_one(self._b(path), buf, 8192):
            return buf.value.decode("utf-8", "replace")
        return None

    def entropy(self, path): return self.lib.sx_entropy_file(self._b(path))


# -------------------------------------------------------------- Python backend
BAD_STRINGS = [
    (b"powershell -enc", 40), (b"FromBase64String", 25), (b"DownloadString", 30),
    (b"Invoke-Expression", 30), (b"vssadmin delete shadows", 60),
    (b"wbadmin delete catalog", 60), (b"Your files have been encrypted", 65),
    (b"CreateRemoteThread", 30), (b"VirtualAllocEx", 30), (b"WriteProcessMemory", 30),
    (b"SetWindowsHookEx", 25), (b"URLDownloadToFile", 35), (b"schtasks /create", 25),
    (b"eval(atob(", 35), (b"WScript.Shell", 20),
]


class PyEngine(_Base):
    backend = "Python fallback"
    version = "SentinelX Core 2.0 (pure Python)"

    def __init__(self):
        self.hash_sigs, self.pat_sigs, self.white = {}, [], set()
        self.exclusions = []
        self.heur = True
        self.max_size = 256 * 1024 * 1024
        self._q: "queue.Queue[str]" = queue.Queue()
        self._stop = threading.Event()
        self._running = False
        self._scanned = self._threats = self._bytes = 0

    def reset_signatures(self): self.hash_sigs.clear(); self.pat_sigs.clear(); self.white.clear()
    def add_hash_sig(self, sha, name): self.hash_sigs[sha.lower()] = name
    def add_whitelist(self, sha): self.white.add(sha.lower())
    def add_exclusion(self, path):
        self.exclusions.append(str(path).lower().rstrip("/\\"))
    def clear_exclusions(self): self.exclusions.clear()
    def is_excluded(self, path):
        p = str(path).lower()
        return any(p.startswith(e) for e in self.exclusions)
    def add_pattern_sig(self, pat, is_ascii, name, sev):
        raw = pat.encode() if is_ascii else bytes.fromhex(pat)
        self.pat_sigs.append((raw, name, sev))
    def set_heuristics(self, on): self.heur = bool(on)
    def set_max_size_mb(self, mb): self.max_size = int(mb) * 1024 * 1024
    def is_running(self): return self._running
    def stats(self): return self._scanned, self._threats, self._bytes
    def scan_stop(self): self._stop.set()

    def next_result(self):
        try: return self._q.get_nowait()
        except queue.Empty: return None

    @staticmethod
    def entropy(path_or_bytes):
        data = path_or_bytes if isinstance(path_or_bytes, bytes) else open(path_or_bytes, "rb").read(1 << 20)
        if not data: return 0.0
        f = [0] * 256
        for b in data: f[b] += 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in f if c)

    SRC_EXT = {".cpp",".cc",".c",".h",".hpp",".py",".pyw",".java",".cs",".go",".rs",
               ".json",".md",".txt",".log",".csv",".xml",".yml",".yaml",".ini",".cfg",
               ".toml",".rst",".html",".htm",".css",".ts",".sql",".spec",".iss"}

    def _check(self, path):
        if self.is_excluded(path):
            return None
        try:
            sz = os.path.getsize(path)
        except OSError:
            return None
        self._scanned += 1
        if sz == 0 or sz > self.max_size: return None
        try:
            data = open(path, "rb").read()
        except OSError:
            return None
        self._bytes += len(data)
        sha = hashlib.sha256(data).hexdigest()
        if sha in self.white: return None
        if sha in self.hash_sigs:
            return f"{path}|INFECTED|{self.hash_sigs[sha]}|100|{sha}"
        for raw, name, sev in self.pat_sigs:
            if raw in data:
                return f"{path}|INFECTED|{name}|{sev}|{sha}"
        if self.heur:
            score, why = 0, []
            low = data[:2 << 20].lower()
            ext = Path(path).suffix.lower()
            str_score = 0
            for s, w in BAD_STRINGS:
                if s.lower() in low: str_score += w; why.append(s.decode())
            if ext in self.SRC_EXT:      # mã nguồn / văn bản: hạ điểm mạnh
                str_score //= 4
            score += str_score
            if data[:2] == b"MZ" and self.entropy(data[:1 << 20]) > 7.2:
                score += 45; why.append("PE entropy cao")
            if ext in (".exe", ".scr", ".bat", ".com", ".pif") and re.search(r"\.(pdf|doc|jpg|txt)$", Path(path).stem, re.I):
                score += 55; why.append("double extension")
            if score >= 60: return f"{path}|INFECTED|Heuristic.Generic [{'; '.join(why)}]|{min(score,99)}|{sha}"
            if score >= 35: return f"{path}|SUSPICIOUS|Heuristic.Suspicious [{'; '.join(why)}]|{score}|{sha}"
        return None

    def scan_one(self, path): return self._check(path)

    def scan_start(self, roots, threads=0):
        if self._running: return
        self._stop.clear(); self._running = True
        self._scanned = self._threats = self._bytes = 0
        while not self._q.empty(): self._q.get_nowait()

        def run():
            for r in roots:
                for dp, dns, fns in os.walk(r):
                    if self._stop.is_set(): break
                    for fn in fns:
                        if self._stop.is_set(): break
                        res = self._check(os.path.join(dp, fn))
                        if res: self._threats += 1; self._q.put(res)
                if self._stop.is_set(): break
            self._running = False
            self._q.put("|DONE|||")
        threading.Thread(target=run, daemon=True).start()


def load_engine():
    p = _find_lib()
    if p:
        try:
            return NativeEngine(p)
        except Exception as e:  # pragma: no cover
            print("[SentinelX] Không nạp được core C++:", e, file=sys.stderr)
    return PyEngine()
