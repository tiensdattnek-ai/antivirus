#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗  ██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚██╗██╔╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      ╚███╔╝
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ██╔██╗
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╔╝ ██╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
   SentinelX Antivirus 2.0  -  Engine C++ + Giao diện Python (Tkinter)
   Chạy:  python app/main.py
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core_services import Config, Logger, Quarantine, RealtimeGuard, Remediator, ROOT, DATA  # noqa
from engine_bridge import load_engine  # noqa

# ----------------------------------------------------------------- Bảng màu
C = {
    "bg":        "#0b0f17",
    "bg2":       "#111726",
    "card":      "#151d2e",
    "card2":     "#1b2437",
    "stroke":    "#243049",
    "txt":       "#e8edf7",
    "muted":     "#8a97b1",
    "accent":    "#00e5a0",
    "accent2":   "#17b0ff",
    "danger":    "#ff4d6d",
    "warn":      "#ffb020",
    "purple":    "#8b5cf6",
}
F = lambda s=11, w="normal": ("Segoe UI" if os.name == "nt" else "DejaVu Sans", s, w)


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024: return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


# ----------------------------------------------------------------- Widgets
class Card(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=C["card"], highlightbackground=C["stroke"],
                         highlightthickness=1, bd=0, **kw)


class GlowButton(tk.Canvas):
    """Nút bo góc tự vẽ, có hiệu ứng hover."""
    def __init__(self, master, text, command=None, w=170, h=42, fill=C["accent"],
                 fg="#04121c", icon="", radius=12, outline=None):
        super().__init__(master, width=w, height=h, bg=master["bg"], highlightthickness=0, bd=0)
        self.cmd, self.w, self.h, self.r = command, w, h, radius
        self.fill, self.fg, self.outline = fill, fg, outline
        self.text, self.icon = text, icon
        self._draw(fill)
        self.bind("<Enter>", lambda e: (self._draw(self._lighten(self.fill)), self.config(cursor="hand2")))
        self.bind("<Leave>", lambda e: self._draw(self.fill))
        self.bind("<Button-1>", lambda e: self.cmd and self.cmd())

    @staticmethod
    def _lighten(hx, k=0.18):
        hx = hx.lstrip("#"); r, g, b = (int(hx[i:i+2], 16) for i in (0, 2, 4))
        f = lambda v: int(v + (255 - v) * k)
        return f"#{f(r):02x}{f(g):02x}{f(b):02x}"

    def _round(self, x1, y1, x2, y2, r, **kw):
        pts = [x1+r,y1, x2-r,y1, x2,y1, x2,y1+r, x2,y2-r, x2,y2, x2-r,y2,
               x1+r,y2, x1,y2, x1,y2-r, x1,y1+r, x1,y1]
        return self.create_polygon(pts, smooth=True, **kw)

    def _draw(self, fill):
        self.delete("all")
        self._round(1, 1, self.w-1, self.h-1, self.r, fill=fill,
                    outline=self.outline or fill, width=1.5)
        label = (self.icon + "  " if self.icon else "") + self.text
        self.create_text(self.w/2, self.h/2, text=label, fill=self.fg, font=F(11, "bold"))

    def set_state(self, fill=None, text=None):
        if fill: self.fill = fill
        if text: self.text = text
        self._draw(self.fill)


class Gauge(tk.Canvas):
    """Vòng tròn tiến trình + trạng thái bảo vệ."""
    def __init__(self, master, size=230):
        super().__init__(master, width=size, height=size, bg=C["card"], highlightthickness=0)
        self.size = size
        self.pct = 0.0
        self.title = "ĐANG BẢO VỆ"
        self.sub = "Hệ thống an toàn"
        self.color = C["accent"]
        self._spin = 0
        self.scanning = False
        self.draw()

    def draw(self):
        self.delete("all")
        s = self.size; pad = 18; r = s - pad
        self.create_oval(pad, pad, r, r, outline=C["card2"], width=14)
        if self.scanning:
            ext = 90
            self.create_arc(pad, pad, r, r, start=self._spin, extent=ext, style="arc",
                            outline=self.color, width=14)
            self.create_arc(pad, pad, r, r, start=self._spin + 180, extent=ext // 2, style="arc",
                            outline=C["accent2"], width=14)
        else:
            self.create_arc(pad, pad, r, r, start=90, extent=-359.9 * max(self.pct, 0.001),
                            style="arc", outline=self.color, width=14)
        self.create_text(s/2, s/2 - 14, text=self.title, fill=C["txt"], font=F(14, "bold"))
        self.create_text(s/2, s/2 + 12, text=self.sub, fill=C["muted"], font=F(10))
        self.create_oval(pad+22, pad+22, r-22, r-22, outline=C["stroke"], width=1)

    def tick(self):
        if self.scanning:
            self._spin = (self._spin - 7) % 360
            self.draw()


class Stat(Card):
    def __init__(self, master, label, value="0", color=C["accent"], icon="●"):
        super().__init__(master)
        tk.Label(self, text=icon, bg=C["card"], fg=color, font=F(16, "bold")).pack(anchor="w", padx=16, pady=(12, 0))
        self.v = tk.Label(self, text=value, bg=C["card"], fg=C["txt"], font=F(20, "bold"))
        self.v.pack(anchor="w", padx=16)
        tk.Label(self, text=label, bg=C["card"], fg=C["muted"], font=F(9)).pack(anchor="w", padx=16, pady=(0, 12))

    def set(self, v): self.v.config(text=str(v))


# ----------------------------------------------------------------- App
class SentinelX(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SentinelX Antivirus 2.0 — Premium Security Suite")
        self.geometry("1180x730")
        self.minsize(1040, 660)
        self.configure(bg=C["bg"])

        self.cfg = Config()
        self.log = Logger()
        self.engine = load_engine()
        self.quar = Quarantine(self.log)
        self.rem = Remediator(self.cfg, self.quar, self.log)
        self.guard = RealtimeGuard(self.engine, self.cfg, self.rem, self.log, self.on_guard_event)

        self.threat_rows = []
        self.scan_start_ts = 0
        self.current_scan_name = "—"
        self.session_detected = 0
        self.session_removed = 0

        self._style()
        self._build()
        self.load_signatures()

        self.log.listeners.append(lambda lv, m: self.after(0, self._append_log, lv, m))
        self.log.info(f"Khởi động SentinelX — engine: {self.engine.backend} / {self.engine.version}")

        if self.cfg["realtime"]:
            self.guard.start()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(60, self.animate)
        self.after(300, self.poll_engine)
        self.after(1000, self.scheduler_tick)

    # ---------------------------------------------------------- styling
    def _style(self):
        st = ttk.Style(self)
        try: st.theme_use("clam")
        except tk.TclError: pass
        st.configure("Treeview", background=C["card"], fieldbackground=C["card"],
                     foreground=C["txt"], rowheight=28, borderwidth=0, font=F(10))
        st.configure("Treeview.Heading", background=C["card2"], foreground=C["muted"],
                     relief="flat", font=F(10, "bold"))
        st.map("Treeview", background=[("selected", C["accent2"])], foreground=[("selected", "#02121d")])
        st.configure("TScrollbar", background=C["card2"], troughcolor=C["bg2"], bordercolor=C["bg2"],
                     arrowcolor=C["muted"])

    # ---------------------------------------------------------- layout
    def _build(self):
        # Sidebar
        side = tk.Frame(self, bg=C["bg2"], width=230)
        side.pack(side="left", fill="y"); side.pack_propagate(False)

        logo = tk.Canvas(side, width=230, height=110, bg=C["bg2"], highlightthickness=0)
        logo.pack()
        logo.create_polygon(40, 26, 68, 38, 68, 64, 54, 82, 40, 88, 26, 82, 12, 64, 12, 38,
                            smooth=True, fill=C["accent"], outline=C["accent2"], width=2)
        logo.create_text(40, 56, text="✓", fill="#04121c", font=F(20, "bold"))
        logo.create_text(96, 46, text="SentinelX", anchor="w", fill=C["txt"], font=F(16, "bold"))
        logo.create_text(97, 68, text="PREMIUM SECURITY", anchor="w", fill=C["muted"], font=F(8, "bold"))

        self.nav_buttons = {}
        self.pages = {}
        container = tk.Frame(self, bg=C["bg"])
        container.pack(side="right", fill="both", expand=True)
        self.container = container

        for key, label, icon in [("dash", "Tổng quan", "⬢"), ("scan", "Quét virus", "◎"),
                                 ("threats", "Mối đe doạ", "⚠"), ("quar", "Khu cách ly", "▣"),
                                 ("logs", "Nhật ký", "☰"), ("set", "Cài đặt", "⚙")]:
            b = tk.Label(side, text=f"   {icon}   {label}", anchor="w", bg=C["bg2"], fg=C["muted"],
                         font=F(11, "bold"), padx=12, pady=12)
            b.pack(fill="x", padx=12, pady=3)
            b.bind("<Button-1>", lambda e, k=key: self.show(k))
            b.bind("<Enter>", lambda e, w=b: w.config(fg=C["txt"], cursor="hand2"))
            b.bind("<Leave>", lambda e, w=b, k=key: w.config(fg=C["txt"] if self.cur == k else C["muted"]))
            self.nav_buttons[key] = b

        self.guard_badge = tk.Label(side, text="", bg=C["bg2"], fg=C["accent"], font=F(9, "bold"),
                                    justify="left", wraplength=200)
        self.guard_badge.pack(side="bottom", pady=16, padx=16, anchor="w")

        self.cur = "dash"
        for k, builder in [("dash", self.page_dash), ("scan", self.page_scan),
                           ("threats", self.page_threats), ("quar", self.page_quar),
                           ("logs", self.page_logs), ("set", self.page_settings)]:
            p = tk.Frame(container, bg=C["bg"])
            self.pages[k] = p
            builder(p)
        self.show("dash")

    def show(self, key):
        for p in self.pages.values(): p.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        self.cur = key
        for k, b in self.nav_buttons.items():
            b.config(fg=C["txt"] if k == key else C["muted"],
                     bg=C["card"] if k == key else C["bg2"])
        if key == "quar": self.refresh_quar()

    @staticmethod
    def header(parent, title, sub):
        f = tk.Frame(parent, bg=C["bg"]); f.pack(fill="x", padx=26, pady=(22, 10))
        tk.Label(f, text=title, bg=C["bg"], fg=C["txt"], font=F(20, "bold")).pack(anchor="w")
        tk.Label(f, text=sub, bg=C["bg"], fg=C["muted"], font=F(10)).pack(anchor="w")
        return f

    # ---------------------------------------------------------- page: dashboard
    def page_dash(self, p):
        self.header(p, "Trung tâm bảo mật", "Tình trạng bảo vệ theo thời gian thực của thiết bị")

        top = tk.Frame(p, bg=C["bg"]); top.pack(fill="x", padx=26)
        left = Card(top); left.pack(side="left", padx=(0, 16), ipadx=10, ipady=10)
        self.gauge = Gauge(left); self.gauge.pack(padx=20, pady=16)
        self.status_line = tk.Label(left, text="Không phát hiện mối đe doạ nào", bg=C["card"],
                                    fg=C["accent"], font=F(11, "bold"))
        self.status_line.pack(pady=(0, 14))

        right = tk.Frame(top, bg=C["bg"]); right.pack(side="left", fill="both", expand=True)
        grid = tk.Frame(right, bg=C["bg"]); grid.pack(fill="x")
        self.s_scanned = Stat(grid, "Tệp đã quét", "0", C["accent2"], "◎")
        self.s_threats = Stat(grid, "Mối đe doạ phát hiện", "0", C["danger"], "⚠")
        self.s_removed = Stat(grid, "Đã xoá / cách ly", "0", C["purple"], "✖")
        self.s_quar = Stat(grid, "Trong khu cách ly", "0", C["warn"], "▣")
        for i, s in enumerate([self.s_scanned, self.s_threats, self.s_removed, self.s_quar]):
            s.grid(row=i // 2, column=i % 2, sticky="nsew", padx=6, pady=6)
        grid.columnconfigure(0, weight=1); grid.columnconfigure(1, weight=1)

        act = Card(right); act.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(act, text="Hành động nhanh", bg=C["card"], fg=C["txt"], font=F(12, "bold")).pack(anchor="w", padx=16, pady=(14, 8))
        row = tk.Frame(act, bg=C["card"]); row.pack(padx=16, pady=(0, 14), anchor="w")
        GlowButton(row, "QUÉT NHANH", lambda: self.start_scan("quick"), icon="⚡").pack(side="left", padx=(0, 10))
        GlowButton(row, "QUÉT TOÀN BỘ", lambda: self.start_scan("full"), fill=C["accent2"], icon="◈").pack(side="left", padx=10)
        GlowButton(row, "CHỌN THƯ MỤC", lambda: self.start_scan("custom"), fill=C["card2"],
                   fg=C["txt"], outline=C["stroke"], icon="▤").pack(side="left", padx=10)

        bottom = Card(p); bottom.pack(fill="both", expand=True, padx=26, pady=18)
        tk.Label(bottom, text="Hoạt động gần đây", bg=C["card"], fg=C["txt"],
                 font=F(12, "bold")).pack(anchor="w", padx=16, pady=(12, 6))
        self.activity = tk.Listbox(bottom, bg=C["card2"], fg=C["txt"], bd=0, highlightthickness=0,
                                   font=F(10), selectbackground=C["accent2"], height=6)
        self.activity.pack(fill="both", expand=True, padx=16, pady=(0, 14))

    # ---------------------------------------------------------- page: scan
    def page_scan(self, p):
        self.header(p, "Quét virus", "Engine đa luồng C++ — quét theo chữ ký, mẫu nhị phân và heuristic")

        bar = Card(p); bar.pack(fill="x", padx=26)
        inner = tk.Frame(bar, bg=C["card"]); inner.pack(fill="x", padx=16, pady=14)
        self.btn_scan = GlowButton(inner, "BẮT ĐẦU QUÉT", self.toggle_scan, icon="▶", w=190)
        self.btn_scan.pack(side="left")
        self.scan_mode = tk.StringVar(value="quick")
        for txt, val in [("Nhanh", "quick"), ("Toàn bộ", "full"), ("Tuỳ chọn", "custom")]:
            tk.Radiobutton(inner, text=txt, variable=self.scan_mode, value=val, bg=C["card"],
                           fg=C["txt"], selectcolor=C["card2"], activebackground=C["card"],
                           activeforeground=C["accent"], font=F(10), bd=0,
                           highlightthickness=0).pack(side="left", padx=10)
        self.lbl_target = tk.Label(inner, text="", bg=C["card"], fg=C["muted"], font=F(9))
        self.lbl_target.pack(side="right")

        prog = Card(p); prog.pack(fill="x", padx=26, pady=12)
        self.pcanvas = tk.Canvas(prog, height=10, bg=C["card2"], highlightthickness=0)
        self.pcanvas.pack(fill="x", padx=16, pady=(16, 8))
        self.pbar = self.pcanvas.create_rectangle(0, 0, 0, 10, fill=C["accent"], width=0)
        info = tk.Frame(prog, bg=C["card"]); info.pack(fill="x", padx=16, pady=(0, 14))
        self.lbl_file = tk.Label(info, text="Sẵn sàng.", bg=C["card"], fg=C["muted"], font=F(9), anchor="w")
        self.lbl_file.pack(side="left", fill="x", expand=True)
        self.lbl_speed = tk.Label(info, text="", bg=C["card"], fg=C["accent2"], font=F(9, "bold"))
        self.lbl_speed.pack(side="right")

        res = Card(p); res.pack(fill="both", expand=True, padx=26, pady=(0, 20))
        cols = ("time", "verdict", "name", "sev", "path", "action")
        self.tree = ttk.Treeview(res, columns=cols, show="headings")
        for c, t, w in [("time", "Thời gian", 80), ("verdict", "Kết luận", 100), ("name", "Tên mã độc", 260),
                        ("sev", "Mức", 60), ("path", "Đường dẫn", 420), ("action", "Xử lý", 110)]:
            self.tree.heading(c, text=t); self.tree.column(c, width=w, anchor="w")
        self.tree.tag_configure("inf", foreground=C["danger"])
        self.tree.tag_configure("sus", foreground=C["warn"])
        sb = ttk.Scrollbar(res, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=12)
        sb.pack(side="right", fill="y", pady=12, padx=(0, 12))

    # ---------------------------------------------------------- page: threats
    def page_threats(self, p):
        self.header(p, "Mối đe doạ", "Danh sách toàn bộ phát hiện trong phiên làm việc")
        card = Card(p); card.pack(fill="both", expand=True, padx=26, pady=(0, 20))
        self.tbox = tk.Text(card, bg=C["card2"], fg=C["txt"], bd=0, highlightthickness=0,
                            font=("Consolas" if os.name == "nt" else "DejaVu Sans Mono", 10), wrap="word")
        self.tbox.pack(fill="both", expand=True, padx=14, pady=14)
        self.tbox.tag_config("h", foreground=C["danger"])
        self.tbox.insert("end", "Chưa có mối đe doạ nào được ghi nhận.\n")
        self.tbox.config(state="disabled")

    # ---------------------------------------------------------- page: quarantine
    def page_quar(self, p):
        self.header(p, "Khu cách ly", "File đã được mã hoá & vô hiệu hoá — có thể phục hồi hoặc xoá vĩnh viễn")
        card = Card(p); card.pack(fill="both", expand=True, padx=26, pady=(0, 20))
        cols = ("time", "threat", "orig", "size")
        self.qtree = ttk.Treeview(card, columns=cols, show="headings")
        for c, t, w in [("time", "Thời gian", 150), ("threat", "Mã độc", 300),
                        ("orig", "Đường dẫn gốc", 460), ("size", "Kích thước", 100)]:
            self.qtree.heading(c, text=t); self.qtree.column(c, width=w)
        self.qtree.pack(fill="both", expand=True, padx=14, pady=(14, 8))
        row = tk.Frame(card, bg=C["card"]); row.pack(anchor="w", padx=14, pady=(0, 14))
        GlowButton(row, "PHỤC HỒI", self.do_restore, fill=C["accent2"], icon="↩", w=150).pack(side="left")
        GlowButton(row, "XOÁ VĨNH VIỄN", self.do_qdelete, fill=C["danger"], fg="#fff", icon="✖", w=180).pack(side="left", padx=10)
        GlowButton(row, "DỌN SẠCH", self.do_qempty, fill=C["card2"], fg=C["txt"],
                   outline=C["stroke"], icon="✦", w=150).pack(side="left")

    # ---------------------------------------------------------- page: logs
    def page_logs(self, p):
        self.header(p, "Nhật ký hệ thống", "Toàn bộ sự kiện của engine, realtime guard và hành động xử lý")
        card = Card(p); card.pack(fill="both", expand=True, padx=26, pady=(0, 20))
        self.logbox = tk.Text(card, bg="#070b12", fg="#9ef7d2", bd=0, highlightthickness=0,
                              font=("Consolas" if os.name == "nt" else "DejaVu Sans Mono", 10))
        self.logbox.pack(fill="both", expand=True, padx=14, pady=14)
        for tag, col in [("INFO", C["muted"]), ("WARN", C["warn"]), ("ERROR", C["danger"]),
                         ("THREAT", C["danger"])]:
            self.logbox.tag_config(tag, foreground=col)

    # ---------------------------------------------------------- page: settings
    def page_settings(self, p):
        self.header(p, "Cài đặt", "Tinh chỉnh chế độ bảo vệ, hành động xử lý và hiệu năng quét")
        wrap = tk.Frame(p, bg=C["bg"]); wrap.pack(fill="both", expand=True, padx=26, pady=(0, 20))

        card = Card(wrap); card.pack(fill="x")
        self.vars = {}

        def toggle(key, label, desc):
            r = tk.Frame(card, bg=C["card"]); r.pack(fill="x", padx=16, pady=8)
            v = tk.BooleanVar(value=bool(self.cfg[key])); self.vars[key] = v
            cb = tk.Checkbutton(r, variable=v, text="  " + label, bg=C["card"], fg=C["txt"],
                                selectcolor=C["card2"], activebackground=C["card"],
                                activeforeground=C["accent"], font=F(11, "bold"), bd=0,
                                highlightthickness=0, command=lambda k=key: self.apply_setting(k))
            cb.pack(anchor="w")
            tk.Label(r, text="     " + desc, bg=C["card"], fg=C["muted"], font=F(9)).pack(anchor="w")

        toggle("realtime", "Bảo vệ thời gian thực", "Theo dõi file mới/thay đổi và chặn ngay lập tức")
        toggle("auto_delete", "Tự động xử lý khi phát hiện", "Xoá hoặc cách ly ngay mà không cần hỏi")
        toggle("heuristics", "Phân tích heuristic", "Phát hiện mã độc chưa có chữ ký (entropy, hành vi, chuỗi nguy hiểm)")
        toggle("sound", "Cảnh báo âm thanh", "Phát tiếng bíp khi phát hiện mối đe doạ")

        r = tk.Frame(card, bg=C["card"]); r.pack(fill="x", padx=16, pady=12)
        tk.Label(r, text="Hành động khi phát hiện:", bg=C["card"], fg=C["txt"], font=F(11, "bold")).pack(side="left")
        self.action_var = tk.StringVar(value=self.cfg["action"])
        for txt, val in [("Cách ly (an toàn)", "quarantine"), ("XOÁ NGAY lập tức", "delete")]:
            tk.Radiobutton(r, text=txt, variable=self.action_var, value=val, bg=C["card"], fg=C["txt"],
                           selectcolor=C["card2"], activebackground=C["card"], font=F(10), bd=0,
                           highlightthickness=0, command=self.apply_action).pack(side="left", padx=12)

        r2 = tk.Frame(card, bg=C["card"]); r2.pack(fill="x", padx=16, pady=(0, 16))
        tk.Label(r2, text="Số luồng quét (0 = tự động):", bg=C["card"], fg=C["txt"], font=F(10)).pack(side="left")
        self.threads_var = tk.StringVar(value=str(self.cfg["threads"]))
        tk.Entry(r2, textvariable=self.threads_var, width=6, bg=C["card2"], fg=C["txt"],
                 insertbackground=C["txt"], bd=0, highlightthickness=1,
                 highlightbackground=C["stroke"]).pack(side="left", padx=8)
        tk.Label(r2, text="Kích thước file tối đa (MB):", bg=C["card"], fg=C["txt"], font=F(10)).pack(side="left", padx=(20, 0))
        self.maxmb_var = tk.StringVar(value=str(self.cfg["max_file_mb"]))
        tk.Entry(r2, textvariable=self.maxmb_var, width=8, bg=C["card2"], fg=C["txt"],
                 insertbackground=C["txt"], bd=0, highlightthickness=1,
                 highlightbackground=C["stroke"]).pack(side="left", padx=8)
        GlowButton(r2, "LƯU", self.save_settings, w=110, h=34, icon="▼").pack(side="left", padx=16)

        card2 = Card(wrap); card2.pack(fill="both", expand=True, pady=14)
        tk.Label(card2, text="Thư mục giám sát thời gian thực", bg=C["card"], fg=C["txt"],
                 font=F(11, "bold")).pack(anchor="w", padx=16, pady=(14, 6))
        self.watchbox = tk.Listbox(card2, bg=C["card2"], fg=C["txt"], bd=0, highlightthickness=0, font=F(10))
        self.watchbox.pack(fill="both", expand=True, padx=16)
        for w in self.cfg["watch_paths"]: self.watchbox.insert("end", w)
        rr = tk.Frame(card2, bg=C["card"]); rr.pack(anchor="w", padx=16, pady=12)
        GlowButton(rr, "THÊM", self.add_watch, w=120, h=34, icon="＋").pack(side="left")
        GlowButton(rr, "XOÁ", self.del_watch, w=120, h=34, fill=C["card2"], fg=C["txt"],
                   outline=C["stroke"], icon="－").pack(side="left", padx=10)
        tk.Label(card2, text=f"Engine: {self.engine.backend} — {self.engine.version}",
                 bg=C["card"], fg=C["muted"], font=F(9)).pack(anchor="w", padx=16, pady=(0, 12))

    # ---------------------------------------------------------- signatures
    def load_signatures(self):
        f = DATA / "signatures.json"
        self.engine.reset_signatures()
        n = 0
        try:
            db = json.loads(f.read_text(encoding="utf-8"))
            for sha, name in db.get("hashes", {}).items():
                self.engine.add_hash_sig(sha, name); n += 1
            for p in db.get("patterns", []):
                self.engine.add_pattern_sig(p["pattern"], p.get("ascii", True), p["name"],
                                            p.get("severity", 70)); n += 1
            self.sig_version = db.get("version", "?")
        except Exception as e:
            self.log.err(f"Lỗi nạp CSDL chữ ký: {e}")
            self.sig_version = "N/A"
        self.engine.set_heuristics(self.cfg["heuristics"])
        try: self.engine.set_max_size_mb(self.cfg["max_file_mb"])
        except Exception: pass
        self.log.info(f"Đã nạp {n} chữ ký (CSDL {self.sig_version})")

    # ---------------------------------------------------------- scanning
    def targets(self, mode):
        home = Path.home()
        if mode == "quick":
            cands = [home / "Downloads", home / "Desktop", home / "Documents",
                     Path(os.environ.get("TEMP", "/tmp")), Path(os.environ.get("APPDATA", str(home)))]
            return [str(c) for c in cands if Path(c).exists()]
        if mode == "full":
            if os.name == "nt":
                import string, ctypes
                mask = ctypes.windll.kernel32.GetLogicalDrives()
                return [f"{d}:\\" for i, d in enumerate(string.ascii_uppercase) if mask >> i & 1]
            return ["/"]
        d = filedialog.askdirectory(title="Chọn thư mục cần quét")
        return [d] if d else []

    def start_scan(self, mode=None):
        if self.engine.is_running(): return
        mode = mode or self.scan_mode.get()
        self.scan_mode.set(mode)
        t = self.targets(mode)
        if not t: return
        self.show("scan")
        self.current_scan_name = {"quick": "Quét nhanh", "full": "Quét toàn bộ", "custom": "Quét tuỳ chọn"}[mode]
        self.lbl_target.config(text=" | ".join(t)[:90])
        self.scan_start_ts = time.time()
        self.gauge.scanning = True
        self.gauge.title = "ĐANG QUÉT"
        self.gauge.sub = self.current_scan_name
        self.btn_scan.set_state(C["danger"], "DỪNG QUÉT")
        self.engine.set_heuristics(self.cfg["heuristics"])
        self.engine.scan_start(t, int(self.cfg["threads"]))
        self.log.info(f"{self.current_scan_name} bắt đầu: {t}")
        self.activity_add(f"▶ {self.current_scan_name} bắt đầu")

    def toggle_scan(self):
        if self.engine.is_running():
            self.engine.scan_stop(); self.log.warn("Người dùng dừng quét")
        else:
            self.start_scan()

    def poll_engine(self):
        got = 0
        while got < 50:
            line = self.engine.next_result()
            if not line: break
            got += 1
            parts = (line.split("|") + ["", "", "", "", ""])[:5]
            path, verdict, name, sev, sha = parts
            if verdict == "DONE":
                self.finish_scan(); continue
            self.on_detect(path, verdict, name, sev, sha, source="scan")

        scanned, threats, nbytes = self.engine.stats()
        self.s_scanned.set(f"{scanned:,}")
        if self.engine.is_running():
            el = max(time.time() - self.scan_start_ts, 0.01)
            self.lbl_speed.config(text=f"{scanned/el:,.0f} tệp/giây  •  {human(nbytes)} đã đọc")
            self.lbl_file.config(text=f"Đang quét... {scanned:,} tệp  •  {threats} mối đe doạ")
            w = self.pcanvas.winfo_width()
            x = (time.time() * 220) % max(w, 1)
            self.pcanvas.coords(self.pbar, max(0, x - 180), 0, x, 10)
        self.after(250, self.poll_engine)

    def finish_scan(self):
        self.gauge.scanning = False
        self.gauge.title = "ĐANG BẢO VỆ" if self.session_detected == 0 else "ĐÃ XỬ LÝ"
        self.gauge.sub = "Hệ thống an toàn" if self.session_detected == 0 else f"{self.session_removed} mối đe doạ đã loại bỏ"
        self.gauge.color = C["accent"] if self.session_detected == 0 else C["warn"]
        self.gauge.pct = 1.0
        self.btn_scan.set_state(C["accent"], "BẮT ĐẦU QUÉT")
        scanned, threats, nbytes = self.engine.stats()
        el = time.time() - self.scan_start_ts
        self.pcanvas.coords(self.pbar, 0, 0, self.pcanvas.winfo_width(), 10)
        msg = f"Hoàn tất: {scanned:,} tệp ({human(nbytes)}) trong {el:.1f}s — {threats} mối đe doạ"
        self.lbl_file.config(text=msg)
        self.log.info(msg)
        self.activity_add("✔ " + msg)
        self.refresh_quar()

    # ---------------------------------------------------------- detections
    def on_detect(self, path, verdict, name, sev, sha, source="scan"):
        self.session_detected += 1
        ts = time.strftime("%H:%M:%S")
        action = "—"
        if self.cfg["auto_delete"] and verdict == "INFECTED":
            action = self.rem.handle(path, name, sha)
            if action in ("deleted", "quarantined"):
                self.session_removed += 1
        else:
            self.log.threat(f"PHÁT HIỆN ({source}): {path} — {name}")
        label = {"deleted": "ĐÃ XOÁ", "quarantined": "ĐÃ CÁCH LY",
                 "failed": "THẤT BẠI", "skipped": "BỎ QUA", "—": "CHỜ XỬ LÝ"}[action]
        self.tree.insert("", 0, values=(ts, verdict, name[:120], sev, path, label),
                         tags=("inf" if verdict == "INFECTED" else "sus",))
        self.s_threats.set(self.session_detected)
        self.s_removed.set(self.session_removed)
        self.status_line.config(text=f"{self.session_detected} mối đe doạ được phát hiện — {self.session_removed} đã loại bỏ",
                                fg=C["danger"])
        self.gauge.color = C["danger"]
        self.activity_add(f"⚠ {name[:48]} → {label}  ({Path(path).name})")
        self.tbox.config(state="normal")
        self.tbox.insert("1.0", f"[{ts}] {verdict} ({sev})  {name}\n        {path}\n        SHA256 {sha}\n        → {label}\n\n", "h")
        self.tbox.config(state="disabled")
        if self.cfg["sound"]:
            try: self.bell()
            except Exception: pass
        self.refresh_quar()

    def on_guard_event(self, kind, data):
        if kind == "detect":
            self.after(0, self.on_detect, data["path"], data["verdict"], data["name"],
                       data["severity"], data["sha"], "realtime")

    # ---------------------------------------------------------- quarantine ops
    def refresh_quar(self):
        if not hasattr(self, "qtree"): return
        self.qtree.delete(*self.qtree.get_children())
        for qid, m in sorted(self.quar.index.items(), reverse=True):
            self.qtree.insert("", "end", iid=qid,
                              values=(m["time"], m["threat"][:90], m["original"], human(m["size"])))
        self.s_quar.set(len(self.quar.index))

    def _sel(self):
        s = self.qtree.selection()
        if not s: messagebox.showinfo("SentinelX", "Hãy chọn một mục trong khu cách ly.")
        return s

    def do_restore(self):
        for qid in self._sel() or []:
            if messagebox.askyesno("Xác nhận", "Phục hồi file này? File có thể chứa mã độc thật sự!"):
                self.quar.restore(qid)
        self.refresh_quar()

    def do_qdelete(self):
        for qid in self._sel() or []:
            self.quar.delete(qid)
        self.refresh_quar()

    def do_qempty(self):
        if self.quar.index and messagebox.askyesno("Xác nhận", "Xoá vĩnh viễn toàn bộ khu cách ly?"):
            self.quar.empty(); self.refresh_quar()

    # ---------------------------------------------------------- settings ops
    def apply_setting(self, key):
        self.cfg[key] = self.vars[key].get(); self.cfg.save()
        if key == "realtime":
            self.guard.start() if self.cfg["realtime"] else self.guard.stop()
        if key == "heuristics":
            self.engine.set_heuristics(self.cfg["heuristics"])

    def apply_action(self):
        self.cfg["action"] = self.action_var.get(); self.cfg.save()
        self.log.warn(f"Hành động xử lý đổi thành: {self.cfg['action'].upper()}")

    def save_settings(self):
        try:
            self.cfg["threads"] = max(0, int(self.threads_var.get()))
            self.cfg["max_file_mb"] = max(1, int(self.maxmb_var.get()))
        except ValueError:
            messagebox.showerror("SentinelX", "Giá trị số không hợp lệ."); return
        self.cfg["watch_paths"] = list(self.watchbox.get(0, "end"))
        self.cfg.save()
        try: self.engine.set_max_size_mb(self.cfg["max_file_mb"])
        except Exception: pass
        self.log.info("Đã lưu cài đặt")
        messagebox.showinfo("SentinelX", "Đã lưu cài đặt thành công.")

    def add_watch(self):
        d = filedialog.askdirectory(title="Chọn thư mục giám sát")
        if d: self.watchbox.insert("end", d)

    def del_watch(self):
        for i in reversed(self.watchbox.curselection()): self.watchbox.delete(i)

    # ---------------------------------------------------------- misc
    def activity_add(self, text):
        self.activity.insert(0, f"{time.strftime('%H:%M:%S')}   {text}")
        if self.activity.size() > 200: self.activity.delete(200, "end")

    def _append_log(self, level, msg):
        if not hasattr(self, "logbox"): return
        self.logbox.insert("end", f"[{time.strftime('%H:%M:%S')}] [{level}] {msg}\n", level)
        self.logbox.see("end")

    def animate(self):
        self.gauge.tick()
        badge = ("● REALTIME ĐANG BẬT\n" if self.guard.active else "○ REALTIME ĐANG TẮT\n")
        badge += f"Đã kiểm tra: {self.guard.checked}\nĐã chặn: {self.guard.blocked}\n"
        badge += f"CSDL: {getattr(self, 'sig_version', '?')}"
        self.guard_badge.config(text=badge, fg=C["accent"] if self.guard.active else C["danger"])
        self.after(60, self.animate)

    def scheduler_tick(self):
        if self.cfg.get("schedule_enabled") and not self.engine.is_running():
            if time.strftime("%H:%M") == self.cfg.get("schedule_time"):
                self.start_scan("quick")
                time.sleep(1)
        self.after(20000, self.scheduler_tick)

    def on_close(self):
        self.guard.stop(); self.engine.scan_stop(); self.cfg.save()
        self.log.info("Thoát SentinelX")
        self.destroy()


if __name__ == "__main__":
    SentinelX().mainloop()
