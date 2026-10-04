# 🛡️ SentinelX Antivirus 2.1 — Premium Security Suite

Phần mềm diệt virus cho **Windows** (chạy được cả Linux/macOS), **engine C++17 đa luồng** + **GUI Python (Tkinter)** giao diện tối cao cấp. Tự động quét, **phát hiện là xử lý ngay lập tức** (xoá vĩnh viễn hoặc cách ly mã hoá).

![screenshot](screenshot.png)

> **Mới ở 2.1:** ⛨ Siêu bảo mật App (khoá ứng dụng bằng mật khẩu) · Tự bảo vệ chống báo nhầm chính mã nguồn · Phục hồi tất cả · Cập nhật CSDL online · Khởi động cùng Windows · Điểm bảo mật.

## 🚀 Chạy nhanh trên Windows
```bat
run.bat          :: tự build DLL (nếu có g++/MSVC) rồi mở GUI
```
hoặc thủ công:
```bat
cd core && build.bat && cd ..
python app\main.py
```
> Không có trình biên dịch C++? Vẫn chạy được — app tự chuyển sang **engine Python fallback** (chậm hơn, đủ tính năng).
> Nên chạy **Run as Administrator** để quét/xoá được file hệ thống.

Linux/macOS: `cd core && make && cd .. && python3 app/main.py`

## 📦 Đóng gói thành file .EXE
```bat
build_exe.bat            :: 1 lệnh: build DLL C++ -> PyInstaller -> dist\SentinelX.exe
```
Kết quả: **`dist\SentinelX.exe`** — một file duy nhất (~12–25 MB), **không cần cài Python**, có:
- icon `assets/sentinelx.ico`, thông tin phiên bản (`version_info.txt`)
- `console=False` (không cửa sổ đen), **`uac_admin=True`** → tự xin quyền Administrator khi mở
- DLL engine C++ + CSDL chữ ký **nhúng sẵn** bên trong; lần chạy đầu tự tạo `data/ logs/ quarantine/` **cạnh file exe**

Không có Windows/trình biên dịch? Đẩy code lên GitHub, workflow **`.github/workflows/build-windows.yml`** sẽ tự build `SentinelX.exe` trên `windows-latest` và cho tải về ở mục *Artifacts*.

**Tạo bộ cài đặt** (Start Menu + shortcut Desktop + tuỳ chọn khởi động cùng Windows):
```bat
iscc installer.iss       :: cần Inno Setup 6  ->  SentinelX_Setup.exe
```
> ⚠️ Vì exe thao tác xoá/ghi đè file, một số AV khác có thể cảnh báo *false positive* — hãy thêm ngoại lệ hoặc ký số (code signing) nếu phát hành rộng rãi.

## ⛨ SIÊU BẢO MẬT APP (App Lock) — tính năng nổi bật

![applock](screenshot_applock.png)

Chọn ứng dụng cần bảo vệ (Chrome, Zalo, Messenger, thư mục ngân hàng, game…). Từ đó:

1. Bạn mở ứng dụng → SentinelX phát hiện **tiến trình mới trong < 1 giây** và **kết thúc nó ngay**
2. Cửa sổ nhập mật khẩu bật lên, luôn **nổi trên cùng** (`-topmost`, `grab_set`)
3. **Nhập ĐÚNG** → ứng dụng tự được khởi chạy lại, có 25 giây ân hạn để không bị hỏi lặp
4. **Nhập SAI (hoặc bấm Huỷ)** → **KHOÁ ứng dụng 3 phút**; trong thời gian đó mọi lần mở đều bị giết tiến trình ngay, kèm đếm ngược trong bảng

| Chi tiết kỹ thuật | |
|---|---|
| Băm mật khẩu | **PBKDF2-HMAC-SHA256, 200.000 vòng, salt ngẫu nhiên 16 byte** — không lưu mật khẩu dạng rõ |
| So sánh | `secrets.compare_digest` (chống timing attack) |
| Giám sát tiến trình | `tasklist /FO CSV` (Windows) · `/proc` (Linux), chu kỳ 0.8s, chỉ xét **PID mới** |
| Kết thúc tiến trình | `taskkill /F /T /PID` (diệt cả cây tiến trình con) |
| Thêm ứng dụng | Duyệt file `.exe` **hoặc** chọn từ danh sách tiến trình đang chạy |
| Lưu trữ | `data/applock.json` |

## ✨ Các nâng cấp khác của 2.1
- **Tự bảo vệ (self-protection):** engine C++ có API `sx_add_exclusion()`; thư mục cài đặt/mã nguồn SentinelX **không bao giờ bị quét hay xoá** → hết cảnh AV tự cách ly chính nó.
- **Heuristic hiểu ngữ cảnh:** file `.cpp .py .json .md .txt .log .html`… bị **chia 4 điểm chuỗi** → không còn báo nhầm mã nguồn, tài liệu, log chứa từ khoá như `powershell -enc`.
- **PHỤC HỒI TẤT CẢ:** một nút trả lại toàn bộ khu cách ly về đúng vị trí gốc (cứu false positive hàng loạt).
- **Quản lý loại trừ** ngay trong Cài đặt (có hiển thị các mục `[tự bảo vệ]` không thể gỡ).
- **Cập nhật CSDL chữ ký online** từ chính repo này (`app/updater.py`), tự chạy lúc khởi động.
- **Khởi động cùng Windows** qua registry `HKCU\...\Run`, có kiểm tra quyền Admin.
- **Điểm bảo mật 0–100** trên Dashboard (realtime + heuristic + app lock + auto-update + quyền admin).

## 🧩 Kiến trúc
```
core/engine.cpp        Engine C++17 → sentinelx_core.dll / libsentinelx_core.so (C ABI)
app/engine_bridge.py   ctypes binding + fallback thuần Python
app/core_services.py   Config · Logger · Quarantine · Remediator · RealtimeGuard
app/main.py            GUI Tkinter (dashboard, quét, đe doạ, cách ly, log, cài đặt)
app/app_lock.py        ⛨ Siêu bảo mật App: PBKDF2, giám sát tiến trình, khoá 3 phút
app/updater.py         Cập nhật CSDL online + khởi động cùng Windows + kiểm tra Admin
app/cli.py             Quét bằng dòng lệnh
data/signatures.json   CSDL chữ ký (hash SHA-256 + mẫu ASCII/HEX)
quarantine/ logs/      Khu cách ly (mã hoá XOR) & nhật ký
```

## ⚙️ Engine C++ có gì
- **SHA-256 tự cài đặt** (không phụ thuộc thư viện ngoài) + đối chiếu hash CSDL
- **Boyer–Moore–Horspool** tìm mẫu nhị phân/ASCII cực nhanh
- **Thread pool** + `recursive_directory_iterator`, hàng đợi kết quả thread-safe
- **Heuristic**: entropy Shannon (phát hiện file PE bị pack/mã hoá), chuỗi nguy hiểm
  (`powershell -enc`, `vssadmin delete shadows`, `CreateRemoteThread`, `eval(atob(`…),
  bẫy **double extension** (`hoadon.pdf.exe`), đuôi hiếm `.scr/.pif/.hta`
- Chấm điểm: ≥60 → **INFECTED**, 35–59 → **SUSPICIOUS**
- Allow-list theo SHA-256, giới hạn dung lượng file, dừng quét tức thời

## 🖥️ Tính năng GUI
| Mục | Mô tả |
|---|---|
| Tổng quan | Vòng tròn trạng thái động, 4 thẻ thống kê, hành động nhanh, hoạt động gần đây |
| Quét virus | Quét **Nhanh / Toàn bộ ổ đĩa / Tuỳ chọn thư mục**, tốc độ tệp/giây, bảng kết quả màu |
| Mối đe doạ | Báo cáo chi tiết: kết luận, mức nguy hiểm, SHA-256, hành động đã thực hiện |
| Khu cách ly | Phục hồi / xoá vĩnh viễn / dọn sạch |
| Nhật ký | Log thời gian thực, tự xoay vòng 4 MB |
| ⛨ Siêu bảo mật App | Đặt/đổi mật khẩu, thêm–gỡ ứng dụng bảo vệ, xem trạng thái & đếm ngược khoá, mở khoá khẩn cấp |
| Cài đặt | Realtime, tự động xử lý, heuristic, âm báo, chế độ xoá/cách ly, số luồng, dung lượng tối đa, thư mục giám sát |

## 🔒 Cơ chế xử lý
- **Cách ly (mặc định, an toàn)**: file bị **XOR bằng khoá ngẫu nhiên 256-bit**, đổi tên `.sxq`, gỡ khỏi vị trí gốc → mất khả năng thực thi nhưng **phục hồi được**.
- **Xoá ngay lập tức**: ghi đè dữ liệu ngẫu nhiên (chống khôi phục) rồi xoá.
- **Realtime Guard**: quét file mới/thay đổi trong Downloads, Desktop, Documents, %TEMP%… mỗi 2 giây và chặn tức thì.

## 🧪 Kiểm thử an toàn
```bat
echo X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > %USERPROFILE%\Downloads\eicar.com
```
File EICAR là **file thử nghiệm chuẩn quốc tế, hoàn toàn vô hại** — SentinelX sẽ phát hiện và xử lý ngay.

## 💻 CLI
```bash
python app/cli.py C:\Users\me\Downloads --delete
```

## ⚠️ Lưu ý
Đây là sản phẩm kỹ thuật/giáo dục, **không thay thế** Windows Defender/Kaspersky… CSDL chữ ký chỉ gồm mẫu minh hoạ; hãy bổ sung hash vào `data/signatures.json` để mở rộng. Heuristic có thể báo nhầm — ưu tiên chế độ **Cách ly** thay vì Xoá.
