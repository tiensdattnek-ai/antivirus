/* ============================================================
   SentinelX Antivirus - High Performance Scan Engine (C++17)
   ------------------------------------------------------------
   Build (Windows):  see build.bat   ->  sentinelx_core.dll
   Build (Linux):    make            ->  libsentinelx_core.so
   Exported as a flat C ABI so Python (ctypes) can drive it.

   Features
     * SHA-256 (hand written, no deps) + fast FNV-1a quick hash
     * Multi-threaded recursive directory walker (thread pool)
     * Signature DB: hash signatures + binary/ASCII pattern signatures
     * Boyer-Moore-Horspool pattern search over memory-mapped-ish buffers
     * Shannon entropy heuristic (packed / encrypted malware detection)
     * PE header inspection (MZ/PE, suspicious section names, high entropy)
     * Script heuristics (powershell -enc, eval(base64..), autorun, etc.)
     * Thread-safe result queue consumed incrementally by the GUI
   ============================================================ */

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(_WIN32)
  #define SX_API extern "C" __declspec(dllexport)
#else
  #define SX_API extern "C" __attribute__((visibility("default")))
#endif

namespace fs = std::filesystem;

/* ----------------------------- SHA-256 ----------------------------- */
namespace sha256 {
struct Ctx { uint32_t s[8]; uint64_t len; uint8_t buf[64]; size_t n; };
static const uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static inline uint32_t rr(uint32_t x,int c){return (x>>c)|(x<<(32-c));}
static void compress(Ctx&c,const uint8_t*p){
  uint32_t w[64];
  for(int i=0;i<16;i++) w[i]=(p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
  for(int i=16;i<64;i++){uint32_t s0=rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>3);
    uint32_t s1=rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1;}
  uint32_t a=c.s[0],b=c.s[1],cc=c.s[2],d=c.s[3],e=c.s[4],f=c.s[5],g=c.s[6],h=c.s[7];
  for(int i=0;i<64;i++){
    uint32_t S1=rr(e,6)^rr(e,11)^rr(e,25), ch=(e&f)^((~e)&g), t1=h+S1+ch+K[i]+w[i];
    uint32_t S0=rr(a,2)^rr(a,13)^rr(a,22), mj=(a&b)^(a&cc)^(b&cc), t2=S0+mj;
    h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;}
  c.s[0]+=a;c.s[1]+=b;c.s[2]+=cc;c.s[3]+=d;c.s[4]+=e;c.s[5]+=f;c.s[6]+=g;c.s[7]+=h;
}
static void init(Ctx&c){c.s[0]=0x6a09e667;c.s[1]=0xbb67ae85;c.s[2]=0x3c6ef372;c.s[3]=0xa54ff53a;
  c.s[4]=0x510e527f;c.s[5]=0x9b05688c;c.s[6]=0x1f83d9ab;c.s[7]=0x5be0cd19;c.len=0;c.n=0;}
static void update(Ctx&c,const uint8_t*d,size_t l){
  c.len+=l;
  while(l){size_t t=std::min(l,64-c.n);memcpy(c.buf+c.n,d,t);c.n+=t;d+=t;l-=t;
    if(c.n==64){compress(c,c.buf);c.n=0;}}}
static std::string final_hex(Ctx&c){
  uint64_t bits=c.len*8; uint8_t pad=0x80; update(c,&pad,1); uint8_t z=0;
  while(c.n!=56) update(c,&z,1);
  uint8_t lenb[8]; for(int i=0;i<8;i++) lenb[i]=(uint8_t)(bits>>(56-8*i));
  update(c,lenb,8);
  static const char*hx="0123456789abcdef"; std::string out; out.reserve(64);
  for(int i=0;i<8;i++) for(int j=3;j>=0;j--){uint8_t b=(uint8_t)(c.s[i]>>(j*8));
    out+=hx[b>>4]; out+=hx[b&15];}
  return out;}
} // namespace sha256

/* ----------------------------- Signatures ----------------------------- */
struct PatternSig {
  std::string name;
  std::vector<uint8_t> pat;
  int severity = 70;
  std::vector<int> shift = std::vector<int>(256, 0);
  void build() { int m = (int)pat.size();
    for (int i = 0; i < 256; i++) shift[i] = m;
    for (int i = 0; i < m - 1; i++) shift[pat[i]] = m - 1 - i; }
};

struct Engine {
  std::unordered_map<std::string, std::string> hashSigs;   // sha256 -> name
  std::vector<PatternSig> patSigs;
  std::unordered_set<std::string> whitelist;               // sha256 allow-list
  std::vector<std::string> exclusions;                     // duong dan bi loai tru (self-protect)
  std::atomic<bool> heuristics{true};
  std::atomic<bool> stopFlag{false};
  std::atomic<uint64_t> scanned{0}, threats{0}, bytes{0};
  size_t maxFileSize = 256ull * 1024 * 1024;
  std::mutex qmtx;
  std::queue<std::string> results;   // "path|verdict|name|severity|sha"
  std::atomic<bool> running{false};
  std::vector<std::thread> workers;
};
static Engine g;

static bool bmh(const uint8_t* hay, size_t n, const PatternSig& s) {
  size_t m = s.pat.size(); if (m == 0 || n < m) return false;
  size_t i = 0;
  while (i <= n - m) {
    size_t j = m; while (j && s.pat[j-1] == hay[i+j-1]) --j;
    if (!j) return true;
    i += s.shift[hay[i+m-1]];
  }
  return false;
}

static double entropy(const uint8_t* d, size_t n) {
  if (!n) return 0.0;
  size_t f[256] = {0};
  for (size_t i = 0; i < n; i++) f[d[i]]++;
  double e = 0.0;
  for (int i = 0; i < 256; i++) if (f[i]) { double p = (double)f[i]/n; e -= p * std::log2(p); }
  return e;
}

static std::string lower(std::string s){ for(auto&c:s) c=(char)std::tolower((unsigned char)c); return s; }

static bool isExcluded(const std::string& path) {
  std::string p = lower(path);
  for (auto& e : g.exclusions) if (p.rfind(e, 0) == 0) return true;
  return false;
}

/* File ma nguon / van ban: chua chuoi "nguy hiem" la binh thuong (bang signature,
   tai lieu, log...). Khong duoc ket luan nhiem chi vi co chuoi. */
static bool isSourceOrText(const std::string& ext) {
  static const std::unordered_set<std::string> k = {
    ".cpp",".cc",".cxx",".c",".h",".hpp",".py",".pyw",".java",".cs",".go",".rs",
    ".json",".md",".txt",".log",".csv",".xml",".yml",".yaml",".ini",".cfg",".toml",
    ".rst",".html",".htm",".css",".ts",".sql",".spec",".iss",".diff",".patch"};
  return k.count(ext) > 0;
}

/* Heuristic rules applied on raw buffer + metadata. Returns severity (0 = clean). */
static int heuristicScan(const std::vector<uint8_t>& b, const std::string& path, std::string& why) {
  int score = 0;
  std::string ext = lower(fs::path(path).extension().string());
  bool isPE = b.size() > 0x40 && b[0] == 'M' && b[1] == 'Z';
  double ent = entropy(b.data(), std::min<size_t>(b.size(), 1u << 20));

  if (isPE && ent > 7.2) { score += 45; why += "PE packed/encrypted (entropy " + std::to_string(ent).substr(0,4) + "); "; }
  if (!isPE && ent > 7.6 && b.size() > 4096) { score += 20; why += "very high entropy blob; "; }

  static const char* badstr[] = {
    "powershell -enc", "powershell -e ", "frombase64string", "downloadstring",
    "invoke-expression", "iex(", "cmd.exe /c vssadmin delete shadows",
    "bcdedit /set {default} recoveryenabled no", "wbadmin delete catalog",
    "your files have been encrypted", "bitcoin wallet", "cryptolocker",
    "createremotethread", "virtualallocex", "writeprocessmemory", "setwindowshookex",
    "shellexecutea", "urldownloadtofile", "schtasks /create", "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "document.write(unescape(", "eval(atob(", "wscript.shell"
  };
  static const int badw[] = {40,40,25,30,30,35,60,60,55,65,25,70,30,30,30,25,15,35,25,35,25,35,20};

  std::string low; low.resize(std::min<size_t>(b.size(), 2u << 20));
  for (size_t i = 0; i < low.size(); i++) low[i] = (char)std::tolower(b[i]);
  bool srcLike = isSourceOrText(ext);
  int strScore = 0;
  for (size_t i = 0; i < sizeof(badstr)/sizeof(*badstr); i++)
    if (low.find(badstr[i]) != std::string::npos) { strScore += badw[i]; why += std::string(badstr[i]) + "; "; }
  /* File .cpp/.py/.json/.md... chi la van ban: ha diem manh de khong bao nham
     ma nguon, CSDL chu ky, tai lieu, log cua chinh phan mem diet virus. */
  if (srcLike) strScore /= 4;
  score += strScore;

  // double extension trick:  invoice.pdf.exe
  std::string stem = lower(fs::path(path).stem().string());
  if ((ext == ".exe" || ext == ".scr" || ext == ".com" || ext == ".pif" || ext == ".bat") &&
      (stem.find(".pdf") != std::string::npos || stem.find(".doc") != std::string::npos ||
       stem.find(".jpg") != std::string::npos || stem.find(".txt") != std::string::npos)) {
    score += 55; why += "double extension; ";
  }
  if (ext == ".scr" || ext == ".pif" || ext == ".hta") { score += 20; why += "rare executable ext; "; }
  return score;
}

static void pushResult(const std::string& line) {
  std::lock_guard<std::mutex> lk(g.qmtx);
  g.results.push(line);
}

static void scanFile(const fs::path& p) {
  if (isExcluded(p.string())) return;
  std::error_code ec;
  auto sz = fs::file_size(p, ec);
  if (ec) return;
  g.scanned++;
  if (sz == 0 || sz > g.maxFileSize) return;
  std::ifstream f(p, std::ios::binary);
  if (!f) return;
  std::vector<uint8_t> buf((size_t)sz);
  f.read((char*)buf.data(), (std::streamsize)sz);
  if (!f) buf.resize((size_t)f.gcount());
  g.bytes += buf.size();

  sha256::Ctx c; sha256::init(c);
  sha256::update(c, buf.data(), buf.size());
  std::string sha = sha256::final_hex(c);

  std::string path = p.string();
  if (g.whitelist.count(sha)) return;

  auto it = g.hashSigs.find(sha);
  if (it != g.hashSigs.end()) {
    g.threats++; pushResult(path + "|INFECTED|" + it->second + "|100|" + sha); return;
  }
  for (auto& s : g.patSigs) {
    if (bmh(buf.data(), buf.size(), s)) {
      g.threats++; pushResult(path + "|INFECTED|" + s.name + "|" + std::to_string(s.severity) + "|" + sha);
      return;
    }
  }
  if (g.heuristics) {
    std::string why;
    int sc = heuristicScan(buf, path, why);
    if (sc >= 60) { g.threats++; pushResult(path + "|INFECTED|Heuristic.Generic [" + why + "]|" + std::to_string(std::min(sc,99)) + "|" + sha); return; }
    if (sc >= 35) { g.threats++; pushResult(path + "|SUSPICIOUS|Heuristic.Suspicious [" + why + "]|" + std::to_string(sc) + "|" + sha); return; }
  }
}

/* --------------------------- Parallel walker --------------------------- */
static void scanTreeThreaded(std::vector<std::string> roots, int nthreads) {
  g.running = true; g.stopFlag = false;
  std::queue<fs::path> work; std::mutex wm; std::condition_variable cv;
  std::atomic<bool> producing{true};

  auto worker = [&]() {
    for (;;) {
      fs::path p;
      { std::unique_lock<std::mutex> lk(wm);
        cv.wait(lk, [&]{ return !work.empty() || !producing || g.stopFlag; });
        if (g.stopFlag) return;
        if (work.empty()) { if (!producing) return; else continue; }
        p = work.front(); work.pop(); }
      scanFile(p);
    }
  };
  std::vector<std::thread> th;
  for (int i = 0; i < nthreads; i++) th.emplace_back(worker);

  for (auto& r : roots) {
    std::error_code ec;
    fs::recursive_directory_iterator it(r, fs::directory_options::skip_permission_denied, ec), end;
    if (ec) continue;
    for (; it != end; it.increment(ec)) {
      if (g.stopFlag) break;
      if (ec) { ec.clear(); continue; }
      if (!it->is_regular_file(ec)) continue;
      { std::lock_guard<std::mutex> lk(wm); work.push(it->path()); }
      cv.notify_one();
      while (true) { std::lock_guard<std::mutex> lk(wm); if (work.size() < 4096) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2)); }
    }
    if (g.stopFlag) break;
  }
  { std::lock_guard<std::mutex> lk(wm); producing = false; }
  cv.notify_all();
  for (auto& t : th) t.join();
  g.running = false;
  pushResult("|DONE|||");
}

/* ------------------------------ C API ------------------------------ */
SX_API const char* sx_version() { return "SentinelX Core 2.0 (C++17)"; }

SX_API void sx_reset_signatures() { g.hashSigs.clear(); g.patSigs.clear(); g.whitelist.clear(); }

SX_API void sx_add_hash_sig(const char* sha256hex, const char* name) { g.hashSigs[lower(sha256hex)] = name; }

SX_API void sx_add_whitelist(const char* sha256hex) { g.whitelist.insert(lower(sha256hex)); }

/* Loai tru mot thu muc/file khoi moi hoat dong quet (dung cho self-protection). */
SX_API void sx_add_exclusion(const char* path) {
  std::string p = lower(path);
  while (!p.empty() && (p.back() == '/' || p.back() == '\\')) p.pop_back();
  if (!p.empty()) g.exclusions.push_back(p);
}
SX_API void sx_clear_exclusions() { g.exclusions.clear(); }
SX_API int  sx_is_excluded(const char* path) { return isExcluded(path) ? 1 : 0; }

/* hexpat: hex string e.g. "4d5a9000" ; or ascii if is_ascii != 0 */
SX_API void sx_add_pattern_sig(const char* pat, int is_ascii, const char* name, int severity) {
  PatternSig s; s.name = name; s.severity = severity;
  if (is_ascii) { for (const char* q = pat; *q; ++q) s.pat.push_back((uint8_t)*q); }
  else { std::string h = pat; for (size_t i = 0; i + 1 < h.size(); i += 2)
           s.pat.push_back((uint8_t)strtol(h.substr(i,2).c_str(), nullptr, 16)); }
  if (s.pat.empty()) return;
  s.build(); g.patSigs.push_back(std::move(s));
}

SX_API void sx_set_heuristics(int on) { g.heuristics = on != 0; }
SX_API void sx_set_max_size(long long mb) { g.maxFileSize = (size_t)mb * 1024 * 1024; }

SX_API void sx_scan_start(const char* roots_semicolon, int threads) {
  if (g.running) return;
  std::vector<std::string> roots; std::string s(roots_semicolon), cur;
  for (char ch : s) { if (ch == ';') { if (!cur.empty()) roots.push_back(cur); cur.clear(); } else cur += ch; }
  if (!cur.empty()) roots.push_back(cur);
  g.scanned = 0; g.threats = 0; g.bytes = 0;
  { std::lock_guard<std::mutex> lk(g.qmtx); std::queue<std::string> e; std::swap(g.results, e); }
  if (threads <= 0) threads = (int)std::max(2u, std::thread::hardware_concurrency());
  std::thread(scanTreeThreaded, roots, threads).detach();
}

SX_API void sx_scan_stop() { g.stopFlag = true; }
SX_API int  sx_is_running() { return g.running ? 1 : 0; }
SX_API long long sx_scanned() { return (long long)g.scanned.load(); }
SX_API long long sx_threats() { return (long long)g.threats.load(); }
SX_API long long sx_bytes()   { return (long long)g.bytes.load(); }

/* Pops one result line into caller buffer. Returns 1 if a result was written. */
SX_API int sx_next_result(char* out, int cap) {
  std::lock_guard<std::mutex> lk(g.qmtx);
  if (g.results.empty()) return 0;
  std::string r = g.results.front(); g.results.pop();
  if ((int)r.size() >= cap) r.resize(cap - 1);
  memcpy(out, r.c_str(), r.size() + 1);
  return 1;
}

/* Scan one single file synchronously (used by the realtime guard). */
SX_API int sx_scan_one(const char* path, char* out, int cap) {
  { std::lock_guard<std::mutex> lk(g.qmtx); std::queue<std::string> e; std::swap(g.results, e); }
  std::error_code ec; fs::path p(path);
  if (!fs::is_regular_file(p, ec)) return 0;
  scanFile(p);
  return sx_next_result(out, cap);
}

SX_API int sx_sha256_file(const char* path, char* out, int cap) {
  std::ifstream f(path, std::ios::binary); if (!f || cap < 65) return 0;
  sha256::Ctx c; sha256::init(c); std::vector<uint8_t> buf(1 << 20);
  while (f) { f.read((char*)buf.data(), (std::streamsize)buf.size());
    sha256::update(c, buf.data(), (size_t)f.gcount()); }
  std::string h = sha256::final_hex(c); memcpy(out, h.c_str(), h.size() + 1); return 1;
}

SX_API double sx_entropy_file(const char* path) {
  std::ifstream f(path, std::ios::binary); if (!f) return -1;
  std::vector<uint8_t> buf(1 << 20);
  f.read((char*)buf.data(), (std::streamsize)buf.size());
  return entropy(buf.data(), (size_t)f.gcount());
}
