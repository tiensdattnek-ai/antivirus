#!/usr/bin/env python3
"""SentinelX CLI — quét không cần GUI.
  python app/cli.py <thư_mục> [--delete] [--quarantine] [--no-heur]
"""
import json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from core_services import Config, Logger, Quarantine, Remediator, DATA
from engine_bridge import load_engine

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); return 1
    roots = [a for a in args if not a.startswith("--")] or ["."]
    cfg = Config()
    cfg["action"] = "delete" if "--delete" in args else "quarantine"
    cfg["heuristics"] = "--no-heur" not in args
    log, eng = Logger("cli"), load_engine()
    rem = Remediator(cfg, Quarantine(log), log)

    db = json.loads((DATA / "signatures.json").read_text(encoding="utf-8"))
    for s, n in db["hashes"].items(): eng.add_hash_sig(s, n)
    for p in db["patterns"]: eng.add_pattern_sig(p["pattern"], p.get("ascii", True), p["name"], p["severity"])
    eng.set_heuristics(cfg["heuristics"])

    print(f"SentinelX CLI — engine: {eng.backend} | hành động: {cfg['action']}")
    t0 = time.time(); eng.scan_start(roots, 0); found = 0
    while True:
        r = eng.next_result()
        if not r: time.sleep(0.05); continue
        path, verdict, name, sev, sha = (r.split("|") + [""] * 5)[:5]
        if verdict == "DONE": break
        found += 1
        act = rem.handle(path, name, sha) if verdict == "INFECTED" else "cảnh báo"
        print(f"  [{verdict}] {name}  ->  {path}  ({act})")
    s, th, b = eng.stats()
    print(f"\nXong: {s:,} tệp, {found} mối đe doạ, {time.time()-t0:.1f}s")
    return 1 if found else 0

if __name__ == "__main__":
    sys.exit(main())
