#!/usr/bin/env python3
"""Reproduce the corpus run.

  python3 scripts/bulk_scan.py list  OUT.json [--pages 10]     # popular plugins, ranked by active installs
  python3 scripts/bulk_scan.py scan  LIST.json START END OUT.jsonl [--workers 4]
  python3 scripts/bulk_scan.py stats OUT.jsonl
  python3 scripts/bulk_scan.py fetch LIST.json START END ZIPDIR   # optional: cache zips for re-runs
  add --zipdir ZIPDIR to `scan` to scan the cached zips instead of re-downloading

`scan` runs every plugin in its own subprocess (wordpress_audit.py <slug>@<version> --json, so
the zip is fetched into memory and never written to disk) with a hard timeout, and appends one
JSON line per plugin; re-running resumes where it stopped.
"""
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "wordpress_audit.py")
sys.path.insert(0, os.path.dirname(HERE))


def cmd_list(out, pages=10):
    import wordpress_audit as wa
    rows, seen = [], set()
    for page in range(1, pages + 1):
        for attempt in range(5):
            try:
                d = wa.popular(page)
                break
            except Exception as e:  # noqa: BLE001
                print("page %d retry %d: %s" % (page, attempt, e), file=sys.stderr)
                time.sleep(5 * (attempt + 1))
        else:
            raise SystemExit("page %d failed" % page)
        for i, p in enumerate(d["plugins"]):
            if p["slug"] in seen:
                continue
            seen.add(p["slug"])
            rows.append({"slug": p["slug"], "version": p.get("version"), "active_installs": p.get("active_installs", 0),
                         "api_rank": len(rows), "last_updated": p.get("last_updated")})
        time.sleep(1)
    rows.sort(key=lambda r: (-r["active_installs"], r["api_rank"]))
    for i, r in enumerate(rows):
        r["rank"] = i
    json.dump(rows, open(out, "w"), indent=0)
    print("%d plugins -> %s" % (len(rows), out))


ZIPDIR = None


def cmd_fetch(lst, start, end, zdir, workers=4):
    import urllib.request
    os.makedirs(zdir, exist_ok=True)
    rows = json.load(open(lst))[start:end]

    def get(row):
        dst = os.path.join(zdir, row["slug"] + ".zip")
        if os.path.exists(dst):
            return row["slug"], "cached"
        for url in ("https://downloads.wordpress.org/plugin/%s.%s.zip" % (row["slug"], row["version"]),
                    "https://downloads.wordpress.org/plugin/%s.latest-stable.zip" % row["slug"]):
            for attempt in range(4):
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "wordpress-audit-bulk"})
                    with urllib.request.urlopen(req, timeout=120) as r:
                        data = r.read()
                    with open(dst + ".part", "wb") as fh:
                        fh.write(data)
                    os.rename(dst + ".part", dst)
                    return row["slug"], "ok %d" % len(data)
                except Exception as e:  # noqa: BLE001
                    err = e
                    if "404" in str(e):
                        break
                    time.sleep(3 * (attempt + 1))
        return row["slug"], "ERR %s" % err

    with cf.ThreadPoolExecutor(workers) as ex:
        for i, (slug, st) in enumerate(ex.map(get, rows), 1):
            if not st.startswith(("ok", "cached")) or i % 100 == 0:
                print(i, slug, st, file=sys.stderr)


def _one(row, timeout=420):
    spec = row["slug"] + ("@" + row["version"] if row.get("version") else "")
    if ZIPDIR and os.path.exists(os.path.join(ZIPDIR, row["slug"] + ".zip")):
        spec = os.path.join(ZIPDIR, row["slug"] + ".zip")
    t = time.time()
    for attempt in range(2):
        try:
            p = subprocess.run([sys.executable, "-I", TOOL, spec, "--json"], capture_output=True, timeout=timeout)
            r = json.loads(p.stdout.decode("utf-8", "replace"))
            if r.get("error") and "404" in r["error"] and row.get("version"):
                p = subprocess.run([sys.executable, "-I", TOOL, row["slug"], "--json"], capture_output=True, timeout=timeout)
                r = json.loads(p.stdout.decode("utf-8", "replace"))
            if r.get("error") and attempt == 0:
                time.sleep(5)
                continue
            break
        except subprocess.TimeoutExpired:
            r = {"target": spec, "error": "timeout", "risk_level": "SAFE", "findings": [], "info": []}
            break
        except ValueError:
            r = {"target": spec, "error": "bad output: %s" % p.stderr.decode()[-300:], "risk_level": "SAFE",
                 "findings": [], "info": []}
    r["rank"], r["slug"], r["active_installs"] = row["rank"], row["slug"], row["active_installs"]
    r["secs"] = round(time.time() - t, 1)
    r["info_ids"] = sorted({f["id"] for f in r.pop("info", [])})
    return r


def cmd_scan(lst, start, end, out, workers=4):
    rows = json.load(open(lst))[start:end]
    done = set()
    if os.path.exists(out):
        for line in open(out):
            try:
                done.add(json.loads(line)["slug"])
            except ValueError:
                pass
    todo = [r for r in rows if r["slug"] not in done]
    print("%d to scan (%d already done)" % (len(todo), len(done)), file=sys.stderr)
    with open(out, "a") as fh, cf.ThreadPoolExecutor(workers) as ex:
        for i, r in enumerate(ex.map(_one, todo), 1):
            fh.write(json.dumps(r) + "\n")
            fh.flush()
            if r["risk_level"] not in ("SAFE",) or r.get("error"):
                print("%4d/%d %-40s %-8s %s %s" % (i, len(todo), r["slug"], r["risk_level"],
                      sorted({f["id"] for f in r.get("findings", [])}), r.get("error", "")), file=sys.stderr)
            elif i % 50 == 0:
                print("%4d/%d ..." % (i, len(todo)), file=sys.stderr)


def cmd_stats(out):
    rs = [json.loads(l) for l in open(out)]
    lv = {}
    for r in rs:
        k = "ERROR" if r.get("error") else r["risk_level"]
        lv[k] = lv.get(k, 0) + 1
    naive = sum(1 for r in rs if r.get("naive_flags"))
    print("n=%d levels=%s naive_flagged=%d (%.1f%%)" % (len(rs), lv, naive, 100.0 * naive / max(1, len(rs))))
    for r in rs:
        if r["risk_level"] in ("HIGH", "CRITICAL"):
            print(r["slug"], r["risk_level"], [(f["severity"], f["id"], f["file"], f["line"]) for f in r["findings"]
                                                if f["severity"] in ("HIGH", "CRITICAL")][:4])


if __name__ == "__main__":
    a = sys.argv[1:]
    w = 4
    if "--workers" in a:
        i = a.index("--workers")
        w = int(a[i + 1])
        del a[i:i + 2]
    if "--zipdir" in a:
        i = a.index("--zipdir")
        ZIPDIR = a[i + 1]
        del a[i:i + 2]
    pages = 10
    if "--pages" in a:
        i = a.index("--pages")
        pages = int(a[i + 1])
        del a[i:i + 2]
    if a[0] == "list":
        cmd_list(a[1], pages)
    elif a[0] == "scan":
        cmd_scan(a[1], int(a[2]), int(a[3]), a[4], w)
    elif a[0] == "fetch":
        cmd_fetch(a[1], int(a[2]), int(a[3]), a[4], w)
    elif a[0] == "stats":
        cmd_stats(a[1])
