#!/usr/bin/env python3
"""
NetPulse - Internet Noise connector
====================================
Genera data/noise.json. Mide "ruido" malicioso de Internet a partir de:

  1. abuse.ch Feodo Tracker (IP blocklist de C2 activos)  -> fuente principal
  2. GreyNoise Community API (opcional, por IP de watchlist) -> clasificacion

Feodo Tracker / abuse.ch hoy puede requerir un Auth-Key GRATUITO.
  -> registrate en https://auth.abuse.ch/ y exporta ABUSECH_AUTH_KEY
GreyNoise Community funciona sin key (rate-limited); con key es mejor.
  -> export GREYNOISE_API_KEY (opcional)

Solo stdlib.
"""

import json
import os
import sys
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

HERE = os.path.dirname(os.path.abspath(__file__))
WATCHLIST = os.path.join(HERE, "watchlist.json")
OUT = os.path.join(HERE, "..", "data", "noise.json")

FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
GREYNOISE = "https://api.greynoise.io/v3/community/{ip}"
TIMEOUT = 25


def get_json(url, headers=None):
    req = Request(url, headers=headers or {"User-Agent": "NetPulse/1.0"})
    try:
        with urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except (URLError, HTTPError, ValueError) as e:
        print(f"  [warn] {url} -> {e}", file=sys.stderr)
        return None


def fetch_feodo():
    headers = {"User-Agent": "NetPulse/1.0"}
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if key:
        headers["Auth-Key"] = key
    data = get_json(FEODO, headers=headers)
    if not isinstance(data, list):
        return [], {}
    by_malware = {}
    for row in data:
        fam = row.get("malware", "unknown")
        by_malware[fam] = by_malware.get(fam, 0) + 1
    return data, by_malware


def greynoise_lookup(ip):
    key = os.environ.get("GREYNOISE_API_KEY")
    headers = {"User-Agent": "NetPulse/1.0", "Accept": "application/json"}
    if key:
        headers["key"] = key
    data = get_json(GREYNOISE.format(ip=ip), headers=headers)
    if not data:
        return None
    return {
        "ip": ip,
        "noise": data.get("noise"),
        "riot": data.get("riot"),
        "classification": data.get("classification", "unknown"),
        "name": data.get("name", ""),
        "last_seen": data.get("last_seen", ""),
    }


def main():
    with open(WATCHLIST, encoding="utf-8") as f:
        cfg = json.load(f)
    watch_ips = cfg.get("noise", {}).get("watch_ips", [])

    blocklist, by_malware = fetch_feodo()
    active_c2 = len(blocklist)
    block_set = {r.get("ip_address") for r in blocklist}

    # cruce con watchlist
    hits = [ip for ip in watch_ips if ip in block_set]

    # GreyNoise por IP de watchlist (opcional / best-effort)
    gn = []
    for ip in watch_ips:
        res = greynoise_lookup(ip)
        if res:
            gn.append(res)
    malicious_gn = sum(1 for g in gn if g.get("classification") == "malicious")

    # noise_index 0-100: escala log-ish sobre C2 activos + hits de watchlist
    base = min(70, active_c2 / 20)        # ~1400 C2 ~> 70
    index = round(min(100, base + len(hits) * 10 + malicious_gn * 5))

    top = sorted(by_malware.items(), key=lambda kv: -kv[1])[:8]

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": ["abuse.ch Feodo Tracker", "GreyNoise Community (optional)"],
        "active_c2_ips": active_c2,
        "by_malware": [{"malware": k, "count": v} for k, v in top],
        "watchlist_hits": hits,
        "greynoise": gn,
        "signal": index,                  # <-- para el Risk Score / panel NOISE
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[ok] C2 activos={active_c2}, hits={len(hits)}, signal={index} -> {OUT}")


if __name__ == "__main__":
    main()
