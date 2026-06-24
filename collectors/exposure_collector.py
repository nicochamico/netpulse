#!/usr/bin/env python3
"""
NetPulse - Exposed Systems connector
====================================
Genera data/exposure.json usando Shodan InternetDB (GRATIS, sin API key).
  GET https://internetdb.shodan.io/{ip}
  -> { ip, ports[], cpes[], hostnames[], tags[], vulns[] }

Agrega los targets monitoreados en un indice de exposicion 0-100.
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
OUT = os.path.join(HERE, "..", "data", "exposure.json")
INTERNETDB = "https://internetdb.shodan.io/{ip}"
TIMEOUT = 25

# puertos considerados "riesgo" si quedan expuestos a Internet
RISKY_PORTS = {21, 23, 135, 139, 445, 3389, 5900, 1433, 3306, 5432, 6379, 9200, 27017, 11211}


def lookup(ip):
    req = Request(INTERNETDB.format(ip=ip), headers={"User-Agent": "NetPulse/1.0"})
    try:
        with urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except HTTPError as e:
        if e.code == 404:        # IP sin datos = sin exposicion conocida
            return {"ip": ip, "ports": [], "vulns": [], "tags": [], "hostnames": [], "cpes": []}
        print(f"  [warn] {ip} -> {e}", file=sys.stderr)
        return None
    except (URLError, ValueError) as e:
        print(f"  [warn] {ip} -> {e}", file=sys.stderr)
        return None


def main():
    with open(WATCHLIST, encoding="utf-8") as f:
        cfg = json.load(f)
    targets = cfg.get("exposure", {}).get("targets", [])

    systems, all_vulns, all_risky = [], set(), 0
    for ip in targets:
        d = lookup(ip)
        if d is None:
            continue
        ports = d.get("ports", [])
        vulns = d.get("vulns", [])
        risky = [p for p in ports if p in RISKY_PORTS]
        all_vulns.update(vulns)
        all_risky += len(risky)
        systems.append({
            "ip": ip,
            "open_ports": ports,
            "risky_ports": risky,
            "vulns": vulns,
            "tags": d.get("tags", []),
            "hostnames": d.get("hostnames", []),
        })

    # exposure_index 0-100: CVEs unicos pesan mas que puertos riesgosos
    index = min(100, len(all_vulns) * 6 + all_risky * 4)

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "Shodan InternetDB",
        "monitored": len(targets),
        "unique_cves": sorted(all_vulns),
        "risky_ports_total": all_risky,
        "systems": systems,
        "signal": index,                 # <-- para el panel EXPOSURE
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[ok] {len(systems)} sistemas, {len(all_vulns)} CVEs, signal={index} -> {OUT}")


if __name__ == "__main__":
    main()
