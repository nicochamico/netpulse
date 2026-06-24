#!/usr/bin/env python3
"""
NetPulse - BGP connector  (v2)
==============================
Genera data/bgp.json a partir de la API publica de RIPEstat (sin API key).

Para cada prefijo de la watchlist evalua, en tiempo (casi) real:
  - Origen(es) visto(s) por los route collectors (looking-glass)
  - MOAS            -> mas de un ASN origen para el mismo prefijo
  - ORIGIN_CHANGE   -> origen visto != expected_origin de la watchlist
  - RPKI_INVALID    -> validacion RPKI del par (origen, prefijo)
  - WITHDRAWN       -> el prefijo no es visible por ningun peer
  - HIGH_CHURN      -> inestabilidad NORMALIZADA por peer (informativo)

Cambios v2:
  * Churn medido por peer visible (updates/peer/24h y withdrawal ratio),
    no como conteo absoluto -> elimina falsos positivos en prefijos anycast.
  * HIGH_CHURN es informativo: NO cuenta como anomalia de seguridad ni
    infla el 'signal'. El signal sale solo de MOAS/ORIGIN_CHANGE/RPKI/WITHDRAWN.

Salida normalizada para el front (tabla BGP WATCH) + 'signal' 0-100 para el
Risk Score (15%). Sin dependencias externas: solo stdlib.
"""

import json
import time
import sys
import os
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import URLError, HTTPError

RIPESTAT = "https://stat.ripe.net/data/{endpoint}/data.json"
SOURCEAPP = "netpulse-bgp"          # RIPEstat pide identificar la app
TIMEOUT = 25
SLEEP_BETWEEN = 0.4                  # cortesia con la API
HERE = os.path.dirname(os.path.abspath(__file__))
WATCHLIST = os.path.join(HERE, "watchlist.json")
OUT = os.path.join(HERE, "..", "data", "bgp.json")

# Anomalias de SEGURIDAD (alimentan el signal)
SEC_SEV = {
    "ORIGIN_CHANGE": 35,   # posible hijack
    "RPKI_INVALID": 30,
    "MOAS": 25,
    "WITHDRAWN": 20,
}
# Informativo (visible en la tabla, NO infla el score)
INFO_SEV = {"HIGH_CHURN": 5}

# Umbrales de churn normalizado
CHURN_UPP = 10.0          # updates por peer / 24h
CHURN_WD_RATIO = 0.5      # withdrawals / peers visibles (flap real)
HIGH_CHURN_ABS_GUARD = 0  # 0 = sin guarda absoluta; subir si quieres piso minimo


def ripestat(endpoint, **params):
    """GET tipado a RIPEstat. Devuelve el dict 'data' o None si falla."""
    params["sourceapp"] = SOURCEAPP
    url = RIPESTAT.format(endpoint=endpoint) + "?" + urlencode(params)
    req = Request(url, headers={"User-Agent": "NetPulse/1.0 (+netpulse-latam)"})
    try:
        with urlopen(req, timeout=TIMEOUT) as r:
            payload = json.loads(r.read().decode("utf-8"))
        return payload.get("data")
    except (URLError, HTTPError, ValueError) as e:
        print(f"  [warn] {endpoint} {params.get('resource')} -> {e}", file=sys.stderr)
        return None


def seen_origins(prefix):
    """Origenes distintos vistos por los route collectors + nro de peers."""
    data = ripestat("looking-glass", resource=prefix)
    origins, peers_total = set(), 0
    if not data:
        return origins, 0
    for rrc in data.get("rrcs", []):
        for peer in rrc.get("peers", []):
            peers_total += 1
            asn = peer.get("asn_origin")
            if asn:
                # asn_origin puede venir como "15169" o "15169 {15169}"
                try:
                    origins.add(int(str(asn).split()[0].strip("{}")))
                except ValueError:
                    pass
    return origins, peers_total


def rpki_status(asn, prefix):
    data = ripestat("rpki-validation", resource=f"AS{asn}", prefix=prefix)
    if not data:
        return "unknown"
    return (data.get("status") or "unknown").lower()


def as_holder(asn):
    data = ripestat("as-overview", resource=f"AS{asn}")
    if not data:
        return f"AS{asn}"
    return data.get("holder") or f"AS{asn}"


def churn_24h(prefix):
    start = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    data = ripestat("bgp-updates", resource=prefix, starttime=start)
    if not data:
        return 0, 0
    a = w = 0
    for u in data.get("updates", []):
        if u.get("type") == "A":
            a += 1
        elif u.get("type") == "W":
            w += 1
    return a, w


def evaluate(entry):
    prefix = entry["prefix"]
    expected = int(entry["expected_origin"])
    name = entry.get("name", "")
    print(f"-> {prefix} (expected AS{expected})", file=sys.stderr)

    origins, peers = seen_origins(prefix)
    time.sleep(SLEEP_BETWEEN)
    ann, wd = churn_24h(prefix)
    time.sleep(SLEEP_BETWEEN)

    statuses = []
    primary_origin = expected
    rpki = "n/a"
    if origins:
        # origen "principal" = el mas plausible (expected si esta presente)
        primary_origin = expected if expected in origins else sorted(origins)[0]

    if peers == 0 or not origins:
        statuses.append("WITHDRAWN")
    else:
        if len(origins) > 1:
            statuses.append("MOAS")
        if expected not in origins:
            statuses.append("ORIGIN_CHANGE")
        rpki = rpki_status(primary_origin, prefix)
        time.sleep(SLEEP_BETWEEN)
        if rpki == "invalid":
            statuses.append("RPKI_INVALID")

    # churn NORMALIZADO por peer visible (no conteo absoluto)
    upp = (ann + wd) / peers if peers else 0          # updates/peer/24h
    wd_ratio = wd / peers if peers else 0             # withdrawals = flap real
    high_churn = (
        peers > 0
        and (upp >= CHURN_UPP or wd_ratio >= CHURN_WD_RATIO)
        and (ann + wd) >= HIGH_CHURN_ABS_GUARD
    )
    if high_churn:
        statuses.append("HIGH_CHURN")

    # severidad = solo anomalias de SEGURIDAD
    sec = [s for s in statuses if s in SEC_SEV]
    score = max((SEC_SEV[s] for s in sec), default=0)
    if not statuses:
        statuses = ["OK"]

    holder = as_holder(primary_origin) if origins else f"AS{expected}"
    time.sleep(SLEEP_BETWEEN)

    return {
        "event": statuses[0],
        "prefix": prefix,
        "origin_asn": primary_origin,
        "origins_seen": sorted(origins),
        "name": name or holder,
        "holder": holder,
        "status": "+".join(statuses),
        "rpki": rpki,
        "updates_24h": {"announcements": ann, "withdrawals": wd},
        "updates_per_peer": round(upp, 2),
        "peers_visible": peers,
        "is_security_anomaly": bool(sec),
        "severity": score,                 # severidad de SEGURIDAD (0 si sana)
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def main():
    with open(WATCHLIST, encoding="utf-8") as f:
        cfg = json.load(f)
    entries = cfg.get("bgp", [])

    events = []
    for entry in entries:
        try:
            ev = evaluate(entry)
        except Exception as e:  # nunca tumbar el pipeline por un prefijo
            print(f"  [error] {entry.get('prefix')}: {e}", file=sys.stderr)
            continue
        events.append(ev)

    # signal 0-100: SOLO anomalias de seguridad
    sec_events = [e for e in events if e["severity"] > 0]
    anomalies = len(sec_events)                       # HIGH_CHURN no cuenta
    max_sev = max((e["severity"] for e in events), default=0)
    density = min(30, (anomalies / len(events) * 30)) if events else 0
    signal = min(100, round(max_sev + density))

    # churn informativo aparte (visibilidad, no afecta el score)
    churn_events = sum(1 for e in events if "HIGH_CHURN" in e["status"])

    events.sort(key=lambda e: (-e["severity"], e["prefix"]))

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "RIPEstat (looking-glass, rpki-validation, bgp-updates, as-overview)",
        "watchlist_size": len(entries),
        "anomalies": anomalies,            # solo seguridad
        "churn_events": churn_events,      # informativo
        "signal": signal,                  # <-- consumido por el Risk Score (15%)
        "events": events,
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[ok] {len(events)} prefijos | anomalias_seg={anomalies} "
          f"churn={churn_events} signal={signal} -> {OUT}")


if __name__ == "__main__":
    main()
