#!/usr/bin/env python3
"""
NetPulse - Risk Score recomputation
====================================
Recalcula data/risk.json combinando las señales YA generadas por los otros
collectors (no vuelve a llamar APIs externas, solo lee JSON local):

  - data/kev.json         -> KEV score        (35%)
  - data/kev.json (epss)  -> EPSS score        (30%)
  - data/ransomware.json  -> Ransomware score  (20%)
  - data/bgp.json         -> BGP score         (15%)

Pensado para correr DESPUES de bgp_collector.py en connectors.yml (cada
15 min), para que el 15% de BGP refleje anomalias casi en tiempo real
en vez de esperar al ciclo horario de scripts/update_feeds.py.

Fixes respecto a la version anterior (calculate_risk_score() en
scripts/update_feeds.py):

  1. bgp_score ahora usa directamente bgp.json['signal'] (0-100, ya
     normalizado por bgp_collector.py: solo cuenta MOAS / ORIGIN_CHANGE /
     RPKI_INVALID / WITHDRAWN, HIGH_CHURN es informativo y no infla el
     score). La version anterior leia bgp.json['count'], una key que
     nunca existio en el archivo -> bgp_score daba 0 siempre.

  2. kev_score y ransomware_score ya NO se basan en el tamano total del
     catalogo/lista (que satura en 100 casi cualquier dia: el catalogo
     KEV completo ya supera las 1000 entradas, y el endpoint de
     ransomware.live siempre trae ~100 victimas recientes). Ahora se
     basan en cuantos items NUEVOS aparecieron en una ventana reciente:
       - KEV: dateAdded dentro de las ultimas KEV_WINDOW_HOURS
       - Ransomware: attackdate dentro de las ultimas RANSOMWARE_WINDOW_HOURS
     Asi el score realmente sube y baja con la actividad del dia, en vez
     de quedar pegado arriba de ~65-70 todo el tiempo.

  Limitacion conocida: data/kev.json y data/ransomware.json solo guardan
  los 10 y 20 items mas recientes respectivamente (no el catalogo/lista
  completa), asi que en dias con actividad MUY alta el conteo de "items
  nuevos" puede subestimarse (satura en el tamano de la muestra guardada).
  Si esto importa para el caso de uso, subir cuantos items guarda
  scripts/update_feeds.py (update_kev / update_ransomware) antes que
  subir los caps de aca.
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "..", "data")

KEV_PATH = os.path.join(DATA_DIR, "kev.json")
RANSOMWARE_PATH = os.path.join(DATA_DIR, "ransomware.json")
BGP_PATH = os.path.join(DATA_DIR, "bgp.json")
OUT_PATH = os.path.join(DATA_DIR, "risk.json")

# Ventanas de tiempo para medir actividad RECIENTE (no tamano total del feed)
KEV_WINDOW_HOURS = 48
KEV_WINDOW_CAP = 8            # 8+ CVEs KEV nuevos en 48h -> kev_score = 100

RANSOMWARE_WINDOW_HOURS = 24
RANSOMWARE_WINDOW_CAP = 40    # 15+ victimas nuevas en 24h -> ransomware_score = 100

WEIGHTS = {"kev": 0.35, "epss": 0.30, "ransomware": 0.20, "bgp": 0.15}


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"  [warn] no se pudo leer {path}: {e}", file=sys.stderr)
        return {}


def parse_dt(value):
    """Admite 'YYYY-MM-DD' (KEV) y 'YYYY-MM-DDTHH:MM:SS+00:00' (ransomware)."""
    if not value:
        return None
    try:
        v = str(value).replace("Z", "+00:00")
        d = datetime.fromisoformat(v)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    except Exception:
        return None


def kev_scores():
    kev = load(KEV_PATH)
    items = kev.get("items", [])
    cutoff = datetime.now(timezone.utc) - timedelta(hours=KEV_WINDOW_HOURS)

    recent = []
    for v in items:
        d = parse_dt(v.get("dateAdded"))
        if d and d >= cutoff:
            recent.append(v)

    kev_score = min(100, round(len(recent) / KEV_WINDOW_CAP * 100)) if KEV_WINDOW_CAP else 0

    epss_values = [v.get("epss") for v in items if isinstance(v.get("epss"), (int, float))]
    avg_epss = (sum(epss_values) / len(epss_values)) if epss_values else 0
    epss_score = min(100, round(avg_epss * 100, 2))

    return kev_score, epss_score, len(recent)


def ransomware_score_calc():
    r = load(RANSOMWARE_PATH)
    items = r.get("items", [])
    cutoff = datetime.now(timezone.utc) - timedelta(hours=RANSOMWARE_WINDOW_HOURS)

    recent = []
    for v in items:
        d = parse_dt(v.get("attackdate") or v.get("discovered"))
        if d and d >= cutoff:
            recent.append(v)

    score = min(100, round(len(recent) / RANSOMWARE_WINDOW_CAP * 100)) if RANSOMWARE_WINDOW_CAP else 0
    return score, len(recent)


def bgp_score_calc():
    bgp = load(BGP_PATH)
    signal = bgp.get("signal")
    if not isinstance(signal, (int, float)):
        return 0, "bgp.json sin 'signal' valido (collector no corrio aun?)"
    return min(100, round(signal)), None


def label_for(score):
    if score >= 70:
        return "HIGH RISK"
    if score >= 40:
        return "MEDIUM RISK"
    return "LOW RISK"


def main():
    try:
        k_score, epss_score, kev_recent_n = kev_scores()
        rw_score, rw_recent_n = ransomware_score_calc()
        b_score, b_note = bgp_score_calc()

        score = round(
            k_score * WEIGHTS["kev"]
            + epss_score * WEIGHTS["epss"]
            + rw_score * WEIGHTS["ransomware"]
            + b_score * WEIGHTS["bgp"]
        )

        prev = load(OUT_PATH)
        prev_score = prev.get("score")
        delta = (score - prev_score) if isinstance(prev_score, (int, float)) else 0
        trend = f"+{delta}" if delta >= 0 else str(delta)

        output = {
            "source": "NetPulse calculated risk score",
            "status": "live",
            "last_success": datetime.now(timezone.utc).isoformat(),
            "score": score,
            "label": label_for(score),
            "trend": trend,
            "components": {
                "kev_score": k_score,
                "epss_score": epss_score,
                "ransomware_score": rw_score,
                "bgp_score": b_score,
            },
            "window": {
                "kev_new_items_48h": kev_recent_n,
                "ransomware_new_victims_24h": rw_recent_n,
            },
        }
        if b_note:
            output["notes"] = b_note

    except Exception as e:
        output = {
            "source": "NetPulse calculated risk score",
            "status": "unavailable",
            "last_success": None,
            "error": str(e),
            "score": None,
            "label": "UNAVAILABLE",
            "trend": "0",
        }

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    if output["status"] == "live":
        print(f"[ok] risk score={output['score']} ({output['label']}) "
              f"kev={output['components']['kev_score']} "
              f"epss={output['components']['epss_score']} "
              f"ransomware={output['components']['ransomware_score']} "
              f"bgp={output['components']['bgp_score']} -> {OUT_PATH}")
    else:
        print(f"[error] risk score unavailable: {output.get('error')}", file=sys.stderr)


if __name__ == "__main__":
    main()
