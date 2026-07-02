#!/usr/bin/env python3
"""
NetPulse - Risk Score recomputation
===================================

Recomputes data/risk.json from already generated local JSON files:

  - data/kev.json         -> KEV score
  - data/kev.json         -> EPSS score
  - data/ransomware.json  -> Ransomware score
  - data/bgp.json         -> BGP score
  - data/noise.json       -> Internet Noise score
  - data/exposure.json    -> Exposure score

This script does not call external APIs. It only reads local JSON files
created by the other collectors.
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
NOISE_PATH = os.path.join(DATA_DIR, "noise.json")
EXPOSURE_PATH = os.path.join(DATA_DIR, "exposure.json")
OUT_PATH = os.path.join(DATA_DIR, "risk.json")

KEV_WINDOW_HOURS = 48
KEV_WINDOW_CAP = 8

RANSOMWARE_WINDOW_HOURS = 24
RANSOMWARE_WINDOW_CAP = 40

WEIGHTS = {
    "kev": 0.30,
    "epss": 0.25,
    "ransomware": 0.15,
    "bgp": 0.15,
    "noise": 0.075,
    "exposure": 0.075,
}


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[warn] could not read {path}: {e}", file=sys.stderr)
        return {}


def parse_dt(value):
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
    for item in items:
        d = parse_dt(item.get("dateAdded"))
        if d and d >= cutoff:
            recent.append(item)

    kev_score = min(100, round(len(recent) / KEV_WINDOW_CAP * 100))

    epss_values = [
        item.get("epss")
        for item in items
        if isinstance(item.get("epss"), (int, float))
    ]

    avg_epss = sum(epss_values) / len(epss_values) if epss_values else 0
    epss_score = min(100, round(avg_epss * 100, 2))

    return kev_score, epss_score, len(recent)


def ransomware_score_calc():
    ransomware = load(RANSOMWARE_PATH)
    items = ransomware.get("items", [])

    cutoff = datetime.now(timezone.utc) - timedelta(hours=RANSOMWARE_WINDOW_HOURS)

    recent = []
    for item in items:
        d = parse_dt(item.get("attackdate") or item.get("discovered"))
        if d and d >= cutoff:
            recent.append(item)

    score = min(100, round(len(recent) / RANSOMWARE_WINDOW_CAP * 100))

    return score, len(recent)


def bgp_score_calc():
    bgp = load(BGP_PATH)
    signal = bgp.get("signal")

    if not isinstance(signal, (int, float)):
        return 0, "bgp.json has no valid 'signal' field; collector may not have run yet"

    return min(100, round(signal)), None


def simple_signal_score(path, key="signal"):
    data = load(path)
    value = data.get(key)

    if not isinstance(value, (int, float)):
        return 0

    return min(100, round(value))


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
        n_score = simple_signal_score(NOISE_PATH)
        e_score = simple_signal_score(EXPOSURE_PATH)

        score = round(
            k_score * WEIGHTS["kev"]
            + epss_score * WEIGHTS["epss"]
            + rw_score * WEIGHTS["ransomware"]
            + b_score * WEIGHTS["bgp"]
            + n_score * WEIGHTS["noise"]
            + e_score * WEIGHTS["exposure"]
        )

        previous = load(OUT_PATH)
        previous_score = previous.get("score")

        delta = score - previous_score if isinstance(previous_score, (int, float)) else 0
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
                "noise_score": n_score,
                "exposure_score": e_score,
            },
            "weights": WEIGHTS,
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
        print(
            "[ok] risk score="
            f"{output['score']} ({output['label']}) "
            f"kev={output['components']['kev_score']} "
            f"epss={output['components']['epss_score']} "
            f"ransomware={output['components']['ransomware_score']} "
            f"bgp={output['components']['bgp_score']} "
            f"noise={output['components']['noise_score']} "
            f"exposure={output['components']['exposure_score']} "
            f"-> {OUT_PATH}"
        )
    else:
        print(f"[error] risk score unavailable: {output.get('error')}", file=sys.stderr)


if __name__ == "__main__":
    main()
