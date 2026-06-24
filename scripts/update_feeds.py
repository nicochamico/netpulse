import json
import os
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

NOW = datetime.now(timezone.utc)
NOW_ISO = NOW.isoformat()

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

EPSS_API = "https://api.first.org/data/v1/epss"

RANSOMWARE_URLS = [
    "https://api.ransomware.live/v2/recentvictims",
    "https://api.ransomware.live/v2/victims/recent"
]

RSS_FEEDS = [
    {
        "source": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews"
    },
    {
        "source": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/"
    },
    {
        "source": "KrebsOnSecurity",
        "url": "https://krebsonsecurity.com/feed/"
    }
]


def fetch_text(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "NetPulseBot/1.0"}
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read().decode("utf-8", errors="replace")


def fetch_json(url):
    return json.loads(fetch_text(url))


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def safe_float(value):
    try:
        return float(value)
    except Exception:
        return None


def update_kev():
    try:
        data = fetch_json(KEV_URL)
        vulns = data.get("vulnerabilities", [])

        latest = sorted(
            vulns,
            key=lambda x: x.get("dateAdded", ""),
            reverse=True
        )[:10]

        cves = [v.get("cveID") for v in latest if v.get("cveID")]
        epss_map = fetch_epss(cves)

        enriched = []
        for v in latest:
            cve = v.get("cveID")
            epss = epss_map.get(cve, {})

            item = dict(v)
            item["epss"] = epss.get("epss")
            item["epss_percentile"] = epss.get("percentile")
            enriched.append(item)

        output = {
            "source": "CISA KEV + FIRST EPSS",
            "status": "fresh",
            "last_success": NOW_ISO,
            "count": len(vulns),
            "items": enriched
        }

    except Exception as e:
        output = {
            "source": "CISA KEV + FIRST EPSS",
            "status": "unavailable",
            "last_success": None,
            "error": str(e),
            "count": None,
            "items": []
        }

    save_json(f"{DATA_DIR}/kev.json", output)


def fetch_epss(cves):
    result = {}

    if not cves:
        return result

    try:
        query = urllib.parse.urlencode({"cve": ",".join(cves)})
        data = fetch_json(f"{EPSS_API}?{query}")

        for row in data.get("data", []):
            cve = row.get("cve")
            result[cve] = {
                "epss": safe_float(row.get("epss")),
                "percentile": safe_float(row.get("percentile"))
            }

    except Exception:
        for cve in cves:
            try:
                query = urllib.parse.urlencode({"cve": cve})
                data = fetch_json(f"{EPSS_API}?{query}")
                rows = data.get("data", [])

                if rows:
                    row = rows[0]
                    result[cve] = {
                        "epss": safe_float(row.get("epss")),
                        "percentile": safe_float(row.get("percentile"))
                    }
            except Exception:
                pass

    return result


def update_news():
    all_items = []

    for feed in RSS_FEEDS:
        try:
            raw = fetch_text(feed["url"])
            root = ET.fromstring(raw)

            for item in root.findall(".//item")[:6]:
                title = item.findtext("title", "").strip()
                link = item.findtext("link", "").strip()
                pub_date = item.findtext("pubDate", "").strip()

                if title:
                    all_items.append({
                        "source": feed["source"],
                        "title": title,
                        "link": link,
                        "published": pub_date
                    })

        except Exception as e:
            all_items.append({
                "source": feed["source"],
                "title": "Feed temporarily unavailable",
                "link": "#",
                "published": "",
                "error": str(e)
            })

    output = {
        "source": "Cybersecurity RSS",
        "status": "fresh" if all_items else "unavailable",
        "last_success": NOW_ISO if all_items else None,
        "items": all_items[:12]
    }

    save_json(f"{DATA_DIR}/news.json", output)


def update_ransomware():
    last_error = None

    for url in RANSOMWARE_URLS:
        try:
            data = fetch_json(url)

            victims = data
            if isinstance(data, dict):
                victims = (
                    data.get("victims")
                    or data.get("data")
                    or data.get("results")
                    or []
                )

            if not isinstance(victims, list):
                victims = []

            output = {
                "source": "ransomware.live",
                "status": "fresh",
                "last_success": NOW_ISO,
                "count": len(victims),
                "items": victims[:20]
            }

            save_json(f"{DATA_DIR}/ransomware.json", output)
            return

        except Exception as e:
            last_error = str(e)

    output = {
        "source": "ransomware.live",
        "status": "unavailable",
        "last_success": None,
        "error": last_error,
        "count": None,
        "items": []
    }

    save_json(f"{DATA_DIR}/ransomware.json", output)


def update_bgp():
    output = {
        "source": "NetPulse BGP connector",
        "status": "unavailable",
        "last_success": None,
        "count": None,
        "items": [],
        "note": "BGP connector pending. Connect this to the NetPulse/BGP Incident Analyzer pipeline."
    }

   # save_json(f"{DATA_DIR}/bgp.json", output)


def update_indicators():
    indicators = {
        "source": "NetPulse indicators",
        "status": "partial",
        "last_success": NOW_ISO,
        "internet_noise": None,
        "exposed_systems": None,
        "note": "Internet Noise and Exposure require a reliable external data source or internal collector."
    }

    save_json(f"{DATA_DIR}/indicators.json", indicators)


def calculate_risk_score():
    try:
        kev = json.load(open(f"{DATA_DIR}/kev.json", encoding="utf-8"))
        ransomware = json.load(open(f"{DATA_DIR}/ransomware.json", encoding="utf-8"))
        bgp = json.load(open(f"{DATA_DIR}/bgp.json", encoding="utf-8"))

        kev_items = kev.get("items", [])
        ransomware_count = ransomware.get("count") or 0
        bgp_count = bgp.get("count") or 0

        avg_epss = 0
        epss_values = [
            item.get("epss")
            for item in kev_items
            if isinstance(item.get("epss"), (int, float))
        ]

        if epss_values:
            avg_epss = sum(epss_values) / len(epss_values)

        kev_score = min(100, len(kev_items) * 10)
        epss_score = min(100, avg_epss * 100)
        ransomware_score = min(100, ransomware_count)
        bgp_score = min(100, bgp_count * 2)

        score = round(
            kev_score * 0.35 +
            epss_score * 0.30 +
            ransomware_score * 0.20 +
            bgp_score * 0.15
        )

        if score >= 70:
            label = "HIGH RISK"
        elif score >= 40:
            label = "MEDIUM RISK"
        else:
            label = "LOW RISK"

        output = {
            "source": "NetPulse calculated risk score",
            "status": "partial_live",
            "last_success": NOW_ISO,
            "score": score,
            "label": label,
            "trend": "+0",
            "components": {
                "kev_score": kev_score,
                "epss_score": round(epss_score, 2),
                "ransomware_score": ransomware_score,
                "bgp_score": bgp_score
            }
        }

    except Exception as e:
        output = {
            "source": "NetPulse calculated risk score",
            "status": "unavailable",
            "last_success": None,
            "error": str(e),
            "score": None,
            "label": "UNAVAILABLE",
            "trend": "0"
        }

    save_json(f"{DATA_DIR}/risk.json", output)


if __name__ == "__main__":
    update_kev()
    update_news()
    update_ransomware()
    update_bgp()
    update_indicators()
    calculate_risk_score()
