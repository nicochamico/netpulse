import json
import os
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

NOW = datetime.now(timezone.utc).isoformat()

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

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
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", errors="replace")


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def update_kev():
    try:
        raw = fetch_text(KEV_URL)
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", [])

        latest = sorted(
            vulns,
            key=lambda x: x.get("dateAdded", ""),
            reverse=True
        )[:10]

        output = {
            "source": "CISA KEV",
            "status": "fresh",
            "last_success": NOW,
            "count": len(vulns),
            "items": latest
        }

    except Exception as e:
        output = {
            "source": "CISA KEV",
            "status": "unavailable",
            "last_success": None,
            "error": str(e),
            "count": None,
            "items": []
        }

    save_json(f"{DATA_DIR}/kev.json", output)


def update_news():
    all_items = []

    for feed in RSS_FEEDS:
        try:
            raw = fetch_text(feed["url"])
            root = ET.fromstring(raw)

            for item in root.findall(".//item")[:5]:
                title = item.findtext("title", "").strip()
                link = item.findtext("link", "").strip()
                pub_date = item.findtext("pubDate", "").strip()

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
        "status": "fresh",
        "last_success": NOW,
        "items": all_items[:10]
    }

    save_json(f"{DATA_DIR}/news.json", output)


def update_demo_indicators():
    risk = {
        "status": "demo",
        "score": 68,
        "label": "HIGH RISK",
        "trend": "+8",
        "last_success": NOW
    }

    bgp = {
        "status": "demo",
        "count": 27,
        "items": [
            {"type": "Possible Hijack", "asn": "AS135377", "time": "10:15"},
            {"type": "Prefix Leak", "asn": "AS2914", "time": "09:42"},
            {"type": "More Specifics", "asn": "AS12389", "time": "08:33"},
            {"type": "Invalid Origin", "asn": "AS4766", "time": "06:55"}
        ]
    }

    indicators = {
        "status": "demo",
        "internet_noise": "7.8M",
        "exposed_systems": 65,
        "ransomware_victims": 136
    }

    save_json(f"{DATA_DIR}/risk.json", risk)
    save_json(f"{DATA_DIR}/bgp.json", bgp)
    save_json(f"{DATA_DIR}/indicators.json", indicators)


if __name__ == "__main__":
    update_kev()
    update_news()
    update_demo_indicators()
