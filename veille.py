#!/usr/bin/env python3
"""Veille cyber : collecte CVE (NVD) + CISA KEV + EPSS + flux RSS, historique JSON,
génération d'un dashboard statique dans docs/index.html.

Usage :
    python veille.py            # collecte + génération
    python veille.py --render   # régénère seulement la page depuis data/
    python veille.py --demo     # données fictives pour tester le rendu (sans réseau)

Variables d'environnement optionnelles :
    NVD_API_KEY      clé NVD (gratuite) -> 10x moins de limitation
    NTFY_TOPIC       topic ntfy.sh pour recevoir les alertes sur le téléphone
    DISCORD_WEBHOOK  URL de webhook Discord pour les alertes
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parent
DATA = ROOT / "data"
DOCS = ROOT / "docs"
CFG = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
UA = {"User-Agent": "veille-cyber/1.0 (+personal watch dashboard)"}

NOW = datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def load(name: str, default):
    p = DATA / name
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"! {name} illisible, on repart de zéro", file=sys.stderr)
    return default


def save(name: str, obj) -> None:
    DATA.mkdir(exist_ok=True)
    (DATA / name).write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")


# --------------------------------------------------------------------------- CVE
def parse_nvd(item: dict) -> dict:
    c = item["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    score, sev, vector = None, None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if c.get("metrics", {}).get(key):
            m = c["metrics"][key][0]["cvssData"]
            score, sev, vector = m.get("baseScore"), m.get("baseSeverity"), m.get("vectorString")
            break
    cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                   if d["value"].startswith("CWE-")})
    vendors = set()
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    vendors.add(f"{parts[3]} {parts[4]}".replace("_", " "))
    return {
        "id": c["id"],
        "published": c["published"],
        "modified": c["lastModified"],
        "desc": desc,
        "cvss": score,
        "sev": (sev or "").upper() or None,
        "vector": vector,
        "cwe": cwes,
        "products": sorted(vendors)[:6],
        "refs": [r["url"] for r in c.get("references", [])[:3]],
        "kev": False,
        "epss": None,
    }


def get_json(session, url, headers=None, params=None, tries=6):
    """GET avec retry/backoff (NVD renvoie souvent 403/429/503 quand il est chargé)."""
    for i in range(tries):
        try:
            r = session.get(url, headers=headers, params=params, timeout=(10, 90))
            if r.status_code in (403, 429, 502, 503, 504):
                raise RuntimeError(f"HTTP {r.status_code}")
            r.raise_for_status()
            return r.json()
        except Exception as e:  # noqa: BLE001
            wait = min(15 * 2 ** i, 120)
            print(f"  ! {e} -> nouvel essai dans {wait}s ({i + 1}/{tries})", flush=True)
            if i == tries - 1:
                raise
            time.sleep(wait)


def fetch_nvd_pages(session, since: datetime, field: str = "pub"):
    """Générateur : renvoie une liste de CVE par page (permet de sauvegarder au fil de l'eau)."""
    key = os.environ.get("NVD_API_KEY")
    headers = dict(UA, **({"apiKey": key} if key else {}))
    pause = 1.0 if key else 6.5  # 50 req/30 s avec clé, 5 sans
    print(f"NVD : {'clé API détectée' if key else 'SANS clé (lent)'}", flush=True)
    window_start = since
    while window_start < NOW:
        window_end = min(window_start + timedelta(days=110), NOW)  # fenêtre max 120 j
        start, page = 0, 0
        while True:
            j = get_json(session, NVD_URL, headers, {
                f"{field}StartDate": iso(window_start), f"{field}EndDate": iso(window_end),
                "startIndex": start, "resultsPerPage": 500})
            items = [parse_nvd(v) for v in j.get("vulnerabilities", [])]
            total, page = j.get("totalResults", 0), page + 1
            start += len(items)
            print(f"  NVD page {page} : {start}/{total}", flush=True)
            yield items
            if not items or start >= total:
                break
            time.sleep(pause)
        window_start = window_end
        time.sleep(pause)


def fetch_kev(session) -> dict[str, dict]:
    r = session.get(KEV_URL, headers=UA, timeout=60)
    r.raise_for_status()
    return {v["cveID"]: v for v in r.json().get("vulnerabilities", [])}


def fetch_epss(session, ids: list[str]) -> dict[str, float]:
    out = {}
    for i in range(0, len(ids), 80):
        chunk = ids[i:i + 80]
        r = session.get(EPSS_URL, headers=UA, timeout=60, params={"cve": ",".join(chunk)})
        if r.ok:
            for row in r.json().get("data", []):
                out[row["cve"]] = float(row["epss"])
    return out


def is_watch(cve: dict) -> list[str]:
    hay = (cve["desc"] + " " + " ".join(cve["products"])).lower()
    return [w for w in CFG["watchlist"] if w.lower() in hay]


def update_cves(session) -> tuple[dict, list[dict]]:
    db: dict = load("cves.json", {})
    first_run = not db
    days = CFG.get("backfill_days", 7) if first_run else 3  # 1er passage court, puis incrémental
    since = NOW - timedelta(days=days)
    cutoff = (NOW - timedelta(days=CFG.get("hot_days", 35))).strftime("%Y-%m-%dT%H:%M:%S")
    new_ids = []
    try:
        # 1er passage : par date de publication ; ensuite par date de modification (récupère
        # les scores CVSS ajoutés après coup), en ignorant les vieilles CVE hors historique.
        for page in fetch_nvd_pages(session, since, "pub" if first_run else "lastMod"):
            for c in page:
                if c["id"] not in db and c["published"] < cutoff:
                    continue
                if c["id"] not in db:
                    new_ids.append(c["id"])
                old = db.get(c["id"], {})
                c["kev"], c["epss"] = old.get("kev", False), old.get("epss")
                db[c["id"]] = c
            save("cves.json", db)  # sauvegarde à chaque page
    except Exception as e:  # noqa: BLE001
        print("! NVD interrompu, on garde ce qui est déjà récupéré :", e, file=sys.stderr, flush=True)

    # KEV : on marque tout l'historique (un vieux CVE peut entrer dans KEV plus tard)
    kev = {}
    try:
        kev = fetch_kev(session)
    except Exception as e:  # noqa: BLE001
        print("! KEV indisponible:", e, file=sys.stderr)
    newly_kev = []
    for cid, k in kev.items():
        if cid in db:
            if not db[cid]["kev"]:
                newly_kev.append(db[cid])
            db[cid]["kev"] = True
            db[cid]["kev_added"] = k.get("dateAdded")
            db[cid]["kev_ransom"] = k.get("knownRansomwareCampaignUse") == "Known"
            db[cid]["kev_name"] = k.get("vulnerabilityName")

    # EPSS : sur la fenêtre "chaude" uniquement
    hot_cut = (NOW - timedelta(days=CFG.get("hot_days", 35))).isoformat()
    hot = [i for i, c in db.items() if c["published"] >= hot_cut[:19]]
    try:
        for cid, v in fetch_epss(session, hot).items():
            db[cid]["epss"] = v
    except Exception as e:  # noqa: BLE001
        print("! EPSS indisponible:", e, file=sys.stderr)

    alerts = [db[i] for i in new_ids if is_alert(db[i])] + newly_kev
    return db, alerts


def is_alert(c: dict) -> bool:
    a = CFG["alerts"]
    return bool(c.get("kev") and a.get("notify_kev")) or (c.get("cvss") or 0) >= a["min_cvss"] and bool(is_watch(c))


# --------------------------------------------------------------------------- NEWS
def clean(txt: str, n: int = 260) -> str:
    txt = re.sub(r"<[^>]+>", " ", txt or "")
    txt = re.sub(r"\s+", " ", html.unescape(txt)).strip()
    return txt if len(txt) <= n else txt[: n - 1].rsplit(" ", 1)[0] + "…"


def update_news() -> dict:
    import feedparser

    db: dict = load("news.json", {})
    for f in CFG["feeds"]:
        try:
            import requests
            resp = requests.get(f["url"], headers=UA, timeout=20)
            resp.raise_for_status()
            d = feedparser.parse(resp.content)
        except Exception as e:  # noqa: BLE001
            print(f"! {f['name']}: {e}", file=sys.stderr)
            continue
        if d.bozo and not d.entries:
            print(f"! {f['name']}: flux vide/invalide", file=sys.stderr)
            continue
        for e in d.entries:
            link = e.get("link")
            if not link or link in db:
                continue
            t = e.get("published_parsed") or e.get("updated_parsed")
            dt = datetime(*t[:6], tzinfo=timezone.utc) if t else NOW
            db[link] = {"title": clean(e.get("title", ""), 200), "url": link,
                        "source": f["name"], "lang": f["lang"],
                        "date": dt.isoformat(timespec="seconds"),
                        "summary": clean(e.get("summary", ""))}
    return db


# --------------------------------------------------------------------------- NOTIFS
def notify(alerts: list[dict]) -> None:
    if not alerts:
        return
    alerts = sorted(alerts, key=lambda c: (not c.get("kev"), -(c.get("cvss") or 0)))
    alerts = alerts[: CFG["alerts"]["max_per_run"]]
    lines = [f"{'🔥KEV ' if c.get('kev') else ''}{c['id']} (CVSS {c.get('cvss') or '?'}) "
             f"{', '.join(is_watch(c)[:2])} – {c['desc'][:90]}" for c in alerts]
    body = "\n".join(lines)
    import requests
    if os.environ.get("NTFY_TOPIC"):
        requests.post(f"https://ntfy.sh/{os.environ['NTFY_TOPIC']}", timeout=20,
                      data=body.encode("utf-8"), headers={"Title": "Veille cyber : alertes"})
    if os.environ.get("DISCORD_WEBHOOK"):
        requests.post(os.environ["DISCORD_WEBHOOK"], timeout=20, json={"content": body[:1900]})


# --------------------------------------------------------------------------- RENDER
def render(cves: dict, news: dict) -> None:
    DOCS.mkdir(exist_ok=True)
    keep_news = (NOW - timedelta(days=120)).isoformat()
    payload = {
        "generated": NOW.isoformat(timespec="seconds"),
        "watchlist": CFG["watchlist"],
        "min_cvss": CFG["alerts"]["min_cvss"],
        "cves": sorted(cves.values(), key=lambda c: c["published"], reverse=True),
        "news": sorted((n for n in news.values() if n["date"] >= keep_news),
                       key=lambda n: n["date"], reverse=True),
    }
    tpl = (ROOT / "template.html").read_text(encoding="utf-8")
    data = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    (DOCS / "index.html").write_text(tpl.replace("/*__DATA__*/null", data), encoding="utf-8")
    print(f"✓ docs/index.html : {len(payload['cves'])} CVE, {len(payload['news'])} articles")


# --------------------------------------------------------------------------- DEMO
def demo() -> tuple[dict, dict]:
    import random
    random.seed(7)
    vendors = ["fortinet fortios", "palo alto pan-os", "citrix netscaler", "ivanti connect secure",
               "cisco ios xe", "vmware esxi", "openssh openssh", "wordpress wp", "linux linux kernel",
               "apache http server", "nginx nginx", "okta verify", "acme widget", "foo bar"]
    kinds = ["Remote code execution", "Authentication bypass", "SQL injection", "Path traversal",
             "Privilege escalation", "Cross-site scripting", "Denial of service", "SSRF"]
    cves = {}
    for i in range(420):
        age = random.random() ** 1.6 * 34
        pub = NOW - timedelta(days=age, hours=random.random() * 5)
        cvss = random.choice([None, 3.1, 4.3, 5.4, 6.5, 7.2, 7.5, 8.1, 8.8, 9.1, 9.8, 10.0])
        sev = None if cvss is None else "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"
        v = random.choice(vendors)
        cid = f"CVE-2026-{20000 + i * 7}"
        cves[cid] = {"id": cid, "published": pub.strftime("%Y-%m-%dT%H:%M:%S.000"),
                     "modified": pub.strftime("%Y-%m-%dT%H:%M:%S.000"),
                     "desc": f"{random.choice(kinds)} in {v.title()} allows a remote attacker to compromise the affected system via crafted requests.",
                     "cvss": cvss, "sev": sev, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                     "cwe": [random.choice(["CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-287"])],
                     "products": [v], "refs": ["https://nvd.nist.gov/vuln/detail/" + cid],
                     "kev": cvss is not None and cvss >= 9 and random.random() < .12,
                     "epss": round(random.random() ** 3, 4)}
        if cves[cid]["kev"]:
            cves[cid].update(kev_added=pub.strftime("%Y-%m-%d"), kev_ransom=random.random() < .3,
                             kev_name="Démo " + v)
    srcs = [f for f in CFG["feeds"]]
    titles = ["Un groupe de ransomware revendique l'attaque d'un hôpital", "Nouvelle campagne de phishing ciblant Microsoft 365",
              "Zero-day exploité dans un VPN d'entreprise", "Fuite de données massive chez un opérateur télécom",
              "Patch Tuesday : 90 failles corrigées", "Un botnet IoT dépasse 100 000 appareils"]
    news = {}
    for i in range(80):
        s = random.choice(srcs)
        d = NOW - timedelta(hours=random.random() * 24 * 20)
        news[f"https://example.org/{i}"] = {"title": random.choice(titles) + f" ({i})", "url": "https://example.org",
                                            "source": s["name"], "lang": s["lang"], "date": d.isoformat(timespec="seconds"),
                                            "summary": "Résumé de démonstration de l'article, uniquement pour valider le rendu."}
    return cves, news


# --------------------------------------------------------------------------- MAIN
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--render", action="store_true")
    ap.add_argument("--demo", action="store_true")
    a = ap.parse_args()

    if a.demo:
        render(*demo())
        return
    if a.render:
        render(load("cves.json", {}), load("news.json", {}))
        return

    import requests
    s = requests.Session()
    try:
        cves, alerts = update_cves(s)
        save("cves.json", cves)
        notify(alerts)
    except Exception as e:  # noqa: BLE001
        print("! CVE: échec de collecte :", e, file=sys.stderr)
        cves = load("cves.json", {})
    news = update_news()
    save("news.json", news)
    render(cves, news)


if __name__ == "__main__":
    main()
