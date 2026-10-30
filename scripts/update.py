#!/usr/bin/env python3
"""Collecte CVE (NVD), CISA KEV, EPSS, flux RSS -> fichiers JSON dans data/.

Variables d'environnement (toutes optionnelles) :
  NVD_API_KEY          clé NVD (fortement conseillée : 10x plus rapide)
  DISCORD_WEBHOOK_URL  alertes Discord
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_TO   alertes mail
"""
import json
import os
import re
import smtplib
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html import unescape
from pathlib import Path

import feedparser
import requests

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
ARCHIVE = DATA / "archive"
CONFIG = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
UA = {"User-Agent": "veille-cyber-dashboard/1.0 (+personal watch)"}

HOT_DAYS = int(CONFIG.get("hot_days", 35))
NOW = datetime.now(timezone.utc)


# ---------- utilitaires ----------
def log(*a):
    print(*a, file=sys.stderr, flush=True)


def load(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def dump(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def parse_iso(s):
    s = s.replace("Z", "+00:00")
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def to_iso(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def nvd_ts(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def http_get(url, params=None, headers=None, tries=5):
    h = dict(UA)
    h.update(headers or {})
    for i in range(tries):
        try:
            r = requests.get(url, params=params, headers=h, timeout=60)
            if r.status_code in (403, 429, 500, 502, 503, 504):
                wait = 10 * (i + 1) + (20 if r.status_code in (403, 429) else 0)
                log(f"  HTTP {r.status_code} sur {url}, nouvelle tentative dans {wait}s")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            log(f"  erreur réseau ({e}), nouvelle tentative…")
            time.sleep(5 * (i + 1))
    raise RuntimeError(f"échec de la requête : {url}")


# ---------- NVD ----------
def nvd_fetch(kind, start, end):
    """kind = 'pub' (date de publication) ou 'lastMod' (date de modification)."""
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    delay = 0.8 if key else 6.5
    idx = 0
    while True:
        params = {
            f"{kind}StartDate": nvd_ts(start),
            f"{kind}EndDate": nvd_ts(end),
            "resultsPerPage": 2000,
            "startIndex": idx,
        }
        data = http_get(NVD_URL, params=params, headers=headers).json()
        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            yield v
        idx += len(vulns)
        if not vulns or idx >= data.get("totalResults", 0):
            break
        time.sleep(delay)
    time.sleep(delay)


def parse_cve(v):
    c = v["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    if desc.startswith("** REJECT **") or c.get("vulnStatus") == "Rejected":
        return None
    score = sev = vector = None
    metrics = c.get("metrics", {})
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(k):
            m = metrics[k][0]
            cd = m["cvssData"]
            score = cd.get("baseScore")
            sev = (cd.get("baseSeverity") or m.get("baseSeverity") or "").upper() or None
            vector = cd.get("vectorString")
            break
    cwe = []
    for w in c.get("weaknesses", []):
        for d in w.get("description", []):
            if d["value"].startswith("CWE-") and d["value"] not in cwe:
                cwe.append(d["value"])
    products = []
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = m["criteria"].split(":")
                if len(parts) > 4:
                    vp = f"{parts[3]}:{parts[4]}"
                    if vp not in products:
                        products.append(vp)
    refs = [r["url"] for r in c.get("references", [])[:5]]
    return {
        "id": c["id"],
        "published": to_iso(parse_iso(c["published"])),
        "modified": to_iso(parse_iso(c["lastModified"])),
        "desc": desc[:500],
        "score": score,
        "sev": sev,
        "vector": vector,
        "cwe": cwe[:3],
        "products": products[:8],
        "refs": refs,
        "status": c.get("vulnStatus"),
        "kev": False,
        "epss": None,
        "pct": None,
    }


def sync_cves(hot, meta):
    last = meta.get("last_nvd_sync")
    cutoff = NOW - timedelta(days=HOT_DAYS)
    if last:
        start, kind, span = parse_iso(last) - timedelta(hours=1), "lastMod", timedelta(days=100)
    else:
        start, kind, span = cutoff, "pub", timedelta(days=119)
    log(f"NVD : mode {kind} depuis {to_iso(start)}")
    cur, n = start, 0
    while cur < NOW:
        end = min(cur + span, NOW)
        for v in nvd_fetch(kind, cur, end):
            rec = parse_cve(v)
            cid = v["cve"]["id"]
            if rec is None:
                hot.pop(cid, None)
                continue
            old = hot.get(cid)
            if old is None and parse_iso(rec["published"]) < cutoff:
                continue
            if old:
                rec["kev"], rec["epss"], rec["pct"] = old.get("kev", False), old.get("epss"), old.get("pct")
            hot[cid] = rec
            n += 1
        cur = end
    log(f"NVD : {n} CVE ajoutées/mises à jour")
    meta["last_nvd_sync"] = to_iso(NOW)


def rotate_archive(hot):
    cutoff = NOW - timedelta(days=HOT_DAYS)
    by_month = {}
    for cid, rec in list(hot.items()):
        if parse_iso(rec["published"]) < cutoff:
            by_month.setdefault(rec["published"][:7], []).append(rec)
            del hot[cid]
    for month, items in by_month.items():
        path = ARCHIVE / f"{month}.json"
        cur = {r["id"]: r for r in load(path, [])}
        cur.update({r["id"]: r for r in items})
        dump(path, sorted(cur.values(), key=lambda r: r["published"], reverse=True))
    index = []
    if ARCHIVE.exists():
        for p in sorted(ARCHIVE.glob("*.json"), reverse=True):
            index.append({"month": p.stem, "count": len(load(p, []))})
    dump(DATA / "index.json", {"archives": index})


# ---------- CISA KEV ----------
def sync_kev():
    vulns = http_get(KEV_URL).json()["vulnerabilities"]
    ids = {v["cveID"] for v in vulns}
    prev = load(DATA / "kev.json", None)
    prev_ids = {e["cve"] for e in prev["items"]} if prev else None
    since = (NOW - timedelta(days=120)).strftime("%Y-%m-%d")
    items = []
    for v in vulns:
        if v["dateAdded"] >= since:
            items.append({
                "cve": v["cveID"],
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "added": v["dateAdded"],
                "due": v.get("dueDate", ""),
                "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                "action": (v.get("requiredAction") or "")[:220],
                "epss": None,
                "pct": None,
            })
    items.sort(key=lambda e: (e["added"], e["cve"]), reverse=True)
    new = [e for e in items if prev_ids is not None and e["cve"] not in prev_ids]
    log(f"KEV : {len(vulns)} entrées, {len(items)} récentes, {len(new)} nouvelles")
    return ids, items, new, len(vulns)


# ---------- EPSS ----------
def fetch_epss(cve_ids):
    out = {}
    ids = sorted(cve_ids)
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        try:
            r = http_get(EPSS_URL, params={"cve": ",".join(chunk)})
            for d in r.json().get("data", []):
                out[d["cve"]] = (float(d["epss"]), float(d["percentile"]))
        except Exception as e:  # noqa: BLE001
            log(f"EPSS : lot ignoré ({e})")
    return out


# ---------- actu ----------
TAG_RE = re.compile(r"<[^>]+>")


def clean(text, n=300):
    t = unescape(TAG_RE.sub(" ", text or ""))
    t = re.sub(r"\s+", " ", t).strip()
    return t if len(t) <= n else t[: n - 1].rsplit(" ", 1)[0] + "…"


def sync_news():
    path = DATA / "news.json"
    items = {i["link"]: i for i in load(path, {}).get("items", [])}
    added = 0
    for f in CONFIG.get("feeds", []):
        try:
            r = http_get(f["url"], tries=2)
            parsed = feedparser.parse(r.content)
        except Exception as e:  # noqa: BLE001
            log(f"Flux ignoré ({f['name']}) : {e}")
            continue
        for e in parsed.entries:
            link = e.get("link")
            if not link or link in items:
                continue
            t = e.get("published_parsed") or e.get("updated_parsed")
            pub = datetime(*t[:6], tzinfo=timezone.utc) if t else NOW
            items[link] = {
                "link": link,
                "title": clean(e.get("title", ""), 200),
                "summary": clean(e.get("summary", "")),
                "source": f["name"],
                "lang": f.get("lang", "en"),
                "published": to_iso(min(pub, NOW)),
            }
            added += 1
    cutoff = to_iso(NOW - timedelta(days=45))
    kept = [i for i in items.values() if i["published"] >= cutoff]
    kept.sort(key=lambda i: i["published"], reverse=True)
    dump(path, {"updated": to_iso(NOW), "sources": [f["name"] for f in CONFIG.get("feeds", [])], "items": kept[:2000]})
    log(f"Actu : {added} nouveaux articles, {len(kept)} conservés")
    return len(kept)


# ---------- alertes ----------
def haystack(rec):
    return (" ".join(rec["products"]) + " " + rec["desc"]).lower().replace("_", " ")


def watch_hit(rec, wl):
    h = haystack(rec)
    return next((w for w in wl if w in h), None)


def notify(title, lines):
    if not lines:
        return
    body = "\n".join(lines)
    hook = os.environ.get("DISCORD_WEBHOOK_URL")
    if hook:
        msg, chunks = f"**{title}**\n", []
        for ln in lines:
            if len(msg) + len(ln) + 1 > 1900:
                chunks.append(msg)
                msg = ""
            msg += ln + "\n"
        chunks.append(msg)
        for c in chunks:
            try:
                requests.post(hook, json={"content": c}, timeout=20)
                time.sleep(1)
            except requests.RequestException as e:
                log(f"Discord KO : {e}")
    host, to = os.environ.get("SMTP_HOST"), os.environ.get("MAIL_TO")
    if host and to:
        try:
            m = EmailMessage()
            m["Subject"], m["To"] = f"[Veille cyber] {title}", to
            m["From"] = os.environ.get("SMTP_USER", to)
            m.set_content(body)
            port = int(os.environ.get("SMTP_PORT", "587"))
            with smtplib.SMTP(host, port, timeout=30) as s:
                s.starttls(context=ssl.create_default_context())
                if os.environ.get("SMTP_USER"):
                    s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
                s.send_message(m)
        except Exception as e:  # noqa: BLE001
            log(f"Mail KO : {e}")


def run_alerts(hot, new_kev):
    cfg = CONFIG.get("alerts", {})
    wl = [w.lower() for w in CONFIG.get("watchlist", [])]
    path = DATA / "alerted.json"
    first_run = not path.exists()
    alerted = set(load(path, []))
    min_cvss = float(cfg.get("min_cvss", 7.0))
    hits = []
    for rec in sorted(hot.values(), key=lambda r: r["published"], reverse=True):
        if rec["id"] in alerted:
            continue
        w = watch_hit(rec, wl)
        if w and ((rec["score"] or 0) >= min_cvss or rec["kev"]):
            hits.append((rec, w))
    if first_run:
        log(f"Alertes : première exécution, {len(hits)} correspondances enregistrées sans notification")
    else:
        cap = int(cfg.get("max_per_run", 15))
        lines = []
        for rec, w in hits[:cap]:
            tag = " 🔥KEV" if rec["kev"] else ""
            score = f"{rec['score']} {rec['sev']}" if rec["score"] else "score en attente"
            lines.append(
                f"• {rec['id']} ({score}){tag} [{w}] {rec['desc'][:150]}\n  https://nvd.nist.gov/vuln/detail/{rec['id']}"
            )
        if len(hits) > cap:
            lines.append(f"… et {len(hits) - cap} autres.")
        notify(f"{len(hits)} CVE sur ta liste de surveillance", lines)
        if cfg.get("notify_kev", True) and new_kev:
            kl = [f"• {e['cve']} {e['vendor']} {e['product']} — {e['name']}\n  https://nvd.nist.gov/vuln/detail/{e['cve']}"
                  for e in new_kev[:cap]]
            notify(f"{len(new_kev)} nouvelle(s) vulnérabilité(s) exploitée(s) (CISA KEV)", kl)
    alerted.update(r["id"] for r, _ in hits)
    dump(path, sorted(alerted)[-5000:])


# ---------- main ----------
def main():
    DATA.mkdir(exist_ok=True)
    meta = load(DATA / "meta.json", {})
    hot = {r["id"]: r for r in load(DATA / "cves.json", [])}
    errors = []

    try:
        sync_cves(hot, meta)
    except Exception as e:  # noqa: BLE001
        errors.append(f"NVD: {e}")
        log(f"NVD en échec : {e}")

    kev_ids, kev_items, new_kev, kev_total = set(), [], [], meta.get("kev_total", 0)
    try:
        kev_ids, kev_items, new_kev, kev_total = sync_kev()
    except Exception as e:  # noqa: BLE001
        errors.append(f"KEV: {e}")
        log(f"KEV en échec : {e}")

    if kev_ids:
        for rec in hot.values():
            rec["kev"] = rec["id"] in kev_ids

    recent = NOW - timedelta(days=14)
    need = {r["id"] for r in hot.values() if r["epss"] is None or parse_iso(r["published"]) >= recent}
    need |= {e["cve"] for e in kev_items}
    epss = fetch_epss(need)
    for rec in hot.values():
        if rec["id"] in epss:
            rec["epss"], rec["pct"] = epss[rec["id"]]
    for e in kev_items:
        if e["cve"] in epss:
            e["epss"], e["pct"] = epss[e["cve"]]

    rotate_archive(hot)
    cves = sorted(hot.values(), key=lambda r: r["published"], reverse=True)
    dump(DATA / "cves.json", cves)
    if kev_items:
        dump(DATA / "kev.json", {"updated": to_iso(NOW), "total": kev_total, "items": kev_items})

    news_count = 0
    try:
        news_count = sync_news()
    except Exception as e:  # noqa: BLE001
        errors.append(f"RSS: {e}")

    try:
        run_alerts(hot, new_kev)
    except Exception as e:  # noqa: BLE001
        errors.append(f"alertes: {e}")
        log(f"Alertes en échec : {e}")

    meta.update({
        "generated_at": to_iso(NOW),
        "cves_hot": len(cves),
        "news": news_count,
        "kev_total": kev_total,
        "hot_days": HOT_DAYS,
        "errors": errors,
    })
    dump(DATA / "meta.json", meta)
    log("Terminé." + (f" Erreurs : {errors}" if errors else ""))


if __name__ == "__main__":
    main()
