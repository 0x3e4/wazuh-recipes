#!/usr/bin/env python3
"""
Antivirus detection email digest for Wazuh (Windows Defender + ClamAV).

Reads malware/tamper detections from the Wazuh Indexer and emails a notify-once HTML ticket
per NEW detection (SQLite dedup, with an explicit seeded_at marker) -- the same pattern as
the vuln-email-digest / entra-config-changes recipes. Runs on a systemd timer.

Scope is chosen with AV_SOURCE (env) / --source: defender | clamav | both.

Deps: Python 3.8+, stdlib + opensearch-py (falls back to the ES 7.x client).
Secrets (INDEX_PASSWORD) come from the environment, never the command line.
"""
import argparse
import html
import os
import smtplib
import sqlite3
import sys
from datetime import datetime, timezone
from email.message import EmailMessage

# ---- config (env, overridable by flags) ------------------------------------
INDEX_URL      = os.environ.get("INDEX_URL", "https://127.0.0.1:9200")
INDEX_USER     = os.environ.get("INDEX_USER", "admin")
INDEX_PASSWORD = os.environ.get("INDEX_PASSWORD", "")
INDEX_PATTERN  = os.environ.get("INDEX_PATTERN", "wazuh-alerts-4.x-*")
CA             = os.environ.get("CA", "/etc/wazuh-indexer/certs/root-ca.pem")
NO_VERIFY      = os.environ.get("NO_VERIFY", "0") == "1"
INDEX_CLIENT_CERT = os.environ.get("INDEX_CLIENT_CERT", "")
INDEX_CLIENT_KEY  = os.environ.get("INDEX_CLIENT_KEY", "")

SMTP_SERVER    = os.environ.get("SMTP_SERVER", "smtp.example.com")
SMTP_PORT      = int(os.environ.get("SMTP_PORT", "25"))
MAIL_FROM      = os.environ.get("MAIL_FROM", "wazuh@example.com")
RECIPIENTS     = [r.strip() for r in os.environ.get("RECIPIENTS", "").split(",") if r.strip()]
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "")

AV_SOURCE      = os.environ.get("AV_SOURCE", "both").lower()   # defender | clamav | both
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "24"))
STATE_DB       = os.environ.get("STATE_DB", "/opt/antivirus-mail/state.db")

FONT = "font-family:Segoe UI,Arial,sans-serif;"

# Detection rules per source. Defender detections are enriched into 100901 (which supersedes
# stock 62113/62122/62123); tamper = defender_tamper group. ClamAV = 100931/100932 (+ stock 52502).
_DEFENDER_IDS = ["100901", "100902", "100906", "100907", "100912", "62113", "62122", "62123", "62126"]
_CLAMAV_IDS   = ["100931", "100932", "52502"]


def _filter(source):
    should = []
    if source in ("defender", "both"):
        should.append({"terms": {"rule.id": _DEFENDER_IDS}})
        should.append({"term": {"rule.groups": "defender_tamper"}})
    if source in ("clamav", "both"):
        should.append({"terms": {"rule.id": _CLAMAV_IDS}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


# ---- indexer client (same shape as the other digest recipes) ---------------
def _get_client(url, user, password, verify, client_cert=None, client_key=None):
    auth = {}
    if client_cert:
        auth["client_cert"] = client_cert
        if client_key:
            auth["client_key"] = client_key
    if password:
        auth["http_auth"] = (user, password)
    common = dict(verify_certs=bool(verify), ca_certs=verify or None, timeout=30)
    try:
        from opensearchpy import OpenSearch
        return OpenSearch(url, ssl_show_warn=False, **common, **auth)
    except ImportError:
        pass
    try:
        from elasticsearch import Elasticsearch
        return Elasticsearch(url, **common, **auth)
    except ImportError as e:
        raise SystemExit("Install opensearch-py (pip install opensearch-py).") from e


_SOURCE_FIELDS = [
    "timestamp", "id", "rule.id", "rule.description", "rule.level", "rule.groups",
    "agent.name", "agent.ip", "data.win.system.computer",
    "data.win.eventdata.threat Name", "data.win.eventdata.severity Name",
    "data.win.eventdata.action Name", "data.clamav.signature", "data.clamav.path", "full_log",
]


def collect(client, index_pattern, lookback_hours, source):
    body = {
        "size": 1000, "_source": _SOURCE_FIELDS, "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"filter": [
            _filter(source),
            {"range": {"timestamp": {"gte": f"now-{int(lookback_hours)}h"}}},
        ]}},
    }
    resp = client.search(index=index_pattern, body=body)
    return resp.get("hits", {}).get("hits", [])


def _dig(d, *keys):
    for k in keys:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return ""
    return d if isinstance(d, (str, int)) else ""


def parse_hit(hit):
    s = hit.get("_source", {})
    rule = s.get("rule", {})
    groups = rule.get("groups", [])
    is_clam = "clamav" in groups or "clamd" in groups or rule.get("id") in _CLAMAV_IDS
    threat = (_dig(s, "data", "clamav", "signature") if is_clam
              else _dig(s, "data", "win", "eventdata", "threat Name"))
    target = (_dig(s, "data", "clamav", "path") if is_clam
              else _dig(s, "data", "win", "eventdata", "action Name"))
    host = s.get("agent", {}).get("name", "") or _dig(s, "data", "win", "system", "computer")
    return {
        "key": hit.get("_id") or s.get("id", ""),
        "product": "ClamAV" if is_clam else "Windows Defender",
        "time": s.get("timestamp", ""),
        "host": host,
        "threat": threat or "(see rule)",
        "target": target,
        "rule_id": rule.get("id", ""),
        "rule_desc": rule.get("description", ""),
        "level": rule.get("level", ""),
    }


# ---- state (notify-once + seeded marker) -----------------------------------
def connect(path):
    conn = sqlite3.connect(path, timeout=30)
    conn.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS notified "
                 "(event_key TEXT PRIMARY KEY, product TEXT, host TEXT, threat TEXT, notified_at TEXT)")
    conn.commit()
    return conn


def mark(conn, r, now):
    conn.execute("INSERT OR REPLACE INTO notified(event_key,product,host,threat,notified_at) "
                 "VALUES(?,?,?,?,?)", (r["key"], r["product"], r["host"], r["threat"], now))


# ---- email -----------------------------------------------------------------
def send_mail(recipients, subject, text_body, html_body, smtp_server, smtp_port):
    em = EmailMessage()
    em["From"] = MAIL_FROM
    em["To"] = ", ".join(recipients)
    em["Subject"] = subject
    em.set_content(text_body)
    em.add_alternative(html_body, subtype="html")
    with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as s:
        s.ehlo()
        s.send_message(em)


def build_html(records):
    rows = []
    for r in records:
        cells = [r["time"], r["product"], html.escape(str(r["host"])), html.escape(str(r["threat"])),
                 html.escape(str(r["target"])), f"{r['rule_id']} (L{r['level']})"]
        tds = "".join(f'<td style="{FONT}padding:6px 10px;border-bottom:1px solid #ddd;">{c}</td>' for c in cells)
        rows.append(f"<tr>{tds}</tr>")
    hdr = "".join(f'<th style="{FONT}padding:6px 10px;text-align:left;background:#b00020;color:#fff;">{h}</th>'
                  for h in ["Time (UTC)", "Product", "Host", "Threat / signature", "Path / action", "Rule"])
    link = f'<p style="{FONT}">Dashboard: <a href="{DASHBOARD_URL}">{DASHBOARD_URL}</a></p>' if DASHBOARD_URL else ""
    return (f'<div style="{FONT}"><h2 style="{FONT}color:#b00020;">Antivirus detections ({len(records)})</h2>'
            f'<table style="border-collapse:collapse;">{hdr}{"".join(rows)}</table>{link}</div>')


def build_text(records):
    L = [f"Antivirus detections ({len(records)}):", ""]
    for r in records:
        L.append(f"- [{r['product']}] {r['host']}: {r['threat']}  ({r['target']})  "
                 f"rule {r['rule_id']} L{r['level']}  @ {r['time']}")
    if DASHBOARD_URL:
        L += ["", f"Dashboard: {DASHBOARD_URL}"]
    return "\n".join(L)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- main ------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Antivirus (Defender/ClamAV) detection email digest.")
    ap.add_argument("--source", default=AV_SOURCE, choices=["defender", "clamav", "both"])
    ap.add_argument("--index-url", default=INDEX_URL)
    ap.add_argument("--user", default=INDEX_USER)
    ap.add_argument("--password", default=INDEX_PASSWORD)
    ap.add_argument("--index-pattern", default=INDEX_PATTERN)
    ap.add_argument("--ca", default=CA)
    ap.add_argument("--no-verify", action="store_true", default=NO_VERIFY)
    ap.add_argument("--cert", default=INDEX_CLIENT_CERT)
    ap.add_argument("--key", default=INDEX_CLIENT_KEY)
    ap.add_argument("--lookback-hours", type=int, default=LOOKBACK_HOURS)
    ap.add_argument("--recipients", default=",".join(RECIPIENTS))
    ap.add_argument("--smtp-server", default=SMTP_SERVER)
    ap.add_argument("--smtp-port", type=int, default=SMTP_PORT)
    ap.add_argument("--state-db", default=STATE_DB)
    ap.add_argument("--seed", action="store_true", help="baseline current detections, send nothing")
    ap.add_argument("--dry-run", action="store_true", help="print what would be sent; no mail, no state change")
    ap.add_argument("--test", action="store_true", help="send one sample ticket from the newest detection (in-memory DB)")
    args = ap.parse_args()

    verify = False if args.no_verify else (args.ca if args.ca else True)
    client = _get_client(args.index_url, args.user, args.password, verify, args.cert, args.key)
    recipients = [r.strip() for r in args.recipients.split(",") if r.strip()]
    now = now_iso()

    hits = collect(client, args.index_pattern, args.lookback_hours, args.source)
    records = [parse_hit(h) for h in hits]
    print(f"[gather] source={args.source} window={args.lookback_hours}h detections={len(records)}")

    if args.test:
        if not records:
            print("[test] no detections in window; nothing to send"); return 0
        r = records[-1]
        if not recipients:
            raise SystemExit("--test needs --recipients or RECIPIENTS")
        send_mail(recipients, f"[TEST] Antivirus detection on {r['host']}",
                  build_text([r]), build_html([r]), args.smtp_server, args.smtp_port)
        print(f"[test] sent sample ticket to {recipients}")
        return 0

    conn = connect(args.state_db)
    seeded = conn.execute("SELECT v FROM meta WHERE k='seeded_at'").fetchone()

    if args.seed:
        for r in records:
            mark(conn, r, now)
        conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('seeded_at',?)", (now,))
        conn.commit()
        print(f"[seed] baselined {len(records)} detection(s); emitted 0")
        return 0

    if not seeded and not args.dry_run:
        raise SystemExit("State DB has no baseline. Run once with --seed first (records current "
                         "detections without mailing). Use --dry-run to preview.")

    already = {row[0] for row in conn.execute("SELECT event_key FROM notified")}
    new = [r for r in records if r["key"] not in already]
    print(f"[notify] new (not yet notified): {len(new)}")
    if not new:
        return 0

    if args.dry_run:
        for r in new:
            print(f"[dry-run] {r['product']} {r['host']}: {r['threat']} ({r['rule_id']})")
        return 0

    if not recipients:
        raise SystemExit("no RECIPIENTS/--recipients set")
    hosts = sorted({r["host"] for r in new})
    subject = f"⚠ Malware detected: {len(new)} on {', '.join(hosts[:3])}" + (" +" if len(hosts) > 3 else "")
    send_mail(recipients, subject, build_text(new), build_html(new), args.smtp_server, args.smtp_port)
    for r in new:
        mark(conn, r, now)
    conn.commit()
    print(f"[notify] mailed {len(new)} detection(s) to {recipients}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
