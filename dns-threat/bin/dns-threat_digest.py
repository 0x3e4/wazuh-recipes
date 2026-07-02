#!/usr/bin/env python3
"""Wazuh "DNS threats" weekly digest.

Stateless periodic summary (NOT per-event; there is no dedup database). Each run
queries the Wazuh Indexer for alerts in the `dns_threat` rule group over the last
RANGE_DAYS, aggregates the matches, and sends ONE HTML email (plain-text fallback).

Pairs with the dns_threat ruleset (rules 100700-100703, chained off Sysmon Event 22):
  100700  query to a KNOWN-MALICIOUS domain (denylist)            T1071.004
  100701  query to a suspicious TLD (.top/.xyz/.tk/...)           T1071.004
  100702  dynamic-DNS / tunneling service (duckdns, ngrok, ...)   T1568.002
  100703  long single label (possible DNS tunneling)              T1048.003

Indexer filter:  rule.groups:dns_threat

Config comes from the environment / an env file (see dns-threat-digest.env.example).
No secrets and no internal hostnames are hard-coded.
"""
import os
import sys
import html
import smtplib
import argparse
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage

_LIB = os.environ.get("WAZUH_RECIPES_LIB", "/opt/wazuh-recipes/lib")
if _LIB and os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# =====================================================================
# Recipe definition
# =====================================================================

TOPIC       = "DNS threats"
RULE_GROUP  = "dns_threat"
RULE_FILTER = "rule.groups:dns_threat"
# friendly labels for the "by detection rule" breakdown
RULE_LABELS = {
    "100700": "Known-malicious domain (denylist)",
    "100701": "Suspicious TLD",
    "100702": "Dynamic-DNS / tunneling service",
    "100703": "Long-label (possible tunneling)",
}

# =====================================================================
# Config (env / .env -- NO hardcoded secrets, NO internal hostnames)
# =====================================================================

INDEX_URL      = os.environ.get("INDEX_URL", "https://127.0.0.1:9200")
INDEX_USER     = os.environ.get("INDEX_USER", "admin")
INDEX_PASSWORD = os.environ.get("INDEX_PASSWORD", "")
INDEX_PATTERN  = os.environ.get("INDEX_PATTERN", "wazuh-alerts-*")
CA             = os.environ.get("CA", "/etc/filebeat/certs/root-ca.pem")
NO_VERIFY      = os.environ.get("NO_VERIFY", "").strip().lower() in ("1", "true", "yes", "on")
SMTP_SERVER    = os.environ.get("SMTP_SERVER", "smtp.example.com")
MAIL_FROM      = os.environ.get("MAIL_FROM", "wazuh@example.com")
RECIPIENTS     = os.environ.get("RECIPIENTS", "")
RANGE_DAYS     = int(os.environ.get("RANGE_DAYS", "7"))
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "https://wazuh.example.com")

_ACCENT_HIGH = "#b3261e"   # >= L12 (denylist hits)
_ACCENT_MED  = "#b06a00"   # L7..L11
_ACCENT_LOW  = "#2980b9"

_TOP_N = 25

# =====================================================================
# Wazuh Indexer (OpenSearch) connection helper
# =====================================================================

def _get_client(url, user, password, verify):
    try:
        from opensearchpy import OpenSearch
        return OpenSearch(url, http_auth=(user, password), verify_certs=bool(verify),
                          ca_certs=verify or None, ssl_show_warn=False, timeout=30)
    except ImportError:
        pass
    try:
        from elasticsearch import Elasticsearch
        return Elasticsearch(url, http_auth=(user, password), verify_certs=bool(verify),
                             ca_certs=verify or None, timeout=30)
    except ImportError as e:
        raise SystemExit(
            "Install opensearch-py (pip install opensearch-py) or set WAZUH_RECIPES_LIB "
            "to a directory that contains it.") from e

# =====================================================================
# Query + aggregation
# =====================================================================

def _base_query(range_days):
    gte = f"now-{int(range_days)}d"
    return {"bool": {"filter": [
        {"term": {"rule.groups": RULE_GROUP}},
        {"range": {"timestamp": {"gte": gte}}},
    ]}}

def collect_summary(client, index_pattern, range_days):
    body = {
        "size": 0,
        "query": _base_query(range_days),
        "aggs": {
            "by_rule":    {"terms": {"field": "rule.id",                      "size": 20}},
            "by_domain":  {"terms": {"field": "data.win.eventdata.queryName", "size": _TOP_N}},
            "by_host":    {"terms": {"field": "agent.name",                   "size": _TOP_N}},
            "by_process": {"terms": {"field": "data.win.eventdata.image",     "size": _TOP_N}},
        },
    }
    resp = client.search(index=index_pattern, body=body,
                         ignore_unavailable=True, allow_no_indices=True)
    total = resp.get("hits", {}).get("total", {})
    total = total.get("value", total) if isinstance(total, dict) else total
    aggs = resp.get("aggregations", {})

    def _buckets(name):
        return [(b.get("key"), b.get("doc_count", 0))
                for b in aggs.get(name, {}).get("buckets", [])]

    return {
        "total":      int(total or 0),
        "by_rule":    _buckets("by_rule"),
        "by_domain":  _buckets("by_domain"),
        "by_host":    _buckets("by_host"),
        "by_process": _buckets("by_process"),
    }

def collect_recent(client, index_pattern, range_days, size=25):
    body = {
        "size": size,
        "_source": ["timestamp", "agent.name", "rule.id", "rule.level",
                    "data.win.eventdata.queryName", "data.win.eventdata.image",
                    "data.win.eventdata.queryResults"],
        "query": _base_query(range_days),
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    resp = client.search(index=index_pattern, body=body,
                         ignore_unavailable=True, allow_no_indices=True)
    rows = []
    for h in resp.get("hits", {}).get("hits", []):
        s = h.get("_source", {}) or {}
        r = s.get("rule", {}) or {}
        a = s.get("agent", {}) or {}
        ed = ((s.get("data", {}) or {}).get("win", {}) or {}).get("eventdata", {}) or {}
        rows.append({
            "timestamp":  s.get("timestamp", ""),
            "agent":      a.get("name", ""),
            "domain":     html.unescape(ed.get("queryName", "")),
            "process":    html.unescape(ed.get("image", "")),
            "results":    html.unescape(ed.get("queryResults", "")),
            "rule_id":    r.get("id", ""),
            "rule_level": r.get("level", ""),
        })
    return rows

# =====================================================================
# Rendering helpers
# =====================================================================

def _esc(s):
    return html.escape(str(s if s is not None else ""))

def _rule_label(rid):
    return RULE_LABELS.get(str(rid), f"rule {rid}")

def _max_level(levels):
    try:
        return max(int(l) for l in levels if str(l).strip() != "")
    except ValueError:
        return 0

def _accent_for_level(level):
    return _ACCENT_HIGH if level >= 12 else (_ACCENT_MED if level >= 7 else _ACCENT_LOW)

def _fmt_ts(ts):
    if not ts:
        return ""
    return str(ts).replace("T", " ")[:19]

# ---------- plain-text ----------

def build_text(summary, recent, range_days, now):
    L = []
    L.append(f"Wazuh {TOPIC} weekly summary")
    L.append(f"Generated: {now}")
    L.append(f"Window: last {range_days} day(s)")
    L.append(f"Filter: {RULE_FILTER}")
    L.append("=" * 72)
    L.append(f"Total DNS-threat alerts: {summary['total']}")
    L.append("")
    L.append("## By detection rule")
    if summary["by_rule"]:
        for rid, n in summary["by_rule"]:
            L.append(f"  {n:>6}  [{rid}] {_rule_label(rid)}")
    else:
        L.append("  (none)")
    L.append("")
    L.append(f"## Top flagged domains - top {_TOP_N}")
    if summary["by_domain"]:
        for dom, n in summary["by_domain"]:
            L.append(f"  {n:>6}  {html.unescape(dom)}")
    else:
        L.append("  (none)")
    L.append("")
    L.append(f"## Top hosts - top {_TOP_N}")
    if summary["by_host"]:
        for h, n in summary["by_host"]:
            L.append(f"  {n:>6}  {h}")
    else:
        L.append("  (none)")
    L.append("")
    L.append(f"## Top processes - top {_TOP_N}")
    if summary["by_process"]:
        for p, n in summary["by_process"]:
            L.append(f"  {n:>6}  {html.unescape(p)}")
    else:
        L.append("  (none)")
    L.append("")
    L.append(f"## Most recent alerts ({len(recent)})")
    if recent:
        for r in recent:
            L.append(f"  {_fmt_ts(r['timestamp'])}  L{r['rule_level']}  [{r['rule_id']}]  "
                     f"{r['agent']}  {r['domain']}")
            if r["process"]:
                L.append(f"      proc: {r['process']}  ->  {r['results']}")
    else:
        L.append("  (none)")
    L.append("")
    L.append(f"Dashboard: {DASHBOARD_URL}")
    return "\n".join(L)

# ---------- HTML ----------

def _kv_table_html(headers, rows):
    th = "".join(
        f'<th style="text-align:left;padding:6px 10px;background:#f1f5f9;'
        f'border-bottom:1px solid #e2e8f0;font-size:12px;color:#475569;">{_esc(h)}</th>'
        for h in headers)
    body = []
    for i, row in enumerate(rows):
        bg = "#ffffff" if i % 2 == 0 else "#f8fafc"
        tds = "".join(
            f'<td style="padding:6px 10px;border-bottom:1px solid #eef2f6;'
            f'font-size:13px;color:#0f172a;{ "white-space:nowrap;" if j == 0 else "" }">{cell}</td>'
            for j, cell in enumerate(row))
        body.append(f'<tr bgcolor="{bg}" style="background:{bg};">{tds}</tr>')
    if not rows:
        body.append(f'<tr><td colspan="{len(headers)}" style="padding:8px 10px;color:#94a3b8;'
                    f'font-size:13px;">none</td></tr>')
    return ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border-collapse:collapse;border:1px solid #e2e8f0;margin:4px 0 14px;">'
            f'<tr>{th}</tr>{"".join(body)}</table>')

def _section_bar_html(label, barcolor="#334155"):
    return ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="margin:18px 0 6px;"><tr>'
            f'<td bgcolor="{barcolor}" style="background:{barcolor};color:#ffffff;padding:6px 12px;'
            f'font-size:14px;font-weight:bold;">{_esc(label)}</td></tr></table>')

def build_html(summary, recent, range_days, now):
    level = _max_level([r["rule_level"] for r in recent]) or 12
    accent = _accent_for_level(level)
    title = f"{TOPIC} &mdash; weekly summary"
    intro = (
        f'<p style="margin:0 0 12px;">'
        f'<strong>{summary["total"]}</strong> suspicious-DNS alert(s) over the last '
        f'<strong>{int(range_days)}</strong> day(s): '
        f'<strong>{len(summary["by_domain"])}</strong> flagged domain(s) across '
        f'<strong>{len(summary["by_host"])}</strong> host(s).<br>'
        f'<span style="font-size:12px;color:#64748b;">Filter: {_esc(RULE_FILTER)} '
        f'(Sysmon Event 22 / rules 100700-100703)</span></p>')

    rule_rows = [(f'[{_esc(rid)}] {_esc(_rule_label(rid))}', f'<strong>{n}</strong>')
                 for rid, n in summary["by_rule"]]
    dom_rows  = [(_esc(html.unescape(d)), f'<strong>{n}</strong>') for d, n in summary["by_domain"]]
    host_rows = [(_esc(h), f'<strong>{n}</strong>') for h, n in summary["by_host"]]
    proc_rows = [(_esc(html.unescape(p)), f'<strong>{n}</strong>') for p, n in summary["by_process"]]

    rec_rows = []
    for r in recent:
        rec_rows.append((_esc(_fmt_ts(r["timestamp"])), f'L{_esc(r["rule_level"])}',
                         _esc(r["rule_id"]), _esc(r["agent"]),
                         _esc(r["domain"][:80]), _esc(r["process"][:60])))
    rec_tbl = _kv_table_html(["Time (UTC offset)", "Level", "Rule", "Host", "Query", "Process"], rec_rows)

    body = (
        _section_bar_html("By detection rule") + _kv_table_html(["Detection rule", "Count"], rule_rows)
        + _section_bar_html("Top flagged domains") + _kv_table_html(["Query name (data.win.eventdata.queryName)", "Count"], dom_rows)
        + _section_bar_html("Top hosts") + _kv_table_html(["Host (agent.name)", "Count"], host_rows)
        + _section_bar_html("Top processes") + _kv_table_html(["Process (data.win.eventdata.image)", "Count"], proc_rows)
        + _section_bar_html("Most recent alerts") + rec_tbl)

    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<meta name="color-scheme" content="light dark">'
        '<meta name="supported-color-schemes" content="light dark"></head>'
        '<body style="margin:0;padding:0;background:#eef2f6;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#eef2f6">'
        '<tr><td align="center" style="padding:18px;">'
        '<table role="presentation" width="860" cellpadding="0" cellspacing="0" '
        "style=\"width:860px;max-width:860px;font-family:'Segoe UI',Arial,sans-serif;\">"
        f'<tr><td bgcolor="{accent}" style="background:{accent};color:#ffffff;padding:14px 18px;'
        f'font-size:18px;font-weight:bold;">{title}</td></tr>'
        '<tr><td bgcolor="#ffffff" style="background:#ffffff;color:#1f2933;padding:16px 18px;'
        'border:1px solid #e3e8ef;border-top:none;">'
        f'{intro}{body}'
        '<div style="margin-top:18px;font-size:11px;color:#94a3b8;border-top:1px solid #e3e8ef;'
        f'padding-top:8px;">Automated weekly {_esc(TOPIC)} summary from Wazuh. '
        f'Dashboard: <a href="{_esc(DASHBOARD_URL)}" style="color:#2563eb;">{_esc(DASHBOARD_URL)}</a></div>'
        '</td></tr></table></td></tr></table></body></html>')

# =====================================================================
# SMTP
# =====================================================================

def send_mail(recipients, subject, text_body, html_body=None):
    em = EmailMessage()
    em["From"] = MAIL_FROM
    em["To"] = ", ".join(recipients)
    em["Subject"] = subject
    em.set_content(text_body)
    if html_body:
        em.add_alternative(html_body, subtype="html")
    with smtplib.SMTP(SMTP_SERVER, 25, timeout=30) as s:
        s.ehlo()
        s.send_message(em)

# =====================================================================
# Main
# =====================================================================

def run(args):
    verify = False if args.no_verify else (args.ca if args.ca else True)
    if isinstance(verify, str) and not os.access(verify, os.R_OK):
        raise SystemExit(
            f"CA file not readable: {verify} (run as a user that can read it, or use --no-verify)")
    if not args.password:
        raise SystemExit("No indexer password set (INDEX_PASSWORD env or --password).")

    client = _get_client(args.index_url, args.user, args.password, verify=verify)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    summary = collect_summary(client, args.index_pattern, args.range_days)
    recent  = collect_recent(client, args.index_pattern, args.range_days)

    subject = f"Wazuh: {TOPIC} weekly summary - {summary['total']} alerts"
    text_body = build_text(summary, recent, args.range_days, now)
    html_body = build_html(summary, recent, args.range_days, now)

    print(f"[digest] topic={TOPIC!r} indexer={args.index_url} index={args.index_pattern} "
          f"range_days={args.range_days} filter={RULE_FILTER!r} total={summary['total']} "
          f"rules={len(summary['by_rule'])} domains={len(summary['by_domain'])} "
          f"hosts={len(summary['by_host'])} processes={len(summary['by_process'])}")

    recipients = [x.strip() for x in (args.recipients or RECIPIENTS).split(",") if x.strip()]

    if args.dry_run:
        print("----- SUBJECT -----"); print(subject)
        print("----- TEXT BODY -----"); print(text_body)
        print(f"----- [dry-run] HTML {len(html_body)} bytes; recipients={recipients!r} -----")
        return

    if summary["total"] == 0 and not args.always:
        print("[digest] nothing this period; no email sent. (use --always to send anyway)")
        return

    if not recipients:
        raise SystemExit("No recipients configured (set RECIPIENTS env or --recipients).")

    send_mail(recipients, subject, text_body, html_body)
    print(f"[digest] sent '{subject}' to {recipients}")

def main():
    ap = argparse.ArgumentParser(
        description=f"Send a weekly Wazuh '{TOPIC}' summary email read from the Wazuh Indexer.")
    ap.add_argument("--index-url", default=INDEX_URL)
    ap.add_argument("--user", default=INDEX_USER)
    ap.add_argument("--password", default=INDEX_PASSWORD)
    ap.add_argument("--index-pattern", default=INDEX_PATTERN)
    ap.add_argument("--no-verify", action="store_true", default=NO_VERIFY)
    ap.add_argument("--ca", default=CA)
    ap.add_argument("--range-days", type=int, default=RANGE_DAYS)
    ap.add_argument("--recipients", default=RECIPIENTS)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--always", action="store_true",
                    help="send the email even when there are 0 alerts in the window")
    run(ap.parse_args())

if __name__ == "__main__":
    main()
