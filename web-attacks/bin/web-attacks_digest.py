#!/usr/bin/env python3
"""Wazuh "Web attacks" weekly digest.

Stateless periodic summary (NOT per-event; there is no dedup database). Each run
queries the Wazuh Indexer for this recipe's rule IDs over the last RANGE_DAYS,
aggregates the matches, and sends ONE HTML email (with a plain-text fallback).

Watched Wazuh rules:
  31151  Multiple errors (400) from same source ip (web scan)
  31153  Multiple common web attacks from same source ip
  31154  Multiple XSS (Cross Site Scripting) attempts from same source ip
  31168  Shellshock attack detected (CVE-2014-6271, level 15)
  31169  Shellshock attack attempt (level 15)

Indexer filter:  rule.id:(31153 OR 31154 OR 31151 OR 31168 OR 31169)

Config comes from the environment / an env file (see web-attacks-digest.env.example).
No secrets and no internal hostnames are hard-coded.
"""
import os
import sys
import html
import smtplib
import argparse
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage

# opensearch-py is installed in a separate location (a venv or a shared lib dir).
# Allow pointing at it without touching the system path; default matches the
# install layout documented in the README.
_LIB = os.environ.get("WAZUH_RECIPES_LIB", "/opt/wazuh-recipes/lib")
if _LIB and os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# =====================================================================
# Recipe definition
# =====================================================================

TOPIC        = "Web attacks"
RULE_IDS     = ["31153", "31154", "31151", "31168", "31169"]
# KQL/query_string equivalent of the rule filter (kept for reference / parity
# with the dashboard panels); the actual query below uses a terms filter.
RULE_FILTER  = "rule.id:(31153 OR 31154 OR 31151 OR 31168 OR 31169)"

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
RECIPIENTS     = os.environ.get("RECIPIENTS", "")        # comma-separated; or --recipients
RANGE_DAYS     = int(os.environ.get("RANGE_DAYS", "7"))
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "https://wazuh.example.com")

# Rule level -> header accent colour (web-attack rules are mostly L10; Shellshock L15).
_ACCENT_HIGH = "#b3261e"   # >= L12
_ACCENT_MED  = "#b06a00"   # L7..L11
_ACCENT_LOW  = "#2980b9"   # < L7

_TOP_N = 20   # rows per breakdown table

# =====================================================================
# Wazuh Indexer (OpenSearch) connection helper
# =====================================================================

def _get_client(url, user, password, verify):
    """Return an OpenSearch client (falls back to the Elasticsearch 7.x client)."""
    try:
        from opensearchpy import OpenSearch
        return OpenSearch(
            url, http_auth=(user, password),
            verify_certs=bool(verify), ca_certs=verify or None,
            ssl_show_warn=False, timeout=30,
        )
    except ImportError:
        pass
    try:
        from elasticsearch import Elasticsearch
        return Elasticsearch(
            url, http_auth=(user, password),
            verify_certs=bool(verify), ca_certs=verify or None, timeout=30,
        )
    except ImportError as e:
        raise SystemExit(
            "Install opensearch-py (pip install opensearch-py) or set WAZUH_RECIPES_LIB "
            "to a directory that contains it."
        ) from e

# =====================================================================
# Query + aggregation
# =====================================================================

def _base_query(range_days):
    gte = f"now-{int(range_days)}d"
    return {
        "bool": {
            "filter": [
                {"terms": {"rule.id": RULE_IDS}},
                {"range": {"timestamp": {"gte": gte}}},
            ]
        }
    }

def collect_summary(client, index_pattern, range_days):
    """One aggregation request -> the whole digest payload.

    Returns a dict with: total, by_rule (description -> count), by_srcip
    (srcip -> count), by_agent, and a list of the most recent events.
    """
    body = {
        "size": 0,
        "query": _base_query(range_days),
        "aggs": {
            "by_rule":  {"terms": {"field": "rule.description", "size": 50}},
            "by_srcip": {"terms": {"field": "data.srcip",       "size": _TOP_N}},
            "by_agent": {"terms": {"field": "agent.name",       "size": _TOP_N}},
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
        "total":    int(total or 0),
        "by_rule":  _buckets("by_rule"),
        "by_srcip": _buckets("by_srcip"),
        "by_agent": _buckets("by_agent"),
    }

def collect_recent(client, index_pattern, range_days, size=25):
    """The most recent matching events for the 'top recent events' table."""
    body = {
        "size": size,
        "_source": ["timestamp", "agent.name", "data.srcip", "data.url",
                    "data.status", "rule.id", "rule.description", "rule.level"],
        "query": _base_query(range_days),
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    resp = client.search(index=index_pattern, body=body,
                         ignore_unavailable=True, allow_no_indices=True)
    rows = []
    for h in resp.get("hits", {}).get("hits", []):
        s = h.get("_source", {}) or {}
        d = s.get("data", {}) or {}
        r = s.get("rule", {}) or {}
        a = s.get("agent", {}) or {}
        rows.append({
            "timestamp":   s.get("timestamp", ""),
            "agent":       a.get("name", ""),
            "srcip":       d.get("srcip", ""),
            "url":         d.get("url", ""),
            "status":      d.get("status", d.get("id", "")),
            "rule_id":     r.get("id", ""),
            "rule_desc":   r.get("description", ""),
            "rule_level":  r.get("level", ""),
        })
    return rows

# =====================================================================
# Rendering helpers
# =====================================================================

def _esc(s):
    return html.escape(str(s if s is not None else ""))

def _max_level(by_rule_levels):
    try:
        return max(int(l) for l in by_rule_levels if str(l).strip() != "")
    except ValueError:
        return 0

def _accent_for_level(level):
    if level >= 12:
        return _ACCENT_HIGH
    if level >= 7:
        return _ACCENT_MED
    return _ACCENT_LOW

def _fmt_ts(ts):
    # Trim the fractional seconds / keep it readable; leave the raw value if parsing fails.
    if not ts:
        return ""
    t = str(ts).replace("T", " ")
    return t[:19]

# ---------- plain-text ----------

def build_text(summary, recent, range_days, now):
    L = []
    L.append(f"Wazuh {TOPIC} weekly summary")
    L.append(f"Generated: {now}")
    L.append(f"Window: last {range_days} day(s)")
    L.append(f"Watched rules: {', '.join(RULE_IDS)}")
    L.append("=" * 72)
    L.append(f"Total alerts: {summary['total']}")
    L.append("")
    L.append(f"## Top attack types (rule.description) - {len(summary['by_rule'])} kind(s)")
    if summary["by_rule"]:
        for desc, n in summary["by_rule"]:
            L.append(f"  {n:>6}  {desc}")
    else:
        L.append("  (none)")
    L.append("")
    L.append(f"## Top source IPs (data.srcip) - top {_TOP_N}")
    if summary["by_srcip"]:
        for ip, n in summary["by_srcip"]:
            L.append(f"  {n:>6}  {ip}")
    else:
        L.append("  (none)")
    L.append("")
    L.append(f"## Top targeted agents (agent.name) - top {_TOP_N}")
    if summary["by_agent"]:
        for ag, n in summary["by_agent"]:
            L.append(f"  {n:>6}  {ag}")
    else:
        L.append("  (none)")
    L.append("")
    L.append(f"## Most recent events ({len(recent)})")
    if recent:
        for r in recent:
            L.append(f"  {_fmt_ts(r['timestamp'])}  L{r['rule_level']}  {r['srcip']}"
                     f"  ->  {r['agent']}  [{r['status']}]  {r['rule_desc']}")
            if r["url"]:
                L.append(f"      url: {r['url']}")
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
        body.append(
            f'<tr><td colspan="{len(headers)}" style="padding:8px 10px;color:#94a3b8;'
            f'font-size:13px;">none</td></tr>')
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="border-collapse:collapse;border:1px solid #e2e8f0;margin:4px 0 14px;">'
        f'<tr>{th}</tr>{"".join(body)}</table>'
    )

def _section_bar_html(label, barcolor="#334155"):
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="margin:18px 0 6px;"><tr>'
        f'<td bgcolor="{barcolor}" style="background:{barcolor};color:#ffffff;padding:6px 12px;'
        f'font-size:14px;font-weight:bold;">{_esc(label)}</td></tr></table>'
    )

def build_html(summary, recent, range_days, now):
    level = _max_level([r["rule_level"] for r in recent]) or 10
    accent = _accent_for_level(level)

    title = f"{TOPIC} &mdash; weekly summary"
    intro = (
        f'<p style="margin:0 0 12px;">'
        f'<strong>{summary["total"]}</strong> web-attack alert(s) over the last '
        f'<strong>{int(range_days)}</strong> day(s) across '
        f'<strong>{len(summary["by_agent"])}</strong> agent(s) from '
        f'<strong>{len(summary["by_srcip"])}</strong> source IP(s).<br>'
        f'<span style="font-size:12px;color:#64748b;">Watched rules: '
        f'{_esc(", ".join(RULE_IDS))}</span></p>'
    )

    # Top attack types
    rule_rows = [(_esc(desc), f'<strong>{n}</strong>') for desc, n in summary["by_rule"]]
    rule_tbl = _kv_table_html(["Attack type (rule.description)", "Count"], rule_rows)

    # Top source IPs
    ip_rows = [(_esc(ip), f'<strong>{n}</strong>') for ip, n in summary["by_srcip"]]
    ip_tbl = _kv_table_html(["Source IP (data.srcip)", "Count"], ip_rows)

    # Top agents
    agent_rows = [(_esc(ag), f'<strong>{n}</strong>') for ag, n in summary["by_agent"]]
    agent_tbl = _kv_table_html(["Targeted agent (agent.name)", "Count"], agent_rows)

    # Recent events
    rec_rows = []
    for r in recent:
        rec_rows.append((
            _esc(_fmt_ts(r["timestamp"])),
            _esc(r["srcip"]),
            _esc(r["agent"]),
            _esc(r["status"]),
            f'L{_esc(r["rule_level"])}',
            _esc(r["url"][:120]),
        ))
    rec_tbl = _kv_table_html(
        ["Time (UTC offset)", "Source IP", "Agent", "Status", "Level", "URL / payload"],
        rec_rows)

    body = (
        _section_bar_html("Top attack types") + rule_tbl
        + _section_bar_html("Top source IPs") + ip_tbl
        + _section_bar_html("Top targeted agents") + agent_tbl
        + _section_bar_html("Most recent events") + rec_tbl
    )

    page = (
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
        '</td></tr></table></td></tr></table></body></html>'
    )
    return page

# =====================================================================
# SMTP
# =====================================================================

def send_mail(recipients, subject, text_body, html_body=None):
    em = EmailMessage()
    em["From"] = MAIL_FROM
    em["To"] = ", ".join(recipients)
    em["Subject"] = subject
    em.set_content(text_body)                  # plain-text fallback
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

    now_dt = datetime.now(timezone.utc)
    now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    summary = collect_summary(client, args.index_pattern, args.range_days)
    recent  = collect_recent(client, args.index_pattern, args.range_days)

    subject = f"Wazuh: {TOPIC} weekly summary - {summary['total']} alerts"
    text_body = build_text(summary, recent, args.range_days, now)
    html_body = build_html(summary, recent, args.range_days, now)

    print(f"[digest] topic={TOPIC!r} indexer={args.index_url} index={args.index_pattern} "
          f"range_days={args.range_days} rules={','.join(RULE_IDS)} "
          f"total={summary['total']} attack_types={len(summary['by_rule'])} "
          f"src_ips={len(summary['by_srcip'])} agents={len(summary['by_agent'])}")

    recipients = [x.strip() for x in (args.recipients or RECIPIENTS).split(",") if x.strip()]

    if args.dry_run:
        print("----- SUBJECT -----")
        print(subject)
        print("----- TEXT BODY -----")
        print(text_body)
        print(f"----- [dry-run] HTML {len(html_body)} bytes; "
              f"recipients={recipients!r} -----")
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
    ap.add_argument("--index-url", default=INDEX_URL,
                    help="Wazuh Indexer URL (env INDEX_URL; default https://127.0.0.1:9200)")
    ap.add_argument("--user", default=INDEX_USER, help="indexer user (env INDEX_USER; default admin)")
    ap.add_argument("--password", default=INDEX_PASSWORD,
                    help="indexer password (prefer the INDEX_PASSWORD env var)")
    ap.add_argument("--index-pattern", default=INDEX_PATTERN,
                    help="alerts index pattern (env INDEX_PATTERN; default wazuh-alerts-*)")
    ap.add_argument("--no-verify", action="store_true", default=NO_VERIFY,
                    help="skip TLS verification of the indexer certificate (env NO_VERIFY)")
    ap.add_argument("--ca", default=CA,
                    help="CA bundle for indexer TLS verification (env CA)")
    ap.add_argument("--range-days", type=int, default=RANGE_DAYS,
                    help="how many days back to summarise (env RANGE_DAYS; default 7)")
    ap.add_argument("--recipients", default=RECIPIENTS,
                    help="comma-separated recipient list (env RECIPIENTS)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the summary; send no email")
    ap.add_argument("--always", action="store_true",
                    help="send the email even when there are 0 alerts in the window")
    args = ap.parse_args()
    run(args)

if __name__ == "__main__":
    main()
