#!/usr/bin/env python3
"""Wazuh "Entra / Intune admin config change" notify-once tickets.

Stateful, near-real-time. Each run queries the Wazuh Indexer for Microsoft Graph
audit events over the last LOOKBACK_HOURS, keeps only *configuration changes made
by a global administrator*, and emails ONE ticket per change the first time it is
seen (SQLite dedup -> notify-once). Every ticket shows WHO changed WHAT and the
exact OLD -> NEW values of each property that actually changed.

Two audit sources are handled (both surface under rule group `ms-graph`):

  * Intune  (deviceManagement/auditEvents)  -- already collected by the ms-graph
    integration. Actor at data.ms-graph.actor.*, changes at
    data.ms-graph.resources[].modifiedProperties[]. A global admin is identified
    by actor.userPermissions containing "*".

  * Entra ID (auditLogs/directoryAudits) -- must be enabled in ossec.conf (see
    ossec/ms-graph-directoryaudits.snippet.xml). Actor at
    data.ms-graph.initiatedBy.user.*, changes at
    data.ms-graph.targetResources[].modifiedProperties[]. directoryAudit events
    carry no userPermissions, so global-admin membership is resolved via a live
    Microsoft Graph lookup of the Global Administrator role members (cached).

Design mirrors the sibling wazuh-recipes digests: env/.env config (no hardcoded
secrets), OpenSearch client + send_mail + inline HTML helpers copied from
bruteforce-success_digest.py, and the notify-once/seed/empty-DB-safety mechanics
from wazuh_vuln_digest.py.

Config comes from the environment / an env file (see the *.env.example).
"""
import os
import sys
import json
import html
import smtplib
import sqlite3
import hashlib
import argparse
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage

# opensearch-py may live in a venv or a shared lib dir; allow pointing at it
# without touching the system path (same convention as the other recipes).
_LIB = os.environ.get("WAZUH_RECIPES_LIB", "/opt/wazuh-recipes/lib")
if _LIB and os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# =====================================================================
# Recipe definition
# =====================================================================

TOPIC = "Entra / Intune admin config change"

# Global Administrator built-in role template id (immutable across every tenant).
GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# =====================================================================
# Config (env / .env -- NO hardcoded secrets, NO internal hostnames)
# =====================================================================

INDEX_URL      = os.environ.get("INDEX_URL", "https://127.0.0.1:9200")
INDEX_USER     = os.environ.get("INDEX_USER", "admin")
INDEX_PASSWORD = os.environ.get("INDEX_PASSWORD", "")
INDEX_PATTERN  = os.environ.get("INDEX_PATTERN", "wazuh-alerts-4.x-*")
CA             = os.environ.get("CA", "/etc/wazuh-indexer/certs/root-ca.pem")
NO_VERIFY      = os.environ.get("NO_VERIFY", "").strip().lower() in ("1", "true", "yes", "on")
# Indexer auth: HTTP basic with INDEX_PASSWORD by default (use a read-only indexer
# user, like the other recipes). To use mTLS instead, point these at a readable
# client cert/key -- e.g. run as root with the admin cert:
#   --cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem
INDEX_CLIENT_CERT = os.environ.get("INDEX_CLIENT_CERT", "")
INDEX_CLIENT_KEY  = os.environ.get("INDEX_CLIENT_KEY", "")
SMTP_SERVER    = os.environ.get("SMTP_SERVER", "smtp.example.com")
SMTP_PORT      = int(os.environ.get("SMTP_PORT", "25"))
MAIL_FROM      = os.environ.get("MAIL_FROM", "wazuh@example.com")
RECIPIENTS     = os.environ.get("RECIPIENTS", "")        # comma-separated; or --recipients
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "https://wazuh.example.com")
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "24"))
STATE_DB       = os.environ.get("STATE_DB", "/opt/entra-config-changes-digest/state.db")
SUPPRESS_NOISE = os.environ.get("SUPPRESS_NOISE", "1").strip().lower() in ("1", "true", "yes", "on")

# Microsoft Graph (used ONLY to resolve Global Administrator membership for Entra
# directoryAudit events; the Intune path needs none of this).
MS_GRAPH_TENANT_ID = os.environ.get("MS_GRAPH_TENANT_ID", "")
MS_GRAPH_CLIENT_ID = os.environ.get("MS_GRAPH_CLIENT_ID", "")
MS_GRAPH_SECRET    = os.environ.get("MS_GRAPH_SECRET", "")
GLOBAL_ADMIN_ROLE_TEMPLATE_IDS = [
    x.strip() for x in os.environ.get(
        "GLOBAL_ADMIN_ROLE_TEMPLATE_IDS", GLOBAL_ADMIN_ROLE_TEMPLATE_ID).split(",") if x.strip()
]
GRAPH_ROLE_CACHE_HOURS = int(os.environ.get("GRAPH_ROLE_CACHE_HOURS", "6"))

_ACCENT = "#b3261e"   # admin config change -> high-severity red header
_MAX_VAL_LEN = 300    # truncate very long property values in the diff table

# =====================================================================
# Wazuh Indexer (OpenSearch) connection helper  [bruteforce-success_digest.py:69]
# =====================================================================

def _get_client(url, user, password, verify, client_cert=None, client_key=None):
    """Return an OpenSearch client (falls back to the Elasticsearch 7.x client).
    Auth is client-certificate (mTLS) when client_cert is given, else HTTP basic
    with (user, password)."""
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
        raise SystemExit(
            "Install opensearch-py (pip install opensearch-py) or set WAZUH_RECIPES_LIB "
            "to a directory that contains it."
        ) from e

# =====================================================================
# Indexer query -- Graph audit events that carry modifiedProperties
# =====================================================================

_SOURCE_FIELDS = ["timestamp", "rule.id", "rule.description", "rule.level",
                  "agent.name", "data.ms-graph"]

def collect_admin_change_events(client, index_pattern, lookback_hours):
    """Page through ms-graph events in the window. We filter broadly (rule group +
    time range) and do all narrowing/classification in Python -- this avoids
    relying on a mapping for the deeply-nested modifiedProperties leaf fields."""
    gte = f"now-{int(lookback_hours)}h"
    body = {
        "size": 1000,
        "_source": _SOURCE_FIELDS,
        "sort": ["_doc"],
        "query": {"bool": {"filter": [
            {"term": {"rule.groups": "ms-graph"}},
            {"range": {"timestamp": {"gte": gte}}},
        ]}},
    }
    hits = []
    resp = client.search(index=index_pattern, body=body, scroll="2m",
                         ignore_unavailable=True, allow_no_indices=True)
    sid = resp.get("_scroll_id")
    page = resp.get("hits", {}).get("hits", [])
    while page:
        hits.extend(page)
        resp = client.scroll(scroll_id=sid, scroll="2m")
        sid = resp.get("_scroll_id")
        page = resp.get("hits", {}).get("hits", [])
    try:
        client.clear_scroll(scroll_id=sid)
    except Exception:
        pass
    return hits

# =====================================================================
# Event classification -- normalise Intune + Entra schemas to one shape
# =====================================================================

def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]

def _g(d, *path, default=None):
    """Safe nested get: _g(src, 'a', 'b') -> src['a']['b'] or default."""
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default

def classify_event(hit):
    """Map one indexer hit to a uniform record, or None if it is not a config
    change (no modifiedProperties). Handles both audit schemas."""
    src = hit.get("_source", {}) or {}
    mg = _g(src, "data", "ms-graph", default={})
    if not isinstance(mg, dict):
        return None

    common = {
        "alert_id":   hit.get("_id", ""),
        "rule_id":    str(_g(src, "rule", "id", default="")),
        "rule_level": str(_g(src, "rule", "level", default="")),
        "agent":      _g(src, "agent", "name", default=""),
        "event_id":   str(mg.get("id") or ""),
        "correlation_id": str(mg.get("correlationId") or ""),
        "category":   str(mg.get("category") or ""),
        "when":       str(mg.get("activityDateTime") or _g(src, "timestamp", default="") or ""),
    }

    if mg.get("resources") is not None:
        # ---- Intune deviceManagement/auditEvents ----
        actor = mg.get("actor") or {}
        perms = _as_list(actor.get("userPermissions"))
        raw_res = _as_list(mg.get("resources"))
        common.update({
            "source":     "intune",
            "source_kind": "Intune (deviceManagement)",
            "actor_upn":  str(actor.get("userPrincipalName") or ""),
            "actor_id":   str(actor.get("userId") or ""),
            "actor_type": str(actor.get("auditActorType") or ""),
            "actor_app":  str(actor.get("applicationDisplayName") or ""),
            "actor_ip":   "",
            "ga_perm":    any(str(p).strip() == "*" for p in perms),
            "action":     str(mg.get("displayName") or mg.get("activityType") or ""),
            "operation":  str(mg.get("activityOperationType") or ""),
            "result":     str(mg.get("activityResult") or ""),
            "resources":  [{
                "display":  str(r.get("displayName") or ""),
                "rtype":    str(r.get("auditResourceType") or r.get("type") or ""),
                "modified": _as_list(r.get("modifiedProperties")),
            } for r in raw_res if isinstance(r, dict)],
        })
        return common

    if mg.get("targetResources") is not None or mg.get("initiatedBy") is not None:
        # ---- Entra ID auditLogs/directoryAudits ----
        user = _g(mg, "initiatedBy", "user", default={}) or {}
        app  = _g(mg, "initiatedBy", "app", default={}) or {}
        raw_res = _as_list(mg.get("targetResources"))
        common.update({
            "source":     "entra",
            "source_kind": "Entra ID (directoryAudit)",
            "actor_upn":  str(user.get("userPrincipalName") or app.get("displayName") or ""),
            "actor_id":   str(user.get("id") or app.get("servicePrincipalId") or ""),
            "actor_type": "User" if user else ("App" if app else ""),
            "actor_app":  str(app.get("displayName") or ""),
            "actor_ip":   str(user.get("ipAddress") or ""),
            "ga_perm":    False,   # not available in directoryAudit; resolved via Graph
            "action":     str(mg.get("activityDisplayName") or ""),
            "operation":  str(mg.get("operationType") or ""),
            "result":     str(mg.get("result") or ""),
            "resources":  [{
                "display":  str(r.get("displayName") or ""),
                "rtype":    str(r.get("type") or ""),
                "modified": _as_list(r.get("modifiedProperties")),
            } for r in raw_res if isinstance(r, dict)],
        })
        return common

    return None

# =====================================================================
# Real-diff extraction  (show only properties that actually changed)
# =====================================================================

_NULLish = {"", "null", "<null>", "[]", "none"}

def _strip_quotes(s):
    s = str(s)
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s

def _norm_val(v):
    """Canonicalise a property value for equality comparison."""
    if v is None:
        return ""
    s = _strip_quotes(v).strip()
    return "" if s.lower() in _NULLish else s

def _is_placeholder(s):
    s = str(s)
    return (s.startswith("System.") or s.startswith("$Collection")
            or s.startswith("Microsoft.") or "Microsoft.Management.Services" in s)

def _disp_val(v):
    """Human-readable rendering of a (de-quoted) value for the diff table."""
    n = _norm_val(v)
    if n == "":
        return "(none)"
    if len(n) > _MAX_VAL_LEN:
        n = n[:_MAX_VAL_LEN] + " …"
    return n

def real_changes(modified_properties):
    """Return [{name, old, new}] for properties whose value actually changed.
    Unchanged snapshot properties (old == new) are dropped; with SUPPRESS_NOISE,
    opaque .NET placeholder values are dropped too (no readable before/after)."""
    out = []
    for mp in modified_properties:
        if not isinstance(mp, dict):
            continue
        name = str(mp.get("displayName") or "")
        old_raw, new_raw = mp.get("oldValue"), mp.get("newValue")
        old_n, new_n = _norm_val(old_raw), _norm_val(new_raw)
        if old_n == new_n:
            continue
        if SUPPRESS_NOISE and (_is_placeholder(old_n) or _is_placeholder(new_n)):
            continue
        out.append({"name": name, "old": _disp_val(old_raw), "new": _disp_val(new_raw)})
    return out

def event_key(rec):
    if rec.get("event_id"):
        return rec["event_id"]
    if rec.get("actor_id") or rec.get("when"):
        raw = "|".join([rec.get("actor_id", ""), rec.get("when", ""),
                        rec.get("action", ""), rec.get("correlation_id", "")])
        return hashlib.sha256(raw.encode()).hexdigest()
    return rec.get("alert_id", "")

# =====================================================================
# Microsoft Graph -- Global Administrator membership (Entra path only)
# =====================================================================

def _graph_token(tenant, client_id, secret):
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
        "scope": "https://graph.microsoft.com/.default",
    }).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r).get("access_token")

def _graph_get(url, token):
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def _fetch_global_admin_ids():
    """Live lookup: object-ids (and UPNs) of every Global Administrator role member.
    Returns {object_id: upn}. Raises on hard failure (caller falls back to cache)."""
    token = _graph_token(MS_GRAPH_TENANT_ID, MS_GRAPH_CLIENT_ID, MS_GRAPH_SECRET)
    if not token:
        raise RuntimeError("no Graph token returned")
    ids = {}
    for tid in GLOBAL_ADMIN_ROLE_TEMPLATE_IDS:
        url = (f"https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId='{tid}')"
               "/members?$select=id,userPrincipalName")
        while url:
            try:
                data = _graph_get(url, token)
            except urllib.error.HTTPError as e:
                if e.code == 404:      # role template not activated in this tenant
                    print(f"[graph] role template {tid} not activated (404); skipping")
                    break
                raise
            for m in data.get("value", []):
                oid = m.get("id")
                if oid:
                    ids[oid] = m.get("userPrincipalName") or ""
            url = data.get("@odata.nextLink")
    return ids

def get_global_admin_ids(conn):
    """Cached Global Administrator member set. Returns a set of object-ids, or
    None if unavailable (no Graph creds and no cache, or Graph error with no
    cache) -- in which case Entra events are skipped rather than mis-flagged."""
    now = datetime.now(timezone.utc)
    row = conn.execute("SELECT v FROM meta WHERE k='global_admins_cached_at'").fetchone()
    if row and row[0]:
        try:
            age = now - datetime.fromisoformat(row[0])
            if age < timedelta(hours=GRAPH_ROLE_CACHE_HOURS):
                cached = {r[0] for r in conn.execute("SELECT object_id FROM global_admins")}
                if cached:
                    print(f"[graph] using cached global-admin set ({len(cached)} members, "
                          f"age {int(age.total_seconds()//60)}m)")
                    return cached
        except ValueError:
            pass

    if not (MS_GRAPH_TENANT_ID and MS_GRAPH_CLIENT_ID and MS_GRAPH_SECRET):
        cached = {r[0] for r in conn.execute("SELECT object_id FROM global_admins")}
        if cached:
            print("[graph] MS_GRAPH_* not set; using stale cached global-admin set")
            return cached
        print("[graph] WARNING: MS_GRAPH_* not configured and no cache -> Entra events skipped")
        return None

    try:
        ids = _fetch_global_admin_ids()
        conn.execute("DELETE FROM global_admins")
        conn.executemany("INSERT OR REPLACE INTO global_admins(object_id, upn) VALUES (?,?)",
                         list(ids.items()))
        conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('global_admins_cached_at', ?)",
                     (now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),))
        conn.commit()
        print(f"[graph] refreshed global-admin set: {len(ids)} member(s)")
        return set(ids)
    except Exception as e:
        cached = {r[0] for r in conn.execute("SELECT object_id FROM global_admins")}
        if cached:
            print(f"[graph] lookup failed ({e}); using stale cache ({len(cached)} members)")
            return cached
        print(f"[graph] WARNING: lookup failed ({e}) and no cache -> Entra events skipped")
        return None

# =====================================================================
# State DB (notify-once)  [wazuh_vuln_digest.py:83]
# =====================================================================

def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notified (
            event_key  TEXT PRIMARY KEY,
            source     TEXT,
            actor      TEXT,
            action     TEXT,
            resource   TEXT,
            changed_at TEXT,
            notified_at TEXT
        )
    """)
    conn.execute("CREATE TABLE IF NOT EXISTS global_admins (object_id TEXT PRIMARY KEY, upn TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    conn.commit()

def mark_notified(conn, rec, now):
    res = "; ".join(r["display"] for r in rec["resources"] if r["display"])[:400]
    conn.execute(
        "INSERT OR REPLACE INTO notified"
        "(event_key, source, actor, action, resource, changed_at, notified_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (event_key(rec), rec["source"], rec["actor_upn"], rec["action"], res,
         rec.get("when", ""), now))

# =====================================================================
# Rendering helpers  [bruteforce-success_digest.py:172-332]
# =====================================================================

def _esc(s):
    return html.escape(str(s if s is not None else ""))

# Set on every text-bearing cell: Outlook/Word-based renderers do NOT inherit
# font-family into nested tables, so without this they fall back to a serif CJK
# font (e.g. PMingLiU). Repeating it per element is the reliable email approach.
_FONT = "font-family:'Segoe UI',Segoe,Tahoma,Arial,sans-serif;"

def _fmt_ts(ts):
    if not ts:
        return ""
    return str(ts).replace("T", " ")[:19]

def _kv_table_html(headers, rows):
    th = "".join(
        f'<th style="{_FONT}text-align:left;padding:6px 10px;background:#f1f5f9;'
        f'border-bottom:1px solid #e2e8f0;font-size:12px;color:#475569;">{_esc(h)}</th>'
        for h in headers)
    body = []
    for i, row in enumerate(rows):
        bg = "#ffffff" if i % 2 == 0 else "#f8fafc"
        tds = "".join(
            f'<td style="{_FONT}padding:6px 10px;border-bottom:1px solid #eef2f6;'
            f'font-size:13px;color:#0f172a;vertical-align:top;'
            f'{ "white-space:nowrap;" if j == 0 else "" }">{cell}</td>'
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
        f'<td bgcolor="{barcolor}" style="{_FONT}background:{barcolor};color:#ffffff;padding:6px 12px;'
        f'font-size:14px;font-weight:bold;">{_esc(label)}</td></tr></table>'
    )

def _html_page(title_html, intro_html, body_html, accent=_ACCENT):
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<meta name="color-scheme" content="light dark">'
        '<meta name="supported-color-schemes" content="light dark"></head>'
        '<body style="margin:0;padding:0;background:#eef2f6;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#eef2f6">'
        '<tr><td align="center" style="padding:18px;">'
        '<table role="presentation" width="840" cellpadding="0" cellspacing="0" '
        "style=\"width:840px;max-width:840px;font-family:'Segoe UI',Arial,sans-serif;\">"
        f'<tr><td bgcolor="{accent}" style="{_FONT}background:{accent};color:#ffffff;padding:14px 18px;'
        f'font-size:18px;font-weight:bold;">{title_html}</td></tr>'
        f'<tr><td bgcolor="#ffffff" style="{_FONT}background:#ffffff;color:#1f2933;padding:16px 18px;'
        'border:1px solid #e3e8ef;border-top:none;">'
        f'{intro_html}{body_html}'
        f'<div style="{_FONT}margin-top:18px;font-size:11px;color:#94a3b8;border-top:1px solid #e3e8ef;'
        f'padding-top:8px;">Automated {_esc(TOPIC)} notification from Wazuh. '
        f'Dashboard: <a href="{_esc(DASHBOARD_URL)}" style="color:#2563eb;">{_esc(DASHBOARD_URL)}</a></div>'
        '</td></tr></table></td></tr></table></body></html>'
    )

def _short_source(rec):
    return "Entra" if rec["source"] == "entra" else "Intune"

def _res_summary(rec):
    parts = []
    for r in rec["resources"]:
        if not r["display"]:
            continue
        suffix = f" ({r['rtype']})" if r["rtype"] else ""
        parts.append(r["display"] + suffix)
    return "; ".join(parts)

def ticket_subject(rec, is_test=False):
    action = (rec["action"] or "configuration change").strip()
    if len(action) > 100:
        action = action[:100] + "..."
    return (f"{'[TEST] ' if is_test else ''}Wazuh: {_short_source(rec)} "
            f"config change: {action}")

def build_ticket_html(rec, is_test=False):
    title = f"{'[TEST] ' if is_test else ''}Config change by global admin"
    n_changes = sum(len(r["changes"]) for r in rec["resources"])
    intro = (f'<p style="{_FONT}margin:0 0 12px;"><strong>{_esc(rec["actor_upn"] or rec["actor_id"])}</strong> '
             f'({_esc(_short_source(rec))}) performed '
             f'<strong>{_esc(rec["action"] or rec["operation"] or "a change")}</strong>: '
             f'<strong>{n_changes}</strong> property change(s).</p>')
    if is_test:
        intro = (f'<p style="{_FONT}margin:0 0 8px;"><strong>This is a manual TEST mail.</strong> '
                 'The dedup database was not modified.</p>') + intro

    who_rows = [
        ("Actor", _esc(rec["actor_upn"] or "(unknown)")),
        ("Actor type", _esc(rec["actor_type"] or "")),
    ]
    if rec["actor_app"]:
        who_rows.append(("Application", _esc(rec["actor_app"])))
    if rec["actor_ip"]:
        who_rows.append(("Source IP", _esc(rec["actor_ip"])))
    ga_reason = rec.get("ga_reason", "")
    who_rows.append(("Global admin", _esc(ga_reason) or "yes"))
    who_rows.append(("When", _esc(_fmt_ts(rec["when"]))))

    what_rows = [
        ("Action", _esc(rec["action"] or "")),
        ("Operation", _esc(rec["operation"] or "")),
        ("Result", _esc(rec["result"] or "")),
        ("Category", _esc(rec["category"] or "")),
        ("Source", _esc(rec["source_kind"])),
        ("Resource(s)", _esc(_res_summary(rec))),
    ]
    if rec["correlation_id"]:
        what_rows.append(("Correlation ID", _esc(rec["correlation_id"])))
    what_rows.append(("Wazuh rule", _esc(f'{rec["rule_id"]} (level {rec["rule_level"]})')))

    body = (_section_bar_html("Who")
            + _kv_table_html(["Field", "Value"], who_rows)
            + _section_bar_html("What")
            + _kv_table_html(["Field", "Value"], what_rows)
            + _section_bar_html("What changed (old → new)"))
    for r in rec["resources"]:
        if not r["changes"]:
            continue
        label = r["display"] or r["rtype"] or "resource"
        body += (f'<div style="{_FONT}font-size:13px;font-weight:bold;color:#0f172a;margin:8px 0 4px;">'
                 f'{_esc(label)}</div>')
        diff_rows = []
        for c in r["changes"]:
            old = f'<span style="color:#b3261e;">{_esc(c["old"])}</span>'
            new = f'<span style="color:#1a7f37;">{_esc(c["new"])}</span>'
            diff_rows.append((_esc(c["name"]), old, new))
        body += _kv_table_html(["Property", "Old", "New"], diff_rows)

    return _html_page(_esc(title), intro, body)

def build_ticket_text(rec, is_test=False):
    L = []
    if is_test:
        L.append("*** TEST mail — dedup DB not modified ***")
    L.append(f"{_short_source(rec)} config change by global admin")
    L.append("=" * 72)
    L.append(f"Actor       : {rec['actor_upn'] or rec['actor_id']}")
    L.append(f"Actor type  : {rec['actor_type']}")
    if rec["actor_app"]:
        L.append(f"Application : {rec['actor_app']}")
    if rec["actor_ip"]:
        L.append(f"Source IP  : {rec['actor_ip']}")
    L.append(f"Global admin: {rec.get('ga_reason', 'yes')}")
    L.append(f"When        : {_fmt_ts(rec['when'])}")
    L.append("")
    L.append(f"Action      : {rec['action']}")
    L.append(f"Operation   : {rec['operation']}    Result: {rec['result']}")
    L.append(f"Category    : {rec['category']}    Source: {rec['source_kind']}")
    if rec["correlation_id"]:
        L.append(f"Correlation : {rec['correlation_id']}")
    L.append(f"Wazuh rule  : {rec['rule_id']} (level {rec['rule_level']})")
    L.append("")
    L.append("Changes (old -> new):")
    for r in rec["resources"]:
        if not r["changes"]:
            continue
        L.append(f"  [{r['display'] or r['rtype'] or 'resource'}]")
        for c in r["changes"]:
            L.append(f"    - {c['name']}: {c['old']}  ->  {c['new']}")
    L.append("")
    L.append(f"Dashboard: {DASHBOARD_URL}")
    return "\n".join(L)

# =====================================================================
# SMTP  [bruteforce-success_digest.py:338]
# =====================================================================

def send_mail(recipients, subject, text_body, html_body=None,
              smtp_server=SMTP_SERVER, smtp_port=SMTP_PORT):
    em = EmailMessage()
    em["From"] = MAIL_FROM
    em["To"] = ", ".join(recipients)
    em["Subject"] = subject
    em.set_content(text_body)                  # plain-text fallback
    if html_body:
        em.add_alternative(html_body, subtype="html")
    with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as s:
        s.ehlo()
        s.send_message(em)

# =====================================================================
# Core: gather -> gate to global admins -> keep real changes
# =====================================================================

def gather_admin_changes(client, conn, args):
    """Return the list of global-admin config-change records (with real diffs)
    in the window. Uses the state DB only for the Graph global-admin cache."""
    hits = collect_admin_change_events(client, args.index_pattern, args.lookback_hours)
    records = [r for r in (classify_event(h) for h in hits) if r]
    intune = [r for r in records if r["source"] == "intune"]
    entra  = [r for r in records if r["source"] == "entra"]
    print(f"[gather] window={args.lookback_hours}h ms-graph_change_events={len(records)} "
          f"(intune={len(intune)} entra={len(entra)})")

    ga_ids = get_global_admin_ids(conn) if entra else set()

    kept = []
    skipped_entra = 0
    for r in records:
        if r["source"] == "intune":
            if not r["ga_perm"]:
                continue
            r["ga_reason"] = "userPermissions [*]"
        else:  # entra
            if ga_ids is None:
                skipped_entra += 1
                continue
            if r["actor_id"] not in ga_ids:
                continue
            r["ga_reason"] = "Graph: Global Administrator"
        # keep only properties that actually changed
        total = 0
        for res in r["resources"]:
            res["changes"] = real_changes(res["modified"])
            total += len(res["changes"])
        if total == 0:
            continue     # no-op patch (all properties unchanged) -> skip
        kept.append(r)

    if skipped_entra:
        print(f"[gather] skipped {skipped_entra} Entra event(s): global-admin set unavailable")
    print(f"[gather] global-admin config changes with real diffs: {len(kept)}")
    return kept

# =====================================================================
# Modes
# =====================================================================

def _verify_arg(args):
    verify = False if args.no_verify else (args.ca if args.ca else True)
    if isinstance(verify, str) and not os.access(verify, os.R_OK):
        raise SystemExit(
            f"CA file not readable: {verify} (run as a user that can read it, or use --no-verify)")
    return verify

def _make_client(args):
    """Build the indexer client. Prefer the admin client cert (mTLS); fall back to
    INDEX_PASSWORD if the cert files are absent/unreadable."""
    verify = _verify_arg(args)
    cert = args.cert if (args.cert and os.access(args.cert, os.R_OK)) else None
    key  = args.key  if (args.key  and os.access(args.key,  os.R_OK)) else None
    if not cert and not args.password:
        raise SystemExit(
            "No indexer auth: provide the admin cert (--cert /etc/wazuh-indexer/certs/admin.pem "
            "--key .../admin-key.pem) readable by this user, or set INDEX_PASSWORD.")
    if cert:
        print(f"[auth] indexer via client certificate {cert}")
    else:
        print("[auth] indexer via username/password")
    return _get_client(args.index_url, args.user, args.password, verify=verify,
                       client_cert=cert, client_key=key)

def _recipients(args):
    return [x.strip() for x in (args.recipients or RECIPIENTS).split(",") if x.strip()]

def _connect_state(path):
    """Open the persistent state DB with a clear error (not a bare sqlite
    OperationalError) and create its parent directory if missing."""
    path = (path or "").strip() or STATE_DB
    if os.path.isdir(path):
        raise SystemExit(f"--state-db / STATE_DB points to a directory, not a file: {path} "
                         "(use e.g. /opt/entra-config-changes-digest/state.db)")
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            raise SystemExit(f"Cannot create state-DB directory {d}: {e}")
    try:
        return sqlite3.connect(path)
    except sqlite3.OperationalError as e:
        raise SystemExit(f"Cannot open state DB '{path}': {e}. "
                         "Check --state-db / STATE_DB and that its directory is writable.")

def run_notify(args):
    client = _make_client(args)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = _connect_state(args.state_db)
    try:
        init_db(conn)
        # Use an explicit seed marker, not "is notified empty" -- admin changes are
        # rare, so a legitimate zero-change baseline must still count as seeded.
        seeded = conn.execute("SELECT v FROM meta WHERE k='seeded_at'").fetchone()
        if not seeded and not args.seed and not args.dry_run:
            raise SystemExit(
                "State DB has no baseline. Run once with --seed to record current "
                "admin changes (no email), then schedule the notify run. "
                "Use --dry-run to preview without seeding.")

        kept = gather_admin_changes(client, conn, args)

        if args.seed:
            for r in kept:
                mark_notified(conn, r, now)
            conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('seeded_at', ?)", (now,))
            conn.commit()
            print(f"[seed] baselined {len(kept)} admin change(s) into {args.state_db}. No email.")
            return

        already = {row[0] for row in conn.execute("SELECT event_key FROM notified")}
        new = [r for r in kept if event_key(r) not in already]
        print(f"[notify] new (not yet notified): {len(new)}")

        if args.dry_run:
            for r in new:
                print("  NEW:", ticket_subject(r))
            print(f"[dry-run] would send {len(new)} ticket(s); recipients={_recipients(args)!r}")
            return

        if not new:
            print("[notify] nothing new this run; no email sent.")
            return

        recipients = _recipients(args)
        if not recipients:
            raise SystemExit("No recipients configured (set RECIPIENTS or --recipients).")

        sent, errs = 0, 0
        for r in new:
            try:
                send_mail(recipients, ticket_subject(r),
                          build_ticket_text(r), build_ticket_html(r),
                          smtp_server=args.smtp_server, smtp_port=args.smtp_port)
                mark_notified(conn, r, now)
                sent += 1
            except Exception as e:
                errs += 1
                print(f"[notify] send failed for {event_key(r)}: {e}")
        conn.commit()
        print(f"[notify] sent {sent} ticket(s) to {recipients}"
              + (f" ({errs} error(s))" if errs else ""))
    finally:
        conn.close()

def run_test(args):
    """Send a sample ticket from the most recent matching event. No DB change
    (except the Graph cache, which is harmless)."""
    client = _make_client(args)

    # A test never persists state; use an in-memory DB so it works regardless of the
    # --state-db path (and writes nothing).
    conn = sqlite3.connect(":memory:")
    try:
        init_db(conn)
        kept = gather_admin_changes(client, conn, args)
    finally:
        conn.close()

    if not kept:
        raise SystemExit("No global-admin config change found in the window to build a test from. "
                         "Try a larger --lookback-hours.")
    # most recent by 'when'
    rec = sorted(kept, key=lambda r: r.get("when", ""), reverse=True)[0]
    subject = ticket_subject(rec, is_test=True)
    text_body = build_ticket_text(rec, is_test=True)
    html_body = build_ticket_html(rec, is_test=True)

    if args.dry_run:
        print("----- SUBJECT -----"); print(subject)
        print("----- TEXT BODY -----"); print(text_body)
        print(f"----- [dry-run] HTML {len(html_body)} bytes -----")
        return
    recipients = _recipients(args)
    if not recipients:
        raise SystemExit("No recipients configured (set RECIPIENTS or --recipients).")
    send_mail(recipients, subject, text_body, html_body,
              smtp_server=args.smtp_server, smtp_port=args.smtp_port)
    print(f"[test] sample ticket sent to {recipients} via {args.smtp_server}:{args.smtp_port}")

def main():
    ap = argparse.ArgumentParser(
        description="Email notify-once tickets for Microsoft Entra/Intune config changes "
                    "made by global admins, read from the Wazuh Indexer.")
    ap.add_argument("--index-url", default=INDEX_URL,
                    help="Wazuh Indexer URL (env INDEX_URL; default https://127.0.0.1:9200)")
    ap.add_argument("--user", default=INDEX_USER, help="indexer user (env INDEX_USER; default admin)")
    ap.add_argument("--password", default=INDEX_PASSWORD,
                    help="indexer password (prefer the INDEX_PASSWORD env var)")
    ap.add_argument("--index-pattern", default=INDEX_PATTERN,
                    help="alerts index pattern (env INDEX_PATTERN; default wazuh-alerts-4.x-*)")
    ap.add_argument("--no-verify", action="store_true", default=NO_VERIFY,
                    help="skip TLS verification of the indexer certificate (env NO_VERIFY)")
    ap.add_argument("--ca", default=CA,
                    help="CA bundle for indexer TLS verification (env CA; "
                         "default /etc/wazuh-indexer/certs/root-ca.pem)")
    ap.add_argument("--cert", default=INDEX_CLIENT_CERT,
                    help="client certificate for indexer mTLS auth (env INDEX_CLIENT_CERT; "
                         "unset = use INDEX_PASSWORD). e.g. /etc/wazuh-indexer/certs/admin.pem")
    ap.add_argument("--key", default=INDEX_CLIENT_KEY,
                    help="client key for indexer mTLS auth (env INDEX_CLIENT_KEY; "
                         "e.g. /etc/wazuh-indexer/certs/admin-key.pem)")
    ap.add_argument("--lookback-hours", type=int, default=LOOKBACK_HOURS,
                    help="how many hours back to scan (env LOOKBACK_HOURS; default 24)")
    ap.add_argument("--recipients", default=RECIPIENTS,
                    help="comma-separated recipient list (env RECIPIENTS)")
    ap.add_argument("--smtp-server", default=SMTP_SERVER,
                    help="SMTP relay host (env SMTP_SERVER; default smtp.example.com)")
    ap.add_argument("--smtp-port", type=int, default=SMTP_PORT,
                    help="SMTP port (env SMTP_PORT; default 25)")
    ap.add_argument("--state-db", default=STATE_DB, help="sqlite dedup DB path (env STATE_DB)")
    ap.add_argument("--dashboard-url", default=DASHBOARD_URL,
                    help="Wazuh dashboard base URL for the email footer")
    ap.add_argument("--seed", action="store_true",
                    help="baseline current admin changes (no email), then exit")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be sent; send no email, no DB change")
    ap.add_argument("--test", action="store_true",
                    help="send a sample ticket from the most recent matching event; no DB change")
    args = ap.parse_args()

    if args.test:
        run_test(args)
    else:
        run_notify(args)

if __name__ == "__main__":
    main()
