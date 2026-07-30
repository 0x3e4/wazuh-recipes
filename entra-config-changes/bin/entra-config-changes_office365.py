#!/usr/bin/env python3
"""Office 365 admin config-change tickets — reads the Wazuh Indexer (office365 events).

Companion to entra-config-changes_graph.py. The Graph poller covers Entra/Intune;
Microsoft Graph does NOT expose Exchange, Defender, Security & Compliance, Purview or
DLP admin changes — those live only in the **Office 365 Management Activity API**
(Unified Audit Log), which Wazuh's `<office365>` module already ingests into the indexer
(rule.groups:office365, data.office365.*). This script reads those events, keeps only
*configuration changes made by an admin*, and emails ONE notify-once ticket per change
(SQLite dedup), showing who / what / the parameters set.

Why a separate script (not the Graph poller): office365 is a different API/schema and is
already in the indexer, so this is an indexer reader — like the original
entra-config-changes_digest.py — with an office365 classifier bolted on. It runs on its
own timer and shares nothing with the poller except conventions.

Key schema facts (validated against the real tenant, 30d):
  * 87% of office365 volume is the `Endpoint` file-activity firehose + Teams/SharePoint
    file access — NOT config. We filter hard to admin surfaces + mutating operations.
  * Admin cmdlet events (Exchange RecordType 1, Security & Compliance RecordType 18) carry
    UserType=2 (Admin) and a PowerShell `Parameters` string (not old->new) — rendered as a
    "parameters set" table.
  * AzureActiveDirectory (RecordType 8) overlaps the Graph directoryAudits poller and is
    full of system service-principal noise -> excluded by default (poller owns Entra).

Config comes from the environment / an env file (see *.env.example). Standard library +
opensearch-py only. Indexer auth is HTTP basic (INDEX_USER/INDEX_PASSWORD; on this box the
working credential is admin / WAZUH_INDEXER_PASSWORD) or mTLS if a readable client cert is
given.
"""
import os
import re
import sys
import json
import html
import smtplib
import sqlite3
import hashlib
import argparse
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

# opensearch-py may live in a venv or a shared lib dir; allow pointing at it.
_LIB = os.environ.get("WAZUH_RECIPES_LIB", "/opt/wazuh-recipes/lib")
if _LIB and os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

TOPIC = "Microsoft 365 admin config change"

# =====================================================================
# Config  (env / .env -- NO hardcoded secrets)
# =====================================================================

INDEX_URL      = os.environ.get("INDEX_URL", "https://127.0.0.1:9200")
INDEX_USER     = os.environ.get("INDEX_USER", "admin")
# On this box the working indexer credential is admin / WAZUH_INDEXER_PASSWORD; accept
# INDEX_PASSWORD too so this matches the other recipes' convention.
INDEX_PASSWORD = os.environ.get("INDEX_PASSWORD") or os.environ.get("WAZUH_INDEXER_PASSWORD", "")
INDEX_PATTERN  = os.environ.get("INDEX_PATTERN", "wazuh-alerts-4.x-*")
CA             = os.environ.get("CA", "/etc/wazuh-indexer/certs/root-ca.pem")
NO_VERIFY      = os.environ.get("NO_VERIFY", "").strip().lower() in ("1", "true", "yes", "on")
INDEX_CLIENT_CERT = os.environ.get("INDEX_CLIENT_CERT", "")
INDEX_CLIENT_KEY  = os.environ.get("INDEX_CLIENT_KEY", "")

SMTP_SERVER    = os.environ.get("SMTP_SERVER", "smtp.example.com")
SMTP_PORT      = int(os.environ.get("SMTP_PORT", "25"))
MAIL_FROM      = os.environ.get("MAIL_FROM", "wazuh@example.com")
RECIPIENTS     = os.environ.get("RECIPIENTS", "")
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "https://wazuh.example.com")
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "24"))
STATE_DB       = os.environ.get("STATE_DB", "/opt/entra-config-changes-digest/office365-state.db")
SUPPRESS_NOISE = os.environ.get("SUPPRESS_NOISE", "1").strip().lower() in ("1", "true", "yes", "on")
GROUP_TICKETS  = os.environ.get("GROUP_TICKETS", "1").strip().lower() in ("1", "true", "yes", "on")
DISPLAY_TZ     = os.environ.get("DISPLAY_TZ", "Europe/Vienna")

# --- office365 filtering knobs ---
# Actor UserTypes treated as "privileged admin" (0=Regular 2=Admin 3=DcAdmin 4=System
# 5=Application 6=ServicePrincipal 10=CustomPolicy). Default: real *human* admins only —
# this deliberately EXCLUDES application/service-principal automation (e.g. Defender's own
# AddIndicator IoC sync, app-driven cmdlets), which is high-volume audit noise, not an
# admin decision. Widen only if you truly want app/system-driven changes.
ADMIN_USERTYPES = {x.strip() for x in os.environ.get("ADMIN_USERTYPES", "2,3").split(",") if x.strip()}
# Opt-in escape hatch: workloads where ANY config op is kept regardless of UserType (i.e.
# app/automation included). EMPTY by default — leaving it empty is what keeps automation
# noise out. Set e.g. "Exchange" only if you want app-driven Exchange changes too.
ALWAYS_ADMIN_WORKLOADS = {x.strip() for x in os.environ.get(
    "ALWAYS_ADMIN_WORKLOADS", "").split(",") if x.strip()}
# Workloads to PULL from the indexer (query include). Firehose/file workloads are excluded.
OFFICE365_WORKLOADS = [x.strip() for x in os.environ.get(
    "OFFICE365_WORKLOADS",
    "Exchange,SecurityComplianceCenter,MicrosoftDefenderForEndpoint,Microsoft365Defender,"
    "Microsoft365DefenderPortal,MicrosoftDefenderExperts,MicrosoftDefenderForIdentity,"
    "MicrosoftDefenderForCloudApps,ThreatIntelligence,PowerPlatform,Purview,Mip"
    ).split(",") if x.strip()]
# Defender/XDR "settings" surfaces. Admin config there uses portal action names (not
# Verb-Noun cmdlets), so on these workloads we keep ANY human-admin operation that is not an
# obvious read / SOC-operational action (default-allow minus the deny substrings below).
# NOTE: events only flow once Defender's "Unified audit log" advanced feature is ON
# (Settings > Endpoints > General > Advanced features).
DEFENDER_SETTINGS_WORKLOADS = {x.strip() for x in os.environ.get(
    "DEFENDER_SETTINGS_WORKLOADS",
    "MicrosoftDefenderForEndpoint,Microsoft365Defender,Microsoft365DefenderPortal,"
    "MicrosoftDefenderExperts,MicrosoftDefenderForIdentity,MicrosoftDefenderForCloudApps"
    ).split(",") if x.strip()}
# Substrings that mark an operation on a settings workload as a read / SOC-operational
# action (dropped). Everything else there is treated as a config change.
_SETTINGS_DENY_SUBSTR = {x.strip().lower() for x in os.environ.get(
    "OFFICE365_SETTINGS_DENY",
    "search,validate,get,list,view,read,export,preview,aggregate,authorize,incident,"
    "remediat,isolat,response,investigat,hunt,query,signin,logon,login,alert,scan,"
    "comment,triage,submission,download,detail").split(",") if x.strip()}
# Extra single-token (non "Verb-Noun") operations to treat as config changes, pulled even
# from otherwise-noisy workloads (Teams/SharePoint). Case-insensitive.
CURATED_OPS = {x.strip().lower() for x in os.environ.get(
    "OFFICE365_CURATED_OPS",
    "TeamsAdminAction,AddIndicator,SecurityRoleUpdated,SecurityRoleCreated").split(",") if x.strip()}
# Exclude AzureActiveDirectory (RecordType 8) — the Graph poller already covers Entra.
EXCLUDE_AAD = os.environ.get("OFFICE365_EXCLUDE_AAD", "1").strip().lower() in ("1", "true", "yes", "on")
# Self-service / per-user Exchange cmdlets. Outlook/OWA run these on the user's OWN mailbox
# when someone changes their personal settings (calendar, language, auto-reply, junk, inbox
# rules, ...). Exchange logs them as admin-style Set-*/New-* cmdlets, often with
# UserType=Admin, but they are NOT admin configuration changes -- classic Exchange audit
# noise. Dropped outright. (This collector has no directory lookup, so it can't prove
# actor==mailbox-owner structurally; an explicit deny-list is the reliable filter.)
# NOTE: inbox-rule creation can be security-relevant (auto-forwarding used in BEC) -- but
# that is a per-user detection concern, not admin config; handle it in a dedicated rule.
IGNORE_OPS = {x.strip().lower() for x in os.environ.get(
    "OFFICE365_IGNORE_OPS",
    "Set-MailboxCalendarConfiguration,Set-MailboxRegionalConfiguration,"
    "Set-MailboxMessageConfiguration,Set-MailboxAutoReplyConfiguration,"
    "Set-MailboxCalendarFolder,Set-MailboxSpellingConfiguration,"
    "Set-MailboxJunkEmailConfiguration,Set-MailboxSearchPreference,"
    "Set-UserPhoto,Remove-UserPhoto,Set-Clutter,Set-FocusedInbox,Set-MailboxProfile,"
    "New-InboxRule,Set-InboxRule,Remove-InboxRule,Enable-InboxRule,Disable-InboxRule"
    ).split(",") if x.strip()}
# PowerShell common/uninteresting parameters to drop from the rendered parameter table.
IGNORE_PARAMS = {x.strip().lower() for x in os.environ.get(
    "OFFICE365_IGNORE_PARAMS",
    "confirm,whatif,erroraction,warningaction,force,verbose,debug,outvariable,outbuffer,"
    "pipelinevariable,informationaction,warningvariable,errorvariable,progressaction").split(",") if x.strip()}
# Actor identities (matched against UserId / UserKey / ClientApplication) that are Microsoft
# datacenter/service principals, NOT humans. They report UserType=Admin yet only run
# automated, non-human cmdlets (e.g. `NT SERVICE\MSExchangeAdminApiNetCore` running
# Remove-StoreMailbox), so they are dropped regardless of Operation/UserType. Case-insensitive
# substring match. Extend via the env var (comma-separated substrings).
ACTOR_DENY_SUBSTR = {x.strip().lower() for x in os.environ.get(
    "OFFICE365_ACTOR_DENY",
    "nt service\\,nt authority\\").split(",") if x.strip()}

_ACCENT = "#b3261e"
_MAX_VAL_LEN = 300

# Verb classification for "Verb-Noun" cmdlet operations.
_MUTATING_VERBS = {"new", "set", "remove", "enable", "disable", "update", "add", "grant",
                   "revoke", "install", "uninstall", "import", "restore", "register",
                   "unregister", "rotate", "move", "rename", "reset", "clear"}
_READONLY_VERBS = {"get", "search", "test", "measure", "resolve", "export", "preview",
                   "find", "select", "compare", "read", "list", "view", "validate",
                   "aggregate", "authorize", "save", "sync", "invoke", "receive", "send",
                   "out", "format", "where", "sort", "group", "convertto", "convertfrom",
                   "trace", "watch"}
# Nouns that are operational even under a mutating verb (SOC actions, not config).
_OPERATIONAL_NOUNS = {"quarantinemessage"}

WORKLOAD_LABEL = {
    "Exchange":                    ("Exchange", "Exchange Online admin (Management Activity)"),
    "SecurityComplianceCenter":    ("Sec&Comp", "Security & Compliance / Purview (Management Activity)"),
    "MicrosoftDefenderForEndpoint":("Defender", "Defender for Endpoint (Management Activity)"),
    "ThreatIntelligence":          ("Defender", "Defender for Office 365 (Management Activity)"),
    "PowerPlatform":               ("PowerPlatform", "Power Platform (Management Activity)"),
    "MicrosoftTeams":              ("Teams", "Microsoft Teams admin (Management Activity)"),
    "SharePoint":                  ("SharePoint", "SharePoint admin (Management Activity)"),
    "OneDrive":                    ("OneDrive", "OneDrive admin (Management Activity)"),
    "Purview":                     ("Purview", "Microsoft Purview (Management Activity)"),
    "Mip":                         ("Purview", "Purview Information Protection (Management Activity)"),
}
USERTYPE_LABEL = {"0": "Regular user", "1": "Reserved", "2": "Admin", "3": "Datacenter admin",
                  "4": "System", "5": "Application", "6": "Service principal",
                  "7": "Custom policy", "8": "System policy", "10": "Custom policy"}

# =====================================================================
# Wazuh Indexer (OpenSearch) connection helper
# =====================================================================

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
        raise SystemExit("Install opensearch-py (pip install opensearch-py) or set "
                         "WAZUH_RECIPES_LIB to a directory that contains it.") from e

# =====================================================================
# Indexer query -- office365 admin-surface events in the window
# =====================================================================

_SOURCE_FIELDS = ["timestamp", "rule.id", "rule.description", "rule.level",
                  "agent.name", "data.office365"]

def collect_office365_events(client, index_pattern, lookback_hours):
    """Page office365 events limited to admin-surface workloads (or curated ops), never the
    Endpoint/file firehose. Final config/actor narrowing is done in Python (classify)."""
    gte = f"now-{int(lookback_hours)}h"
    should = [{"terms": {"data.office365.Workload": OFFICE365_WORKLOADS}}]
    if CURATED_OPS:
        # match on the original-case operation names too (keyword field is case-sensitive)
        should.append({"terms": {"data.office365.Operation":
                                 [o for o in os.environ.get(
                                     "OFFICE365_CURATED_OPS",
                                     "TeamsAdminAction,AddIndicator,SecurityRoleUpdated,"
                                     "SecurityRoleCreated").split(",") if o.strip()]}})
    body = {
        "size": 1000,
        "_source": _SOURCE_FIELDS,
        "sort": ["_doc"],
        "query": {"bool": {
            "filter": [
                {"term": {"rule.groups": "office365"}},
                {"range": {"timestamp": {"gte": gte}}},
            ],
            "should": should,
            "minimum_should_match": 1,
            "must_not": [
                {"terms": {"data.office365.Workload": ["Endpoint", "PublicEndpoint"]}},
            ],
        }},
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
# Helpers
# =====================================================================

def _g(d, *path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default

def op_kind(operation):
    """Classify an Operation:
      'cmdlet'  -- a mutating "Verb-Noun" admin cmdlet (Set-/New-/Remove-/Enable-/...); a
                   genuine configuration change. RBAC means only an authorised admin could
                   run it, so it is kept regardless of the (unreliable) UserType.
      'curated' -- a whitelisted single-token admin op (TeamsAdminAction, AddIndicator, ...).
                   These are automation-prone, so they additionally require a human UserType.
      None      -- not a configuration change (read / triage / file / activity)."""
    op = str(operation or "").strip()
    if not op:
        return None
    if op.lower() in CURATED_OPS:
        return "curated"
    if "-" in op:                         # PowerShell "Verb-Noun" cmdlet
        verb, noun = op.split("-", 1)
        v, n = verb.strip().lower(), noun.strip().lower()
        if v in _READONLY_VERBS:
            return None
        if n in _OPERATIONAL_NOUNS:
            return None
        if v in _MUTATING_VERBS:
            return "cmdlet"
    return None

def is_settings_change(operation):
    """For Defender/XDR settings workloads: True unless the operation is an obvious read /
    SOC-operational action. Default-allow so unknown config ops are still captured."""
    low = str(operation or "").strip().lower()
    if not low:
        return False
    return not any(s in low for s in _SETTINGS_DENY_SUBSTR)

def classify_kind(operation, workload):
    """Full config-change classification: mutating cmdlet, curated op, Defender settings-
    workload change, or None."""
    kind = op_kind(operation)
    if kind is None and workload in DEFENDER_SETTINGS_WORKLOADS and is_settings_change(operation):
        return "curated"   # human-gated like other curated ops
    return kind

def is_config_op(operation, workload=None):
    return classify_kind(operation, workload) is not None

# ---- PowerShell audit `Parameters` string parsing -------------------
# e.g.  -Identity "Default" -Enabled $true -Domains ("a.com","b.com") -Recipient (@ENC@..)
_PARAM_BOUNDARY = re.compile(r'(?:^|\s)-([A-Za-z][A-Za-z0-9]*)')

def parse_cmdlet_parameters(param_str):
    """Best-effort parse of an audit Parameters string into [(name, raw_value)]. A value is
    everything up to the next ' -Param' boundary (handles quotes and (..) lists). Switch
    params with no value yield ''. Falls back to [] if nothing parses."""
    s = str(param_str or "").strip()
    if not s:
        return []
    marks = list(_PARAM_BOUNDARY.finditer(s))
    if not marks:
        return []
    out = []
    for i, m in enumerate(marks):
        name = m.group(1)
        v0 = m.end()
        v1 = marks[i + 1].start() if i + 1 < len(marks) else len(s)
        out.append((name, s[v0:v1].strip()))
    return out

def _display_param_value(v):
    s = str(v if v is not None else "").strip()
    if s == "":
        return "(set)"                      # bare switch, e.g. -Enabled
    if "@ENC@" in s:
        return "(encrypted by Microsoft)"
    # Normalise only the PowerShell literals; leave quoted strings verbatim (audit fidelity).
    if s.lower() == "$true":
        return "true"
    if s.lower() == "$false":
        return "false"
    if s.lower() == "$null":
        return "(none)"
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    if len(s) > _MAX_VAL_LEN:
        s = s[:_MAX_VAL_LEN] + " …"
    return s

def _param_value(params, name):
    for n, v in params:
        if n.lower() == name.lower():
            return _display_param_value(v)
    return ""

_NULLISH = {"", "null", "<null>", "[]", "none", "not available"}
_NOISE_PROP_NAMES = {"included updated properties"}

def _norm(v):
    if v is None:
        return ""
    s = str(v).strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1].strip()
    return "" if s.lower() in _NULLISH else s

def _is_placeholder(s):
    s = str(s)
    return s.startswith("System.") or s.startswith("Microsoft.") or s.startswith("$Collection")

def _trunc(s):
    return s[:_MAX_VAL_LEN] + " …" if len(s) > _MAX_VAL_LEN else s

def changes_from_modified(mods):
    """Build change rows from a Management-Activity `ModifiedProperties` list
    ([{Name, OldValue, NewValue}]). Keeps only properties that actually changed and drops
    opaque .NET placeholder values under SUPPRESS_NOISE."""
    out = []
    for mp in mods:
        if not isinstance(mp, dict):
            continue
        name = str(mp.get("Name") or mp.get("displayName") or "")
        if name.strip().lower() in _NOISE_PROP_NAMES:
            continue
        old_n = _norm(mp.get("OldValue", mp.get("oldValue")))
        new_n = _norm(mp.get("NewValue", mp.get("newValue")))
        if old_n == new_n:
            continue
        if SUPPRESS_NOISE and (_is_placeholder(old_n) or _is_placeholder(new_n)):
            continue
        out.append({"name": name,
                    "old": _trunc(old_n) if old_n else "(none)",
                    "new": _trunc(new_n) if new_n else "(none)"})
    return out

# =====================================================================
# Classification -- one office365 event -> the uniform record shape
# =====================================================================

def classify_event(hit):
    src = hit.get("_source", {}) or {}
    o = _g(src, "data", "office365", default={})
    if not isinstance(o, dict) or not o:
        return None

    workload = str(o.get("Workload") or "")
    record_type = str(o.get("RecordType") or "")
    operation = str(o.get("Operation") or "")

    if EXCLUDE_AAD and record_type == "8":
        return None
    if operation.strip().lower() in IGNORE_OPS:   # self-service / per-user cmdlets -> noise
        return None
    kind = classify_kind(operation, workload)
    if kind is None:
        return None

    usertype = str(o.get("UserType") or "")
    # Mutating cmdlets are genuine config changes (RBAC-gated) -> keep regardless of the
    # unreliable UserType. Curated single-token ops are automation-prone -> require a human
    # admin UserType (this is what keeps Defender's AddIndicator IoC sync and similar out).
    if kind == "curated" and usertype not in ADMIN_USERTYPES and workload not in ALWAYS_ADMIN_WORKLOADS:
        return None

    actor = str(o.get("UserId") or o.get("UserKey") or "")
    # Drop Microsoft datacenter/service identities: they report UserType=Admin yet only run
    # automated, non-human cmdlets (e.g. NT SERVICE\MSExchange... running Remove-StoreMailbox).
    if ACTOR_DENY_SUBSTR:
        _actor_probe = (actor + " " + str(o.get("ClientApplication") or "")).lower()
        if any(pat in _actor_probe for pat in ACTOR_DENY_SUBSTR):
            return None
    params = parse_cmdlet_parameters(o.get("Parameters"))
    mods = o.get("ModifiedProperties")
    mods = mods if isinstance(mods, list) else []

    # Build the "what changed" rows. Prefer the cmdlet `Parameters` (Exchange / Security &
    # Compliance); cmdlet params have no previous value, so old="(none)" -> the renderer
    # shows a Parameter/Value table. Fall back to `ModifiedProperties` (old->new) for
    # non-cmdlet records (e.g. TeamsAdminAction, tenant settings).
    changes = []
    if params:
        for name, raw in params:
            if name.lower() in IGNORE_PARAMS:
                continue
            changes.append({"name": name, "old": "(none)", "new": _display_param_value(raw)})
    elif mods:
        changes = changes_from_modified(mods)

    # Object being changed: -Identity / -Name, else ObjectId, else a ModifiedProperties
    # displayName, else the workload.
    obj = (_param_value(params, "Identity") or _param_value(params, "Name")
           or str(o.get("ObjectId") or ""))
    if not obj:
        for mp in mods:
            if isinstance(mp, dict) and str(mp.get("Name", "")).lower() in ("displayname", "objectdisplayname"):
                obj = _norm(mp.get("NewValue") or mp.get("OldValue"))
                if obj:
                    break
    obj = obj or workload

    short, label = WORKLOAD_LABEL.get(workload, (workload or "M365", f"{workload} (Management Activity)"))
    ut_label = USERTYPE_LABEL.get(usertype, usertype or "?")
    if kind == "cmdlet":
        reason = f"admin cmdlet ({operation.split('-', 1)[0]}-*), UserType={ut_label}"
    else:
        reason = f"admin op, UserType={ut_label}"

    return {
        "alert_id":   hit.get("_id", ""),
        "rule_id":    str(_g(src, "rule", "id", default="")),
        "rule_level": str(_g(src, "rule", "level", default="")),
        "agent":      _g(src, "agent", "name", default=""),
        "event_id":   str(o.get("Id") or ""),
        "correlation_id": "",
        "category":   label,
        "when":       str(o.get("CreationTime") or _g(src, "timestamp", default="") or ""),
        "source":     "office365",
        "workload":   workload,
        "short":      short,
        "source_kind": label,
        "record_type": record_type,
        "_usertype":  usertype,
        "actor_upn":  actor,
        "actor_id":   actor,
        "actor_type": USERTYPE_LABEL.get(usertype, usertype or ""),
        "actor_app":  str(o.get("ClientApplication") or ""),
        "actor_ip":   str(o.get("ClientIP") or o.get("ActorIpAddress") or ""),
        "ga_reason":  reason,
        "action":     operation,
        "operation":  f"RecordType {record_type}",
        "result":     str(o.get("ResultStatus") or ""),
        "resources":  [{"display": obj, "rtype": short, "changes": changes}],
    }

def event_key(rec):
    if rec.get("event_id"):
        return rec["event_id"]
    raw = "|".join([rec.get("actor_id", ""), rec.get("when", ""),
                    rec.get("action", ""), rec.get("workload", "")])
    return hashlib.sha256(raw.encode()).hexdigest()

# =====================================================================
# State DB (notify-once)
# =====================================================================

def _connect_state(path):
    path = (path or "").strip() or STATE_DB
    if os.path.isdir(path):
        raise SystemExit(f"--state-db / STATE_DB points to a directory, not a file: {path}")
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            raise SystemExit(f"Cannot create state-DB directory {d}: {e}")
    try:
        return sqlite3.connect(path)
    except sqlite3.OperationalError as e:
        raise SystemExit(f"Cannot open state DB '{path}': {e}")

def init_db(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS notified (
        event_key TEXT PRIMARY KEY, source TEXT, actor TEXT, action TEXT,
        resource TEXT, changed_at TEXT, notified_at TEXT)""")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    conn.commit()

def mark_notified(conn, rec, now):
    res = "; ".join(r["display"] for r in rec["resources"] if r["display"])[:400]
    conn.execute("INSERT OR REPLACE INTO notified"
                 "(event_key, source, actor, action, resource, changed_at, notified_at)"
                 " VALUES (?,?,?,?,?,?,?)",
                 (event_key(rec), rec["source"], rec["actor_upn"], rec["action"], res,
                  rec.get("when", ""), now))

# =====================================================================
# Rendering  (mirrors entra-config-changes_graph.py)
# =====================================================================

def _esc(s):
    return html.escape(str(s if s is not None else ""))

_FONT = "font-family:'Segoe UI',Segoe,Tahoma,Arial,sans-serif;"

def _fmt_ts(ts):
    if not ts:
        return ""
    s = str(ts).strip()
    try:
        s2 = re.sub(r"(\.\d{6})\d+", r"\1", s.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if ZoneInfo is not None:
            dt = dt.astimezone(ZoneInfo(DISPLAY_TZ))
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return s.replace("T", " ")[:19]

def _kv_table_html(headers, rows):
    th = "".join(f'<th style="{_FONT}text-align:left;padding:6px 10px;background:#f1f5f9;'
                 f'border-bottom:1px solid #e2e8f0;font-size:12px;color:#475569;">{_esc(h)}</th>' for h in headers)
    body = []
    for i, row in enumerate(rows):
        bg = "#ffffff" if i % 2 == 0 else "#f8fafc"
        tds = "".join(f'<td style="{_FONT}padding:6px 10px;border-bottom:1px solid #eef2f6;'
                      f'font-size:13px;color:#0f172a;vertical-align:top;{ "white-space:nowrap;" if j == 0 else "" }">{cell}</td>'
                      for j, cell in enumerate(row))
        body.append(f'<tr bgcolor="{bg}" style="background:{bg};">{tds}</tr>')
    if not rows:
        body.append(f'<tr><td colspan="{len(headers)}" style="padding:8px 10px;color:#94a3b8;font-size:13px;">none</td></tr>')
    return ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border-collapse:collapse;border:1px solid #e2e8f0;margin:4px 0 14px;">'
            f'<tr>{th}</tr>{"".join(body)}</table>')

def _section_bar_html(label, barcolor="#334155"):
    return ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:18px 0 6px;"><tr>'
            f'<td bgcolor="{barcolor}" style="{_FONT}background:{barcolor};color:#ffffff;padding:6px 12px;'
            f'font-size:14px;font-weight:bold;">{_esc(label)}</td></tr></table>')

def _html_page(title_html, intro_html, body_html, accent=_ACCENT):
    return ('<!DOCTYPE html><html><head><meta charset="utf-8">'
            '<meta name="color-scheme" content="light dark"></head>'
            '<body style="margin:0;padding:0;background:#eef2f6;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#eef2f6">'
            '<tr><td align="center" style="padding:18px;">'
            '<table role="presentation" width="840" cellpadding="0" cellspacing="0" '
            "style=\"width:840px;max-width:840px;\">"
            f'<tr><td bgcolor="{accent}" style="{_FONT}background:{accent};color:#ffffff;padding:14px 18px;'
            f'font-size:18px;font-weight:bold;">{title_html}</td></tr>'
            f'<tr><td bgcolor="#ffffff" style="{_FONT}background:#ffffff;color:#1f2933;padding:16px 18px;'
            'border:1px solid #e3e8ef;border-top:none;">'
            f'{intro_html}{body_html}'
            f'<div style="{_FONT}margin-top:18px;font-size:11px;color:#94a3b8;border-top:1px solid #e3e8ef;'
            f'padding-top:8px;">Automated {_esc(TOPIC)} notification from Wazuh '
            f'(Office 365 Management Activity). Dashboard: '
            f'<a href="{_esc(DASHBOARD_URL)}" style="color:#2563eb;">{_esc(DASHBOARD_URL)}</a></div>'
            '</td></tr></table></td></tr></table></body></html>')

def _res_summary(rec):
    parts = []
    for r in rec["resources"]:
        if not r["display"]:
            continue
        parts.append(r["display"] + (f" ({r['rtype']})" if r["rtype"] else ""))
    return "; ".join(parts)

def ticket_subject(rec, is_test=False):
    action = (rec["action"] or "configuration change").strip()
    if len(action) > 100:
        action = action[:100] + "..."
    return f"{'[TEST] ' if is_test else ''}Wazuh: {rec['short']} config change: {action}"

def _who_rows(rec, include_when=True):
    rows = [("Actor", _esc(rec["actor_upn"] or rec["actor_id"] or "(unknown)")),
            ("Actor type", _esc(rec["actor_type"]))]
    if rec["actor_app"]:
        rows.append(("Client", _esc(rec["actor_app"])))
    if rec["actor_ip"]:
        rows.append(("Source IP", _esc(rec["actor_ip"])))
    rows.append(("Privileged admin", _esc(rec.get("ga_reason", "")) or "yes"))
    if include_when:
        rows.append(("When", _esc(_fmt_ts(rec["when"]))))
    return rows

def _resource_changes_html(r):
    out = (f'<div style="{_FONT}font-size:13px;font-weight:bold;color:#0f172a;margin:8px 0 4px;">'
           f'{_esc(r["display"] or r["rtype"] or "resource")}</div>')
    if all(c["old"] == "(none)" for c in r["changes"]):
        rows = [(_esc(c["name"]), f'<span style="color:#1a7f37;">{_esc(c["new"])}</span>') for c in r["changes"]]
        out += _kv_table_html(["Parameter", "Value"], rows)
        out += (f'<div style="{_FONT}font-size:11px;color:#94a3b8;margin:-8px 0 10px;">'
                f'Cmdlet parameters as recorded (no previous value in the audit log).</div>')
    else:
        rows = [(_esc(c["name"]), f'<span style="color:#b3261e;">{_esc(c["old"])}</span>',
                 f'<span style="color:#1a7f37;">{_esc(c["new"])}</span>') for c in r["changes"]]
        out += _kv_table_html(["Property", "Old", "New"], rows)
    return out

def _what_changes_html(rec):
    what = [("Operation", _esc(rec["action"] or "")),
            ("Result", _esc(rec["result"] or "")),
            ("Source", _esc(rec["source_kind"])),
            ("Record", _esc(rec["operation"] or "")),
            ("Target", _esc(_res_summary(rec)))]
    what.append(("Wazuh rule", _esc(f'{rec["rule_id"]} (level {rec["rule_level"]})')))
    body = _section_bar_html("What") + _kv_table_html(["Field", "Value"], what)
    body += _section_bar_html("What changed")
    shown = [_resource_changes_html(r) for r in rec["resources"] if r["changes"]]
    body += "".join(shown) if shown else f'<div style="{_FONT}font-size:13px;color:#94a3b8;">(no parameter detail recorded)</div>'
    return body

def build_ticket_html(rec, is_test=False):
    n = sum(len(r["changes"]) for r in rec["resources"])
    intro = (f'<p style="{_FONT}margin:0 0 12px;"><strong>{_esc(rec["actor_upn"] or rec["actor_id"])}</strong> '
             f'({_esc(rec["short"])}) performed '
             f'<strong>{_esc(rec["action"] or "a change")}</strong>: '
             f'<strong>{n}</strong> parameter(s).</p>')
    if is_test:
        intro = f'<p style="{_FONT}margin:0 0 8px;"><strong>This is a manual TEST mail.</strong></p>' + intro
    body = _section_bar_html("Who") + _kv_table_html(["Field", "Value"], _who_rows(rec)) + _what_changes_html(rec)
    return _html_page(f"{'[TEST] ' if is_test else ''}Admin config change", intro, body)

def build_group_ticket_html(recs, is_test=False):
    recs = _dedupe_events(recs)
    if len(recs) == 1:
        return build_ticket_html(recs[0], is_test)
    obj = _group_object(recs[0])
    actor = recs[0]["actor_upn"] or recs[0]["actor_id"]
    intro = (f'<p style="{_FONT}margin:0 0 12px;"><strong>{_esc(actor)}</strong> '
             f'({_esc(recs[0]["short"])}) made <strong>{len(recs)}</strong> configuration '
             f'change(s) to <strong>{_esc(obj)}</strong>.</p>')
    if is_test:
        intro = f'<p style="{_FONT}margin:0 0 8px;"><strong>This is a manual TEST mail.</strong></p>' + intro
    body = _section_bar_html("Who") + _kv_table_html(["Field", "Value"], _who_rows(recs[0], include_when=False))
    for rec in sorted(recs, key=lambda r: r.get("when", "")):
        body += (f'<div style="{_FONT}font-size:14px;font-weight:bold;color:#b3261e;margin:16px 0 0;">'
                 f'{_esc(rec["action"] or "change")} — {_esc(_fmt_ts(rec["when"]))}</div>')
        body += _what_changes_html(rec)
    return _html_page(f"{'[TEST] ' if is_test else ''}{len(recs)} config changes — {_esc(obj)}", intro, body)

def _what_changes_text(rec):
    L = [f"Operation   : {rec['action']}   result={rec['result']}",
         f"Source      : {rec['source_kind']}   ({rec['operation']})",
         f"Target      : {_res_summary(rec)}",
         f"Wazuh rule  : {rec['rule_id']} (level {rec['rule_level']})",
         "Parameters:"]
    for r in rec["resources"]:
        if not r["changes"]:
            continue
        allo = all(c["old"] == "(none)" for c in r["changes"])
        for c in r["changes"]:
            L.append(f"    - {c['name']}: {c['new']}" if allo else f"    - {c['name']}: {c['old']}  ->  {c['new']}")
    if not any(r["changes"] for r in rec["resources"]):
        L.append("    (no parameter detail recorded)")
    return L

def build_ticket_text(rec, is_test=False):
    L = ["*** TEST mail — dedup DB not modified ***"] if is_test else []
    L.append(f"{rec['short']} admin config change")
    L.append("=" * 72)
    L.append(f"Actor       : {rec['actor_upn'] or rec['actor_id']}")
    L.append(f"Actor type  : {rec['actor_type']}")
    if rec["actor_ip"]:
        L.append(f"Source IP   : {rec['actor_ip']}")
    L.append(f"Privileged  : {rec.get('ga_reason', 'yes')}")
    L.append(f"When        : {_fmt_ts(rec['when'])}")
    L += _what_changes_text(rec)
    return "\n".join(L)

def build_group_ticket_text(recs, is_test=False):
    recs = _dedupe_events(recs)
    if len(recs) == 1:
        return build_ticket_text(recs[0], is_test)
    obj = _group_object(recs[0])
    actor = recs[0]["actor_upn"] or recs[0]["actor_id"]
    L = ["*** TEST mail ***"] if is_test else []
    L.append(f"{len(recs)} config changes to {obj} by {actor}")
    L.append("=" * 72)
    L.append(f"Actor       : {actor}")
    L.append(f"Actor type  : {recs[0]['actor_type']}")
    if recs[0]["actor_ip"]:
        L.append(f"Source IP   : {recs[0]['actor_ip']}")
    L.append(f"Privileged  : {recs[0].get('ga_reason', 'yes')}")
    for rec in sorted(recs, key=lambda r: r.get("when", "")):
        L.append("")
        L.append(f"--- {rec['action'] or 'change'} — {_fmt_ts(rec['when'])} ---")
        L += _what_changes_text(rec)
    return "\n".join(L)

def _dedupe_events(recs):
    seen, out = set(), []
    for r in recs:
        sig = (r["action"], tuple(sorted(
            (c["name"], c["old"], c["new"]) for res in r["resources"] for c in res["changes"])))
        if sig in seen:
            continue
        seen.add(sig)
        out.append(r)
    return out

def _group_object(rec):
    for r in rec["resources"]:
        if r.get("display"):
            return r["display"]
    return rec.get("action") or "change"

def group_key(rec):
    return (rec.get("actor_upn") or rec.get("actor_id"), rec["workload"], _group_object(rec))

def group_subject(recs, is_test=False):
    recs = _dedupe_events(recs)
    if len(recs) == 1:
        return ticket_subject(recs[0], is_test)
    obj = _group_object(recs[0])
    return f"{'[TEST] ' if is_test else ''}Wazuh: {recs[0]['short']} config change: {obj} — {len(recs)} changes"[:200]

def send_mail(recipients, subject, text_body, html_body=None, smtp_server=SMTP_SERVER, smtp_port=SMTP_PORT):
    em = EmailMessage()
    em["From"] = MAIL_FROM
    em["To"] = ", ".join(recipients)
    em["Subject"] = subject
    em.set_content(text_body)
    if html_body:
        em.add_alternative(html_body, subtype="html")
    with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as s:
        s.ehlo()
        s.send_message(em)

# =====================================================================
# Core
# =====================================================================

def gather(client, args):
    hits = collect_office365_events(client, args.index_pattern, args.lookback_hours)
    by_wl, by_op = {}, {}
    kept = []
    for h in hits:
        rec = classify_event(h)
        if rec is None:
            continue
        kept.append(rec)
        by_wl[rec["workload"]] = by_wl.get(rec["workload"], 0) + 1
        by_op[rec["action"]] = by_op.get(rec["action"], 0) + 1
    print(f"[gather] window={args.lookback_hours}h office365_hits={len(hits)} "
          f"admin_config_changes={len(kept)}")
    if kept:
        print("[gather] by workload: " + ", ".join(f"{k}={v}" for k, v in sorted(by_wl.items(), key=lambda x: -x[1])))
        top = sorted(by_op.items(), key=lambda x: -x[1])[:12]
        print("[gather] by operation: " + ", ".join(f"{k}={v}" for k, v in top))
    return kept

def _recipients(args):
    return [x.strip() for x in (args.recipients or RECIPIENTS).split(",") if x.strip()]

def _verify_arg(args):
    verify = False if args.no_verify else (args.ca if args.ca else True)
    if isinstance(verify, str) and not os.access(verify, os.R_OK):
        raise SystemExit(f"CA file not readable: {verify} (use --no-verify for localhost).")
    return verify

def _make_client(args):
    verify = _verify_arg(args)
    cert = args.cert if (args.cert and os.access(args.cert, os.R_OK)) else None
    key  = args.key  if (args.key  and os.access(args.key,  os.R_OK)) else None
    if not cert and not args.password:
        raise SystemExit("No indexer auth: set INDEX_PASSWORD / WAZUH_INDEXER_PASSWORD, or "
                         "give a readable --cert/--key.")
    print(f"[auth] indexer via {'client certificate' if cert else 'username/password'}")
    return _get_client(args.index_url, args.user, args.password, verify=verify,
                       client_cert=cert, client_key=key)

def run(args):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    client = _make_client(args)
    conn = _connect_state(args.state_db)
    try:
        init_db(conn)
        seeded = conn.execute("SELECT v FROM meta WHERE k='seeded_at'").fetchone()
        if not seeded and not args.seed and not args.dry_run and not args.test:
            raise SystemExit("State DB has no baseline. Run once with --seed to record current "
                             "changes (no email), then schedule the notify run. Use --dry-run "
                             "to preview without seeding.")

        kept = gather(client, args)

        if args.test:
            if not kept:
                raise SystemExit("No admin config change in the window to build a test from. "
                                 "Try a larger --lookback-hours.")
            rec = sorted(kept, key=lambda r: r.get("when", ""), reverse=True)[0]
            recips = _recipients(args)
            if not recips:
                raise SystemExit("No recipients (set RECIPIENTS or --recipients).")
            send_mail(recips, ticket_subject(rec, True), build_ticket_text(rec, True),
                      build_ticket_html(rec, True), args.smtp_server, args.smtp_port)
            print(f"[test] sample ticket sent to {recips}")
            return

        if args.seed:
            for r in kept:
                mark_notified(conn, r, now)
            conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('seeded_at', ?)", (now,))
            conn.commit()
            print(f"[seed] baselined {len(kept)} change(s) into {args.state_db}. No email.")
            return

        already = {row[0] for row in conn.execute("SELECT event_key FROM notified")}
        new = [r for r in kept if event_key(r) not in already]
        print(f"[notify] new (not yet notified): {len(new)}")

        if args.group:
            buckets = {}
            for r in new:
                buckets.setdefault(group_key(r), []).append(r)
            batches = list(buckets.values())
        else:
            batches = [[r] for r in new]

        if args.dry_run:
            for r in sorted(new, key=lambda r: r.get("when", "")):
                print(f"  CHANGE  {_fmt_ts(r['when']):<24}  UserType={r.get('_usertype',''):<2} "
                      f"{(r['actor_upn'] or r['actor_id'])[:34]:<34}  {r['workload'][:22]:<22} "
                      f"{r['action'][:32]:<32}  -> {_group_object(r)[:40]}")
            print(f"[dry-run] would send {len(batches)} email(s) for {len(new)} change(s); "
                  f"recipients={_recipients(args)!r}")
            return

        if not new:
            print("[notify] nothing new this run; no email sent.")
            return
        recips = _recipients(args)
        if not recips:
            raise SystemExit("No recipients configured (set RECIPIENTS or --recipients).")
        sent, errs = 0, 0
        for b in batches:
            try:
                send_mail(recips, group_subject(b), build_group_ticket_text(b),
                          build_group_ticket_html(b), args.smtp_server, args.smtp_port)
                for r in b:
                    mark_notified(conn, r, now)
                sent += 1
            except Exception as e:
                errs += 1
                print(f"[notify] send failed for group ({len(b)} event(s)): {e}")
        conn.commit()
        print(f"[notify] sent {sent} email(s) for {len(new)} change(s) to {recips}"
              + (f" ({errs} error(s))" if errs else ""))
    finally:
        conn.close()

def main():
    ap = argparse.ArgumentParser(
        description="Email notify-once tickets for Microsoft 365 (Exchange/Defender/Purview/"
                    "Security & Compliance) admin config changes, read from the Wazuh Indexer "
                    "(office365 Management Activity events).")
    ap.add_argument("--index-url", default=INDEX_URL)
    ap.add_argument("--user", default=INDEX_USER)
    ap.add_argument("--password", default=INDEX_PASSWORD,
                    help="indexer password (prefer INDEX_PASSWORD / WAZUH_INDEXER_PASSWORD env)")
    ap.add_argument("--index-pattern", default=INDEX_PATTERN)
    ap.add_argument("--no-verify", action="store_true", default=NO_VERIFY)
    ap.add_argument("--ca", default=CA)
    ap.add_argument("--cert", default=INDEX_CLIENT_CERT, help="client cert for indexer mTLS")
    ap.add_argument("--key", default=INDEX_CLIENT_KEY, help="client key for indexer mTLS")
    ap.add_argument("--lookback-hours", type=int, default=LOOKBACK_HOURS)
    ap.add_argument("--recipients", default=RECIPIENTS)
    ap.add_argument("--smtp-server", default=SMTP_SERVER)
    ap.add_argument("--smtp-port", type=int, default=SMTP_PORT)
    ap.add_argument("--state-db", default=STATE_DB)
    ap.add_argument("--dashboard-url", default=DASHBOARD_URL)
    ap.add_argument("--seed", action="store_true", help="baseline current changes (no email), then exit")
    ap.add_argument("--dry-run", action="store_true", help="print what would be sent; no email, no DB change")
    ap.add_argument("--test", action="store_true", help="send a sample ticket from the most recent match; no DB change")
    ap.add_argument("--no-group", dest="group", action="store_false",
                    help="one email per event instead of grouping per (admin + object)")
    ap.set_defaults(group=GROUP_TICKETS)
    run(ap.parse_args())

if __name__ == "__main__":
    main()
