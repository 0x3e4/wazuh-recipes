#!/usr/bin/env python3
"""Entra / Intune admin config-change tickets — DIRECT-from-Microsoft-Graph poller.

Why this exists: the Wazuh ms-graph wodle cannot reliably deliver the audit feeds we
need. It queries deviceManagement/auditEvents and auditLogs/directoryAudits with a
`createdDateTime` filter, but those resources use `activityDateTime` -> HTTP 400
"Invalid filter clause" -> nothing is collected (wazuh/wazuh#31451, #27606). The huge
detectedApps/managedDevices enumeration also triggers Graph 429 throttling.

This poller talks to Microsoft Graph directly with the SAME app registration, using the
CORRECT `activityDateTime` filter, forward-only (a per-feed bookmark; first run starts
"now" unless --lookback-hours is given). It reuses the recipe's global-admin gate, real
old->new diff extraction, notify-once dedup and HTML ticket rendering.

Config (env / EnvironmentFile): MS_GRAPH_TENANT_ID / MS_GRAPH_CLIENT_ID / MS_GRAPH_SECRET
(required), RECIPIENTS, SMTP_SERVER, SMTP_PORT, MAIL_FROM, DASHBOARD_URL, STATE_DB,
SUPPRESS_NOISE, GLOBAL_ADMIN_ROLE_TEMPLATE_IDS, GRAPH_ROLE_CACHE_HOURS. Standard library only.
"""
import os, sys, re, json, html, smtplib, sqlite3, hashlib, argparse
import urllib.request, urllib.parse, urllib.error
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

TOPIC = "Entra / Intune admin config change"
GRAPH = "https://graph.microsoft.com/v1.0"
GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# Feeds to poll: (Graph path, source kind). Both filter on activityDateTime.
GRAPH_FEEDS = [
    ("deviceManagement/auditEvents", "intune"),
    ("auditLogs/directoryAudits",    "entra"),
]

# ---- config ----
MS_GRAPH_TENANT_ID = os.environ.get("MS_GRAPH_TENANT_ID", "")
MS_GRAPH_CLIENT_ID = os.environ.get("MS_GRAPH_CLIENT_ID", "")
MS_GRAPH_SECRET    = os.environ.get("MS_GRAPH_SECRET", "")
GLOBAL_ADMIN_ROLE_TEMPLATE_IDS = [x.strip() for x in os.environ.get(
    "GLOBAL_ADMIN_ROLE_TEMPLATE_IDS", GLOBAL_ADMIN_ROLE_TEMPLATE_ID).split(",") if x.strip()]
GRAPH_ROLE_CACHE_HOURS = int(os.environ.get("GRAPH_ROLE_CACHE_HOURS", "6"))
SMTP_SERVER    = os.environ.get("SMTP_SERVER", "smtp.example.com")
SMTP_PORT      = int(os.environ.get("SMTP_PORT", "25"))
MAIL_FROM      = os.environ.get("MAIL_FROM", "wazuh@example.com")
RECIPIENTS     = os.environ.get("RECIPIENTS", "")
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "https://wazuh.example.com")
STATE_DB       = os.environ.get("STATE_DB", "/opt/entra-config-changes-digest/graph-state.db")
SUPPRESS_NOISE = os.environ.get("SUPPRESS_NOISE", "1").strip().lower() in ("1", "true", "yes", "on")
# Full property displayNames to drop entirely (audit noise). Comma-separated, case-insensitive.
IGNORE_PROPERTIES = {x.strip().lower() for x in os.environ.get(
    "IGNORE_PROPERTIES",
    "DeviceManagementAPIVersion,Included Updated Properties,TargetId.ServicePrincipalNames").split(",") if x.strip()}
# Leaf names (last dotted/bracketed segment) of always-changing metadata -> dropped under SUPPRESS_NOISE.
NOISE_LEAVES = {x.strip().lower() for x in os.environ.get(
    "NOISE_LEAVES", "modifieddatetime,createddatetime,lastmodifieddatetime").split(",") if x.strip()}
DISPLAY_TZ = os.environ.get("DISPLAY_TZ", "Europe/Vienna")  # "When" is shown in this zone
RESOLVE_GUIDS = os.environ.get("RESOLVE_GUIDS", "1").strip().lower() in ("1", "true", "yes", "on")
DIR_OBJECT_CACHE_HOURS = int(os.environ.get("DIR_OBJECT_CACHE_HOURS", "24"))
GROUP_TICKETS = os.environ.get("GROUP_TICKETS", "1").strip().lower() in ("1", "true", "yes", "on")
# Optional: append each global-admin change as native ms-graph JSON to this file so a
# Wazuh <localfile> ingests it (json-msgraph decoder) -> shows in the prebuilt Microsoft
# Graph API dashboard and fires the entra_admin_change rules. Empty = feed disabled.
FEED_FILE = os.environ.get("FEED_FILE", "")
_ACCENT = "#b3261e"
_MAX_VAL_LEN = 300

# =====================================================================
# Microsoft Graph
# =====================================================================

def _graph_token():
    if not (MS_GRAPH_TENANT_ID and MS_GRAPH_CLIENT_ID and MS_GRAPH_SECRET):
        raise SystemExit("MS_GRAPH_TENANT_ID / MS_GRAPH_CLIENT_ID / MS_GRAPH_SECRET must be set.")
    url = f"https://login.microsoftonline.com/{MS_GRAPH_TENANT_ID}/oauth2/v2.0/token"
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": MS_GRAPH_CLIENT_ID,
        "client_secret": MS_GRAPH_SECRET, "scope": "https://graph.microsoft.com/.default"}).encode()
    req = urllib.request.Request(url, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            tok = json.load(r).get("access_token")
    except urllib.error.HTTPError as e:
        raise SystemExit(f"Graph token request failed: HTTP {e.code} {e.read().decode(errors='replace')[:400]}")
    if not tok:
        raise SystemExit("Graph token request returned no access_token.")
    return tok

def _graph_get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def _graph_post(url, body, token):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

_GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_WELL_KNOWN_APPIDS = {
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "00000002-0000-0000-c000-000000000000": "Azure Active Directory Graph",
    "00000002-0000-0ff1-ce00-000000000000": "Office 365 Exchange Online",
    "00000003-0000-0ff1-ce00-000000000000": "Office 365 SharePoint Online",
    "797f4846-ba00-4fd7-ba43-dac1f8f63013": "Windows Azure Service Management API",
}
_WK_BY_NAME = {v.lower(): k for k, v in _WELL_KNOWN_APPIDS.items()}

def _dir_cache_get(conn, keys):
    if not keys:
        return {}
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=DIR_OBJECT_CACHE_HOURS)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    q = "SELECT object_id, display FROM dir_objects WHERE cached_at>=? AND object_id IN (%s)" % ",".join("?" * len(keys))
    return {r[0]: r[1] for r in conn.execute(q, [cutoff, *keys])}

def _dir_cache_put(conn, mapping):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    conn.executemany("INSERT OR REPLACE INTO dir_objects(object_id, display, cached_at) VALUES(?,?,?)",
                     [(k, v, now) for k, v in mapping.items()])

def resolve_dir_objects(conn, token, ids):
    """Resolve directory OBJECT ids -> display name via POST /directoryObjects/getByIds. Cached."""
    ids = [i for i in set(ids) if _GUID_RE.fullmatch(i or "")]
    if not ids:
        return {}
    resolved = _dir_cache_get(conn, ids)
    missing = [i for i in ids if i not in resolved]
    for s in range(0, len(missing), 900):
        batch = missing[s:s + 900]
        try:
            data = _graph_post("https://graph.microsoft.com/v1.0/directoryObjects/getByIds", {"ids": batch}, token)
        except Exception as e:
            print(f"[resolve] getByIds failed ({e}); leaving object GUIDs raw"); break
        found = {}
        for o in data.get("value", []):
            disp = o.get("displayName") or o.get("appDisplayName") or o.get("userPrincipalName")
            if o.get("id") and disp:
                found[o["id"]] = disp
        if found:
            _dir_cache_put(conn, found)
        resolved.update(found)
    return resolved

def resolve_app_ids(conn, token, appids):
    """Resolve application (client) IDs -> service-principal display name. Cached ('appid:' keys)."""
    out = {}
    for a in {x for x in appids if _GUID_RE.fullmatch(x or "")}:
        if a in _WELL_KNOWN_APPIDS:
            out[a] = _WELL_KNOWN_APPIDS[a]; continue
        c = _dir_cache_get(conn, ["appid:" + a])
        if "appid:" + a in c:
            out[a] = c["appid:" + a]; continue
        try:
            disp = _graph_get(f"https://graph.microsoft.com/v1.0/servicePrincipals(appId='{a}')?$select=displayName",
                              token).get("displayName")
        except Exception:
            disp = None
        if disp:
            out[a] = disp; _dir_cache_put(conn, {"appid:" + a: disp})
    return out

def annotate_guids(conn, token, kept):
    """Replace directory-object / app-ID GUIDs in change values, actor and resource with
    'Name (12345678…)'. Needs Directory.Read.All; on error it leaves GUIDs untouched."""
    if not (RESOLVE_GUIDS and kept):
        return
    obj_ids, app_ids = set(), set()
    def scan(v, into):
        for m in _GUID_RE.findall(str(v or "")):
            into.add(m)
    for rec in kept:
        scan(rec.get("actor_id"), obj_ids)
        for r in rec["resources"]:
            scan(r.get("display"), obj_ids)
            for c in r["changes"]:
                scan(c["old"], obj_ids); scan(c["new"], obj_ids)
                if c["name"].lower().endswith("resourceappid"):
                    scan(c["old"], app_ids); scan(c["new"], app_ids)
    try:
        names = resolve_dir_objects(conn, token, obj_ids)
        appnames = resolve_app_ids(conn, token, app_ids)
        conn.commit()
    except Exception as e:
        print(f"[resolve] disabled this run ({e})"); return
    if not (names or appnames):
        return
    def repl(val):
        return _GUID_RE.sub(lambda m: (f"{names.get(m.group(0)) or appnames.get(m.group(0))} "
                                       f"({m.group(0)[:8]}…)") if (names.get(m.group(0)) or appnames.get(m.group(0)))
                            else m.group(0), str(val if val is not None else ""))
    for rec in kept:
        if rec.get("actor_id") in names and not rec.get("actor_upn"):
            rec["actor_upn"] = names[rec["actor_id"]]
        for r in rec["resources"]:
            if r.get("display"):
                r["display"] = repl(r["display"])
            for c in r["changes"]:
                c["old"] = repl(c["old"]); c["new"] = repl(c["new"])

def resolve_app_perms(conn, token, appid):
    """Map a resource SP's permission ids -> names (appRoles + oauth2PermissionScopes). Cached."""
    if not _GUID_RE.fullmatch(appid or ""):
        return {}
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=DIR_OBJECT_CACHE_HOURS)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    cached = {r[0]: r[1] for r in conn.execute(
        "SELECT perm_id, name FROM app_perms WHERE resource=? AND cached_at>=?", (appid, cutoff))}
    if cached:
        return cached
    try:
        data = _graph_get("https://graph.microsoft.com/v1.0/servicePrincipals(appId='%s')"
                          "?$select=appRoles,oauth2PermissionScopes" % appid, token)
    except Exception as e:
        print(f"[resolve] appRoles/scopes for {appid[:8]}… failed ({e})"); return {}
    m = {}
    for r in data.get("appRoles", []) or []:
        if r.get("id"):
            m[r["id"]] = (r.get("value") or r.get("displayName") or "app role")
    for s in data.get("oauth2PermissionScopes", []) or []:
        if s.get("id"):
            m[s["id"]] = (s.get("value") or s.get("adminConsentDisplayName") or "scope")
    if m:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        conn.executemany("INSERT OR REPLACE INTO app_perms(resource, perm_id, name, cached_at) VALUES(?,?,?,?)",
                         [(appid, k, v, now) for k, v in m.items()])
    return m

def annotate_perms(conn, token, kept):
    """Resolve OAuth permission ids (EntitlementId, AppRole.Id, consent scope ids) to
    permission names via the resource SP that publishes them. Needs Directory.Read.All."""
    if not (RESOLVE_GUIDS and kept):
        return
    appids = set()
    for rec in kept:
        for r in rec["resources"]:
            wk = _WK_BY_NAME.get(str(r.get("display", "")).split(" (")[0].strip().lower())
            if wk:
                appids.add(wk)
            for c in r["changes"]:
                appids.update(re.findall(r"ResourceAppId=([0-9a-fA-F-]{36})", c["name"]))
                if c["name"].strip().lower().endswith("appid"):
                    appids.update(_GUID_RE.findall(str(c["old"] or "") + " " + str(c["new"] or "")))
    perm = {}
    for a in appids:
        try:
            perm.update({k.lower(): v for k, v in resolve_app_perms(conn, token, a).items()})
        except Exception:
            pass
    conn.commit()
    if not perm:
        return
    def repl(val):
        return _GUID_RE.sub(lambda m: (f"{perm[m.group(0).lower()]} ({m.group(0)[:8]}…)")
                            if m.group(0).lower() in perm else m.group(0),
                            str(val if val is not None else ""))
    for rec in kept:
        for r in rec["resources"]:
            for c in r["changes"]:
                c["old"] = repl(c["old"]); c["new"] = repl(c["new"])

def get_global_admin_ids(conn, token):
    """Cached set of Global Administrator member object-ids. None if unavailable."""
    now = datetime.now(timezone.utc)
    row = conn.execute("SELECT v FROM meta WHERE k='global_admins_cached_at'").fetchone()
    if row and row[0]:
        try:
            if now - datetime.fromisoformat(row[0]) < timedelta(hours=GRAPH_ROLE_CACHE_HOURS):
                cached = {r[0] for r in conn.execute("SELECT object_id FROM global_admins")}
                if cached:
                    return cached
        except ValueError:
            pass
    try:
        ids = {}
        for tid in GLOBAL_ADMIN_ROLE_TEMPLATE_IDS:
            url = (f"{GRAPH}/directoryRoles(roleTemplateId='{tid}')/members?$select=id,userPrincipalName")
            while url:
                try:
                    data = _graph_get(url, token)
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        print(f"[graph] role template {tid} not activated (404); skipping"); break
                    raise
                for m in data.get("value", []):
                    if m.get("id"):
                        ids[m["id"]] = m.get("userPrincipalName") or ""
                url = data.get("@odata.nextLink")
        conn.execute("DELETE FROM global_admins")
        conn.executemany("INSERT OR REPLACE INTO global_admins(object_id, upn) VALUES (?,?)", list(ids.items()))
        conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('global_admins_cached_at', ?)",
                     (now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),))
        conn.commit()
        print(f"[graph] global-admin set: {len(ids)} member(s)")
        return set(ids)
    except Exception as e:
        cached = {r[0] for r in conn.execute("SELECT object_id FROM global_admins")}
        if cached:
            print(f"[graph] GA lookup failed ({e}); using stale cache"); return cached
        print(f"[graph] WARNING: GA lookup failed ({e}) and no cache -> Entra events skipped")
        return None

def collect_from_graph(conn, token, lookback_hours, now_dt, seed=False):
    """Pull new auditEvents + directoryAudits since each feed's bookmark (forward-only,
    correct activityDateTime filter). On --seed, only advance the bookmark to 'now' and
    return nothing. Returns synthetic 'hits' the classifier understands."""
    hits = []
    for path, _kind in GRAPH_FEEDS:
        key = f"graph_bookmark_{path}"
        row = conn.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        if row and row[0]:
            since = row[0]
        else:  # first run: forward-only (now), unless a lookback is requested
            since = (now_dt - timedelta(hours=lookback_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        if seed:
            conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (key, now_iso))
            print(f"[seed] {path}: bookmark set to {now_iso} (no fetch)")
            continue
        flt = urllib.parse.quote(f"activityDateTime gt {since}")
        url = f"{GRAPH}/{path}?$filter={flt}&$top=100"
        newest, n = since, 0
        try:
            while url:
                data = _graph_get(url, token)
                for item in data.get("value", []):
                    hits.append({"_id": str(item.get("id") or ""),
                                 "_source": {"timestamp": item.get("activityDateTime"),
                                             "rule": {"id": "graph", "level": ""},
                                             "agent": {"name": ""},
                                             "data": {"ms-graph": item}}})
                    adt = item.get("activityDateTime") or ""
                    if adt > newest:
                        newest = adt
                    n += 1
                url = data.get("@odata.nextLink")
        except urllib.error.HTTPError as e:
            print(f"[graph] {path}: HTTP {e.code} {e.read().decode(errors='replace')[:300]}")
            continue
        conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (key, newest))
        print(f"[graph] {path}: {n} event(s) since {since}; bookmark -> {newest}")
    return hits

# =====================================================================
# Classification / diff  (identical semantics to the indexer recipe)
# =====================================================================

def _as_list(x):
    return [] if x is None else (x if isinstance(x, list) else [x])

def _g(d, *path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default

def classify_event(hit):
    src = hit.get("_source", {}) or {}
    mg = _g(src, "data", "ms-graph", default={})
    if not isinstance(mg, dict):
        return None
    common = {
        "alert_id": hit.get("_id", ""),
        "rule_id": str(_g(src, "rule", "id", default="")),
        "rule_level": str(_g(src, "rule", "level", default="")),
        "agent": _g(src, "agent", "name", default=""),
        "event_id": str(mg.get("id") or ""),
        "correlation_id": str(mg.get("correlationId") or ""),
        "category": str(mg.get("category") or ""),
        "when": str(mg.get("activityDateTime") or _g(src, "timestamp", default="") or ""),
        "_raw": mg,   # original Graph ms-graph object, for the Wazuh feed
    }
    if mg.get("resources") is not None:
        actor = mg.get("actor") or {}
        perms = _as_list(actor.get("userPermissions"))
        common.update({
            "source": "intune", "source_kind": "Intune (deviceManagement)",
            "actor_upn": str(actor.get("userPrincipalName") or ""),
            "actor_id": str(actor.get("userId") or ""),
            "actor_type": str(actor.get("auditActorType") or ""),
            "actor_app": str(actor.get("applicationDisplayName") or ""),
            "actor_ip": "",
            "ga_perm": any(str(p).strip() == "*" for p in perms),
            "action": str(mg.get("displayName") or mg.get("activityType") or ""),
            "operation": str(mg.get("activityOperationType") or ""),
            "result": str(mg.get("activityResult") or ""),
            "resources": [{"display": str(r.get("displayName") or ""),
                           "rtype": str(r.get("auditResourceType") or r.get("type") or ""),
                           "modified": _as_list(r.get("modifiedProperties"))}
                          for r in _as_list(mg.get("resources")) if isinstance(r, dict)],
        })
        return common
    if mg.get("targetResources") is not None or mg.get("initiatedBy") is not None:
        user = _g(mg, "initiatedBy", "user", default={}) or {}
        app = _g(mg, "initiatedBy", "app", default={}) or {}
        common.update({
            "source": "entra", "source_kind": "Entra ID (directoryAudit)",
            "actor_upn": str(user.get("userPrincipalName") or app.get("displayName") or ""),
            "actor_id": str(user.get("id") or app.get("servicePrincipalId") or ""),
            "actor_type": "User" if user else ("App" if app else ""),
            "actor_app": str(app.get("displayName") or ""),
            "actor_ip": str(user.get("ipAddress") or ""),
            "ga_perm": False,
            "action": str(mg.get("activityDisplayName") or ""),
            "operation": str(mg.get("operationType") or ""),
            "result": str(mg.get("result") or ""),
            "resources": [{"display": str(r.get("displayName") or ""),
                           "rtype": str(r.get("type") or ""),
                           "modified": _as_list(r.get("modifiedProperties"))}
                          for r in _as_list(mg.get("targetResources")) if isinstance(r, dict)],
        })
        return common
    return None

_NULLish = {"", "null", "<null>", "[]", "none"}

def _strip_quotes(s):
    s = str(s)
    return s[1:-1] if len(s) >= 2 and s[0] == '"' and s[-1] == '"' else s

def _norm_val(v):
    if v is None:
        return ""
    s = _strip_quotes(v).strip()
    return "" if s.lower() in _NULLish else s

def _is_placeholder(s):
    s = str(s)
    return (s.startswith("System.") or s.startswith("$Collection") or s.startswith("Microsoft.")
            or "Microsoft.Management.Services" in s)

def _disp_val(v):
    n = _norm_val(v)
    if n == "":
        return "(none)"
    return n[:_MAX_VAL_LEN] + " …" if len(n) > _MAX_VAL_LEN else n

_MAX_JSON_DIFFS = 40
# When a JSON list holds objects, key its elements by a stable id field (not the array
# index) so a reordered list doesn't show every element as "changed".
_LIST_KEYS = ("EntitlementId", "ResourceAppId", "Id", "id", "ObjectId", "objectId",
              "AppId", "appId", "RoleDefinitionId", "PrincipalId", "Name", "name")

def _list_key(elem):
    if isinstance(elem, dict):
        for k in _LIST_KEYS:
            if elem.get(k) not in (None, ""):
                return f"{k}={elem[k]}"
    return None

def _deep_parse(v):
    """Best-effort decode of a possibly JSON-encoded value. Entra often double-encodes
    (e.g. a JSON array whose single element is a JSON string). Unwrap a few layers."""
    for _ in range(5):
        if isinstance(v, str):
            s = v.strip()
            if s[:1] in ("[", "{"):
                try:
                    v = json.loads(s)
                    continue
                except Exception:
                    return v
            return v
        if isinstance(v, list) and len(v) == 1:
            v = v[0]
            continue
        return v
    return v

def _flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k, val in obj.items():
            out.update(_flatten(val, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            seg = _list_key(val)
            out.update(_flatten(val, f"{prefix}[{seg}]" if seg else f"{prefix}[{i}]"))
    else:
        out[prefix or "value"] = obj
    return out

def _json_leaf_diff(old_raw, new_raw):
    """If old/new decode to JSON structures, return [(path, old, new)] for changed
    leaves; else None (caller falls back to the raw string)."""
    o, n = _deep_parse(old_raw), _deep_parse(new_raw)
    if not (isinstance(o, (dict, list)) or isinstance(n, (dict, list))):
        return None
    fo, fn = _flatten(o), _flatten(n)
    diffs = []
    for k in sorted(set(fo) | set(fn)):
        if fo.get(k) != fn.get(k):
            diffs.append((k, fo.get(k), fn.get(k)))
    return diffs

def real_changes(modified_properties):
    out = []
    for mp in modified_properties:
        if not isinstance(mp, dict):
            continue
        name = str(mp.get("displayName") or "")
        if name.strip().lower() in IGNORE_PROPERTIES:
            continue
        if SUPPRESS_NOISE and name.split(".")[-1].split("[")[0].strip().lower() in NOISE_LEAVES:
            continue
        old_raw, new_raw = mp.get("oldValue"), mp.get("newValue")
        old_n, new_n = _norm_val(old_raw), _norm_val(new_raw)
        if old_n == new_n:
            continue
        if SUPPRESS_NOISE and (_is_placeholder(old_n) or _is_placeholder(new_n)):
            continue
        # If the value is embedded JSON, show only the nested fields that changed.
        jdiff = _json_leaf_diff(old_raw, new_raw)
        if jdiff is not None:
            emitted = 0
            for path, a, b in jdiff:
                leaf = path.split(".")[-1].split("[")[0].strip().lower()
                if SUPPRESS_NOISE and leaf in NOISE_LEAVES:
                    continue
                if emitted >= _MAX_JSON_DIFFS:
                    out.append({"name": f"{name} › …", "old": "",
                                "new": f"(+{len(jdiff) - emitted} more changed field(s))"})
                    break
                out.append({"name": f"{name} › {path}", "old": _disp_val(a), "new": _disp_val(b)})
                emitted += 1
            continue   # JSON handled (even if all-noise -> nothing emitted)
        out.append({"name": name,
                    "old": _disp_val(old_raw), "new": _disp_val(new_raw)})
    return out

def event_key(rec):
    if rec.get("event_id"):
        return rec["event_id"]
    if rec.get("actor_id") or rec.get("when"):
        raw = "|".join([rec.get("actor_id", ""), rec.get("when", ""), rec.get("action", ""),
                        rec.get("correlation_id", "")])
        return hashlib.sha256(raw.encode()).hexdigest()
    return rec.get("alert_id", "")

# =====================================================================
# State DB (notify-once + bookmark + GA cache)
# =====================================================================

def _connect_state(path):
    path = (path or "").strip() or STATE_DB
    if os.path.isdir(path):
        raise SystemExit(f"--state-db points to a directory, not a file: {path}")
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
    conn.execute("CREATE TABLE IF NOT EXISTS global_admins (object_id TEXT PRIMARY KEY, upn TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS dir_objects (object_id TEXT PRIMARY KEY, display TEXT, cached_at TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS app_perms (resource TEXT, perm_id TEXT, name TEXT, cached_at TEXT, PRIMARY KEY(resource, perm_id))")
    conn.commit()

def mark_notified(conn, rec, now):
    res = "; ".join(r["display"] for r in rec["resources"] if r["display"])[:400]
    conn.execute("INSERT OR REPLACE INTO notified"
                 "(event_key, source, actor, action, resource, changed_at, notified_at) VALUES (?,?,?,?,?,?,?)",
                 (event_key(rec), rec["source"], rec["actor_upn"], rec["action"], res, rec.get("when", ""), now))

# =====================================================================
# Rendering (identical to the indexer recipe)
# =====================================================================

def _esc(s):
    return html.escape(str(s if s is not None else ""))

_FONT = "font-family:'Segoe UI',Segoe,Tahoma,Arial,sans-serif;"

def _fmt_ts(ts):
    """Render a Graph UTC activityDateTime in DISPLAY_TZ (default Europe/Vienna),
    e.g. '2026-07-02 12:56:38 CEST'. Falls back to the raw value on parse error."""
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
            f'padding-top:8px;">Automated {_esc(TOPIC)} notification (direct Microsoft Graph poll).</div>'
            '</td></tr></table></td></tr></table></body></html>')

def _short_source(rec):
    return "Entra" if rec["source"] == "entra" else "Intune"

_ACTOR_TYPE = {"itpro": "IT admin (portal)", "user": "User", "application": "Application",
               "serviceprincipal": "Service principal", "system": "System",
               "systemaccount": "System account", "unknown": "Unknown"}

def _actor_type_label(t):
    return _ACTOR_TYPE.get(str(t or "").strip().lower(), t)

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
    return f"{'[TEST] ' if is_test else ''}Wazuh: {_short_source(rec)} config change: {action}"

def _who_rows(rec, include_when=True):
    rows = [("Actor", _esc(rec["actor_upn"] or rec["actor_id"] or "(unknown)")),
            ("Actor type", _esc(_actor_type_label(rec["actor_type"])))]
    if rec["actor_app"]:
        rows.append(("Application", _esc(rec["actor_app"])))
    if rec["actor_ip"]:
        rows.append(("Source IP", _esc(rec["actor_ip"])))
    rows.append(("Global admin", _esc(rec.get("ga_reason", "")) or "yes"))
    if include_when:
        rows.append(("When", _esc(_fmt_ts(rec["when"]))))
    return rows

def _resource_changes_html(r):
    out = (f'<div style="{_FONT}font-size:13px;font-weight:bold;color:#0f172a;margin:8px 0 4px;">'
           f'{_esc(r["display"] or r["rtype"] or "resource")}</div>')
    if all(c["old"] == "(none)" for c in r["changes"]):
        rows = [(_esc(c["name"]), f'<span style="color:#1a7f37;">{_esc(c["new"])}</span>') for c in r["changes"]]
        out += _kv_table_html(["Property", "Value"], rows)
        out += (f'<div style="{_FONT}font-size:11px;color:#94a3b8;margin:-8px 0 10px;">'
                f'Only the resulting values were recorded (no previous values).</div>')
    else:
        rows = [(_esc(c["name"]), f'<span style="color:#b3261e;">{_esc(c["old"])}</span>',
                 f'<span style="color:#1a7f37;">{_esc(c["new"])}</span>') for c in r["changes"]]
        out += _kv_table_html(["Property", "Old", "New"], rows)
    return out

def _what_changes_html(rec):
    what = [("Action", _esc(rec["action"] or "")), ("Operation", _esc(rec["operation"] or "")),
            ("Result", _esc(rec["result"] or "")), ("Category", _esc(rec["category"] or "")),
            ("Source", _esc(rec["source_kind"])), ("Resource(s)", _esc(_res_summary(rec)))]
    if rec["correlation_id"]:
        what.append(("Correlation ID", _esc(rec["correlation_id"])))
    body = _section_bar_html("What") + _kv_table_html(["Field", "Value"], what)
    body += _section_bar_html("What changed (old → new)")
    shown = [_resource_changes_html(r) for r in rec["resources"] if r["changes"]]
    body += "".join(shown) if shown else f'<div style="{_FONT}font-size:13px;color:#94a3b8;">(no field-level detail)</div>'
    return body

def build_ticket_html(rec, is_test=False):
    n = sum(len(r["changes"]) for r in rec["resources"])
    intro = (f'<p style="{_FONT}margin:0 0 12px;"><strong>{_esc(rec["actor_upn"] or rec["actor_id"])}</strong> '
             f'({_esc(_short_source(rec))}) performed '
             f'<strong>{_esc(rec["action"] or rec["operation"] or "a change")}</strong>: '
             f'<strong>{n}</strong> property change(s).</p>')
    if is_test:
        intro = f'<p style="{_FONT}margin:0 0 8px;"><strong>This is a manual TEST mail.</strong></p>' + intro
    body = _section_bar_html("Who") + _kv_table_html(["Field", "Value"], _who_rows(rec)) + _what_changes_html(rec)
    return _html_page(f"{'[TEST] ' if is_test else ''}Config change by global admin", intro, body)

def build_group_ticket_html(recs, is_test=False):
    recs = _dedupe_events(recs)
    if len(recs) == 1:
        return build_ticket_html(recs[0], is_test)
    obj = _group_object(recs[0]); actor = recs[0]["actor_upn"] or recs[0]["actor_id"]
    intro = (f'<p style="{_FONT}margin:0 0 12px;"><strong>{_esc(actor)}</strong> '
             f'({_esc(_short_source(recs[0]))}) made <strong>{len(recs)}</strong> configuration '
             f'change(s) to <strong>{_esc(obj)}</strong>.</p>')
    if is_test:
        intro = f'<p style="{_FONT}margin:0 0 8px;"><strong>This is a manual TEST mail.</strong></p>' + intro
    body = _section_bar_html("Who") + _kv_table_html(["Field", "Value"], _who_rows(recs[0], include_when=False))
    for rec in sorted(recs, key=lambda r: r.get("when", "")):
        body += (f'<div style="{_FONT}font-size:14px;font-weight:bold;color:#b3261e;margin:16px 0 0;">'
                 f'{_esc(rec["action"] or rec["operation"] or "change")} — {_esc(_fmt_ts(rec["when"]))}</div>')
        body += _what_changes_html(rec)
    return _html_page(f"{'[TEST] ' if is_test else ''}{len(recs)} config changes — {_esc(obj)}", intro, body)

def _what_changes_text(rec):
    L = [f"Action      : {rec['action']}   op={rec['operation']}  result={rec['result']}",
         f"Category    : {rec['category']}   Source: {rec['source_kind']}"]
    if rec["correlation_id"]:
        L.append(f"Correlation : {rec['correlation_id']}")
    L.append("Changes (old -> new):")
    any_ch = False
    for r in rec["resources"]:
        if not r["changes"]:
            continue
        any_ch = True
        L.append(f"  [{r['display'] or r['rtype'] or 'resource'}]")
        allo = all(c["old"] == "(none)" for c in r["changes"])
        for c in r["changes"]:
            L.append(f"    - {c['name']}: {c['new']}" if allo else f"    - {c['name']}: {c['old']}  ->  {c['new']}")
        if allo:
            L.append("    (only resulting values recorded; no previous values)")
    if not any_ch:
        L.append("  (no field-level detail)")
    return L

def build_ticket_text(rec, is_test=False):
    L = []
    if is_test:
        L.append("*** TEST mail — dedup DB not modified ***")
    L.append(f"{_short_source(rec)} config change by global admin")
    L.append("=" * 72)
    L.append(f"Actor       : {rec['actor_upn'] or rec['actor_id']}")
    L.append(f"Actor type  : {_actor_type_label(rec['actor_type'])}")
    if rec["actor_app"]:
        L.append(f"Application : {rec['actor_app']}")
    if rec["actor_ip"]:
        L.append(f"Source IP  : {rec['actor_ip']}")
    L.append(f"Global admin: {rec.get('ga_reason', 'yes')}")
    L.append(f"When        : {_fmt_ts(rec['when'])}")
    L += _what_changes_text(rec)
    return "\n".join(L)

def build_group_ticket_text(recs, is_test=False):
    recs = _dedupe_events(recs)
    if len(recs) == 1:
        return build_ticket_text(recs[0], is_test)
    obj = _group_object(recs[0]); actor = recs[0]["actor_upn"] or recs[0]["actor_id"]
    L = ["*** TEST mail ***"] if is_test else []
    L.append(f"{len(recs)} config changes to {obj} by {actor}")
    L.append("=" * 72)
    L.append(f"Actor       : {actor}")
    L.append(f"Actor type  : {_actor_type_label(recs[0]['actor_type'])}")
    if recs[0]["actor_ip"]:
        L.append(f"Source IP  : {recs[0]['actor_ip']}")
    L.append(f"Global admin: {recs[0].get('ga_reason', 'yes')}")
    for rec in sorted(recs, key=lambda r: r.get("when", "")):
        L.append("")
        L.append(f"--- {rec['action'] or 'change'} — {_fmt_ts(rec['when'])} ---")
        L += _what_changes_text(rec)
    return "\n".join(L)

def _dedupe_events(recs):
    seen, out = set(), []
    for r in recs:
        sig = (r["action"], r["operation"], tuple(sorted(
            (c["name"], c["old"], c["new"]) for res in r["resources"] for c in res["changes"])))
        if sig in seen:
            continue
        seen.add(sig); out.append(r)
    return out

def _group_object(rec):
    for r in rec["resources"]:
        if r.get("display"):
            return r["display"]
    for r in rec["resources"]:
        for c in r["changes"]:
            if c["name"].strip().lower().endswith("displayname"):
                v = c["new"] if c["new"] not in ("(none)", "") else c["old"]
                if v and v != "(none)":
                    return v
    return rec.get("action") or "change"

def group_key(rec):
    return (rec.get("actor_upn") or rec.get("actor_id"), rec["source"], _group_object(rec))

def group_subject(recs, is_test=False):
    recs = _dedupe_events(recs)
    if len(recs) == 1:
        return ticket_subject(recs[0], is_test)
    obj = _group_object(recs[0])
    return f"{'[TEST] ' if is_test else ''}Wazuh: {_short_source(recs[0])} config change: {obj} — {len(recs)} changes"[:200]

def feed_events(path, records):
    """Append each record's native ms-graph event to a JSON logfile for Wazuh ingestion.
    Tagged with ms-graph.admin_change=true so a custom rule can elevate it and it shows
    in the prebuilt Microsoft Graph API dashboard (rule.groups:ms-graph, data.ms-graph.*)."""
    if not path:
        return 0
    try:
        with open(path, "a", encoding="utf-8") as fh:
            for rec in records:
                item = dict(rec.get("_raw") or {})
                # directoryAudits use activityDisplayName; give the dashboard a displayName
                item.setdefault("displayName", item.get("activityDisplayName")
                                or item.get("activityType") or rec.get("action") or "")
                item["admin_change"] = "true"
                item["is_global_admin"] = "true"
                item["admin_actor"] = rec.get("actor_upn") or rec.get("actor_id") or ""
                item["admin_source"] = rec.get("source") or ""
                # compact separators: the json-msgraph decoder prematches the literal
                # '"integration":"ms-graph"' (no spaces).
                fh.write(json.dumps({"integration": "ms-graph", "ms-graph": item},
                                    ensure_ascii=False, separators=(",", ":")) + "\n")
        return len(records)
    except OSError as e:
        print(f"[feed] WARNING: cannot write {path}: {e}")
        return 0

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

def gather(conn, token, hits):
    records = [r for r in (classify_event(h) for h in hits) if r]
    entra = [r for r in records if r["source"] == "entra"]
    ga_ids = get_global_admin_ids(conn, token) if entra else set()
    kept, skipped = [], 0
    for r in records:
        if r["source"] == "intune":
            if not r["ga_perm"]:
                continue
            r["ga_reason"] = "userPermissions [*]"
        else:
            if ga_ids is None:
                skipped += 1; continue
            if r["actor_id"] not in ga_ids:
                continue
            r["ga_reason"] = "Graph: Global Administrator"
        total = 0
        for res in r["resources"]:
            res["changes"] = real_changes(res["modified"])
            total += len(res["changes"])
        if total:
            kept.append(r)
    if skipped:
        print(f"[gather] skipped {skipped} Entra event(s): global-admin set unavailable")
    annotate_guids(conn, token, kept)   # directory/app GUIDs -> display names (best-effort)
    annotate_perms(conn, token, kept)   # EntitlementId / AppRole.Id -> permission names
    print(f"[gather] global-admin config changes with real diffs: {len(kept)}")
    return kept

def _recipients(args):
    return [x.strip() for x in (args.recipients or RECIPIENTS).split(",") if x.strip()]

def run(args):
    now_dt = datetime.now(timezone.utc)
    now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    token = _graph_token()
    conn = _connect_state(args.state_db)
    try:
        init_db(conn)
        if args.seed:
            collect_from_graph(conn, token, args.lookback_hours, now_dt, seed=True)
            conn.commit()
            print("[seed] bookmarks set to now; no email."); return
        hits = collect_from_graph(conn, token, args.lookback_hours, now_dt)
        conn.commit()   # persist advanced bookmarks even if sends fail
        kept = gather(conn, token, hits)

        if args.test:
            if not kept:
                raise SystemExit("No global-admin config change in the polled window to build a test from.")
            rec = sorted(kept, key=lambda r: r.get("when", ""), reverse=True)[0]
            recips = _recipients(args)
            if not recips:
                raise SystemExit("No recipients (set RECIPIENTS or --recipients).")
            send_mail(recips, ticket_subject(rec, True), build_ticket_text(rec, True),
                      build_ticket_html(rec, True), args.smtp_server, args.smtp_port)
            print(f"[test] sample ticket sent to {recips}"); return

        already = {row[0] for row in conn.execute("SELECT event_key FROM notified")}
        new = [r for r in kept if event_key(r) not in already]
        print(f"[notify] new (not yet notified): {len(new)}")
        # Group for email (the Wazuh feed stays per-event). One email per (admin, object).
        if args.group:
            buckets = {}
            for r in new:
                buckets.setdefault(group_key(r), []).append(r)
            batches = list(buckets.values())
        else:
            batches = [[r] for r in new]
        if args.dry_run:
            for b in batches:
                print("  NEW:", group_subject(b))
            return
        if new and args.feed_file:
            fed = feed_events(args.feed_file, new)
            if fed:
                print(f"[feed] wrote {fed} event(s) to {args.feed_file}")
        if not new:
            print("[notify] nothing new; no email."); return
        recips = _recipients(args)
        if not recips:
            raise SystemExit("No recipients (set RECIPIENTS or --recipients).")
        sent, errs = 0, 0
        for b in batches:
            try:
                send_mail(recips, group_subject(b), build_group_ticket_text(b), build_group_ticket_html(b),
                          args.smtp_server, args.smtp_port)
                for r in b:
                    mark_notified(conn, r, now)
                sent += 1
            except Exception as e:
                errs += 1; print(f"[notify] send failed for group ({len(b)} event(s)): {e}")
        conn.commit()
        print(f"[notify] sent {sent} email(s) for {len(new)} change(s) to {recips}"
              + (f" ({errs} error(s))" if errs else ""))
    finally:
        conn.close()

def main():
    ap = argparse.ArgumentParser(description="Direct Microsoft Graph poller for Entra/Intune "
                                             "admin config-change tickets (bypasses the Wazuh ms-graph wodle).")
    ap.add_argument("--recipients", default=RECIPIENTS)
    ap.add_argument("--smtp-server", default=SMTP_SERVER)
    ap.add_argument("--smtp-port", type=int, default=SMTP_PORT)
    ap.add_argument("--state-db", default=STATE_DB)
    ap.add_argument("--dashboard-url", default=DASHBOARD_URL)
    ap.add_argument("--feed-file", default=FEED_FILE,
                    help="append fed ms-graph events to this JSON logfile for a Wazuh <localfile> "
                         "(env FEED_FILE; empty = disabled)")
    ap.add_argument("--lookback-hours", type=float, default=0.0,
                    help="on first run per feed, start this many hours in the past (default 0 = forward-only)")
    ap.add_argument("--seed", action="store_true", help="set bookmarks to now (no email), then exit")
    ap.add_argument("--dry-run", action="store_true", help="print what would be sent; no email")
    ap.add_argument("--test", action="store_true", help="send a sample ticket from the most recent match")
    ap.add_argument("--no-group", dest="group", action="store_false",
                    help="one email per event instead of grouping per (admin + object)")
    ap.set_defaults(group=GROUP_TICKETS)
    run(ap.parse_args())

if __name__ == "__main__":
    main()
