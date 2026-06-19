#!/usr/bin/env python3
import os, sys, csv, io, argparse
import sqlite3, hashlib, smtplib, html, re
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage

# =====================================================================
# Wazuh Indexer (OpenSearch) connection helpers
# =====================================================================

# Try OpenSearch first, then Elasticsearch (7.x)
def _get_client(url, user, password, verify):
    try:
        from opensearchpy import OpenSearch
        return OpenSearch(url, http_auth=(user, password), verify_certs=bool(verify), ca_certs=verify or None, ssl_show_warn=False, timeout=30)
    except ImportError:
        pass
    try:
        from elasticsearch import Elasticsearch
        # v7 client
        return Elasticsearch(url, http_auth=(user, password), verify_certs=bool(verify), ca_certs=verify or None, timeout=30)
    except ImportError as e:
        raise SystemExit("Install opensearch-py or elasticsearch client") from e

def _field_caps(client, index, fields):
    try:
        return client.field_caps(index=index, fields=",".join(fields), allow_no_indices=True)
    except Exception:
        return {"fields": {}}

def _pick_agg_field(caps, candidates):
    fields_caps = caps.get("fields", {})
    for f in candidates:
        meta = fields_caps.get(f, {})
        for _type, info in meta.items():
            if info.get("aggregatable", False):
                return f
    return None

# =====================================================================
# Vulnerability email digest (state-driven inventory poller)
# =====================================================================

STATE_DB_DEFAULT     = "/opt/wazuh-vuln-digest/wazuh-vuln-alert.db"
SMTP_SERVER          = os.environ.get("SMTP_SERVER", "smtp.example.com")
MAIL_FROM            = os.environ.get("MAIL_FROM", "wazuh@example.com")
DEFAULT_RECIPIENTS   = os.environ.get("DIGEST_RECIPIENTS", "")  # comma-separated; or pass --recipients
DEFAULT_RENOTIFY_DAYS = 30
# A finding must be ABSENT from the inventory at least this long before it counts
# as "resolved" (and may notify again on a genuine reappearance). Absorbs Wazuh's
# daily re-scan gaps so a still-open finding is never re-announced.
RESOLVE_GRACE_HOURS  = 168         # 7 days

# Wazuh dashboard base URL + per-agent deep link (used for clickable agent links
# in the HTML mails). Override with --dashboard-url. The path works on Wazuh 4.x.
WAZUH_DASHBOARD   = os.environ.get("WAZUH_DASHBOARD", "https://wazuh.example.com")
WAZUH_AGENT_PATH  = "/app/endpoints-summary#/agents?tab=welcome&agent={id}"

_MONTHS = ["", "January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December"]
_SEV_LEVEL = {"critical": 13, "high": 10, "medium": 7, "low": 5}
_SEV_COLOR = {"critical": "#c0392b", "high": "#e67e22", "medium": "#d4ac0d", "low": "#2980b9"}

# Optional noise filter: package names listed here are still recorded in the DB
# (so resolution is tracked) but NEVER emailed. Empty by default -- add the
# packages that are noise in YOUR environment, e.g.:
#   EXCLUDED_PACKAGES = {"linux-image-generic", "sssd", "libsss-idmap0"}
# Substring matches can be added in is_excluded() below.
EXCLUDED_PACKAGES = set()

def is_excluded(package_name, description=""):
    name = package_name or ""
    if name in EXCLUDED_PACKAGES:
        return True
    # Add your own substring rules here if needed, e.g.:
    #   if name.startswith("linux-image"): return True
    return False

def vuln_key(agent_id, cve, package_name, package_version):
    raw = "|".join([str(agent_id), str(cve), str(package_name), str(package_version)])
    return hashlib.sha256(raw.encode()).hexdigest()

def init_db(conn):
    # Digest state (dedup) DB; path from STATE_DB_DEFAULT / --state-db.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sent_vulnerabilities (
            vuln_key TEXT PRIMARY KEY,
            agent_id TEXT,
            agent_name TEXT,
            cve TEXT,
            package_name TEXT,
            package_version TEXT,
            severity TEXT,
            status TEXT,
            first_seen TEXT,
            last_seen TEXT,
            last_sent TEXT,
            send_count INTEGER DEFAULT 1,
            notified_at TEXT
        )
    """)
    # Migration for DBs created before notified_at existed: add the column and
    # backfill currently-open, already-mailed findings so the next run does NOT
    # re-announce all of them as "new".
    cols = [r[1] for r in conn.execute("PRAGMA table_info(sent_vulnerabilities)").fetchall()]
    if "notified_at" not in cols:
        conn.execute("ALTER TABLE sent_vulnerabilities ADD COLUMN notified_at TEXT")
        conn.execute("""UPDATE sent_vulnerabilities SET notified_at = last_sent
                         WHERE status='active' AND send_count >= 1 AND notified_at IS NULL""")
    conn.commit()

_SOURCE_FIELDS = [
    "agent.id", "agent.name",
    "package.name", "package.version", "package.path",
    "package.type", "package.architecture", "package.installed",
    "vulnerability.id", "vulnerability.cve", "vulnerability.severity",
    "vulnerability.description", "vulnerability.reference",
    "vulnerability.score", "vulnerability.cvss",
]

def _map_vuln_hit(s):
    """Map one indexer _source doc to our row dict (flat ECS or legacy)."""
    v = s.get("vulnerability") or s.get("data", {}).get("vulnerability", {}) or {}
    p = s.get("package") or v.get("package", {}) or {}
    a = s.get("agent", {}) or {}
    score = v.get("score", {})
    base = score.get("base") if isinstance(score, dict) else None
    if base is None:
        base = (v.get("cvss", {}).get("cvss3", {}) or {}).get("base_score")
    return {
        "agent_id":          str(a.get("id", "unknown")),
        "agent_name":        str(a.get("name", "unknown")),
        "cve":               str(v.get("id", v.get("cve", "unknown"))),
        "package_name":      str(p.get("name", "unknown")),
        "package_version":   str(p.get("version", "unknown")),
        "package_path":      str(p.get("path", "") or ""),
        "package_type":      str(p.get("type", "") or ""),
        "package_arch":      str(p.get("architecture", "") or ""),
        "package_installed": str(p.get("installed", "") or ""),
        "severity":          str(v.get("severity", "")),
        "score":             str(base) if base is not None else "N/A",
        "reference":         str(v.get("reference", "")),
        "description":       str(v.get("description", v.get("title", ""))),
    }

def collect_open_vuln_docs(client, index_pattern, severities=None):
    """Page through current open vulnerability state documents.
    severities: optional list e.g. ['Critical','High']; falsy = all severities."""
    query = {"terms": {"vulnerability.severity": list(severities)}} if severities else {"match_all": {}}
    body = {
        "size": 1000,
        "_source": _SOURCE_FIELDS,
        "sort": ["_doc"],
        "query": query,
    }
    rows = []
    resp = client.search(index=index_pattern, body=body, scroll="2m",
                         ignore_unavailable=True, allow_no_indices=True)
    sid = resp.get("_scroll_id")
    hits = resp.get("hits", {}).get("hits", [])
    while hits:
        for h in hits:
            rows.append(_map_vuln_hit(h.get("_source", {}) or {}))
        resp = client.scroll(scroll_id=sid, scroll="2m")
        sid = resp.get("_scroll_id")
        hits = resp.get("hits", {}).get("hits", [])
    try:
        client.clear_scroll(scroll_id=sid)
    except Exception:
        pass
    return rows

def collect_docs_for_cve(client, index_pattern, cve):
    """Fetch all current inventory docs for a single CVE (any severity)."""
    body = {
        "size": 10000,
        "_source": _SOURCE_FIELDS,
        "query": {"term": {"vulnerability.id": cve}},
    }
    resp = client.search(index=index_pattern, body=body,
                         ignore_unavailable=True, allow_no_indices=True)
    return [_map_vuln_hit(h.get("_source", {}) or {})
            for h in resp.get("hits", {}).get("hits", [])]

def persist_and_diff(conn, rows, seed=False, renotify_days=DEFAULT_RENOTIFY_DAYS,
                     resolve_grace_hours=RESOLVE_GRACE_HOURS, now=None):
    """Upsert current inventory; return (new, resolved, aging) eligible row lists."""
    now = now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=renotify_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    resolve_cutoff = (datetime.now(timezone.utc) - timedelta(hours=resolve_grace_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur = conn.cursor()

    existing = {}
    for r in cur.execute("SELECT vuln_key, status, send_count, last_sent, last_seen, notified_at FROM sent_vulnerabilities"):
        existing[r[0]] = {"status": r[1], "send_count": r[2] or 0, "last_sent": r[3],
                          "last_seen": r[4], "notified_at": r[5]}

    current_keys = set()
    new_rows = []
    for row in rows:
        k = vuln_key(row["agent_id"], row["cve"], row["package_name"], row["package_version"])
        row["vuln_key"] = k
        current_keys.add(k)
        excluded = is_excluded(row["package_name"], row.get("description", ""))
        prev = existing.get(k)

        if prev is None:
            if seed:
                send_count = 0 if excluded else 1
                last_sent = None if excluded else now
            else:
                send_count = 0
                last_sent = None
            notified = last_sent   # seed-eligible -> now (baselined as mailed); else NULL until mailed
            conn.execute("""
                INSERT INTO sent_vulnerabilities
                    (vuln_key, agent_id, agent_name, cve, package_name, package_version,
                     severity, status, first_seen, last_seen, last_sent, send_count, notified_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (k, row["agent_id"], row["agent_name"], row["cve"], row["package_name"],
                  row["package_version"], row["severity"], "active", now, now, last_sent, send_count, notified))
            if (not seed) and (not excluded):
                new_rows.append(row)
        else:
            conn.execute("""
                UPDATE sent_vulnerabilities
                   SET status='active', last_seen=?, agent_name=?, severity=?
                 WHERE vuln_key=?
            """, (now, row["agent_name"], row["severity"], k))
            # NEW only if never mailed (notified_at NULL) -> notify-once; a genuine
            # reappearance clears notified_at (see RESOLVED) so it can notify again.
            if (not seed) and (not excluded) and (prev["notified_at"] is None):
                new_rows.append(row)

    # NOTE: NEW/aging rows are marked as reported only AFTER a successful send
    # (see mark_reported); we do not commit here so --dry-run can roll back and
    # a failed SMTP send leaves items pending for the next run.

    # RESOLVED: previously active and absent for >= grace (debounce). Transient
    # daily re-scan gaps stay 'active' and are NOT resolved -> no flap mail.
    resolved_rows = []
    for k, prev in existing.items():
        if k not in current_keys and prev["status"] == "active":
            ls = prev["last_seen"]
            if not (ls and ls < resolve_cutoff):
                continue   # absent but within grace (or unknown last_seen) -> leave active
            # genuinely gone: mark resolved and clear the notify guard so a real
            # later reappearance can notify again
            conn.execute("UPDATE sent_vulnerabilities SET status='resolved', notified_at=NULL WHERE vuln_key=?", (k,))
            if (not seed) and prev["notified_at"]:
                d = cur.execute("""SELECT agent_id, agent_name, cve, package_name, package_version
                                     FROM sent_vulnerabilities WHERE vuln_key=?""", (k,)).fetchone()
                if d and not is_excluded(d[3]):
                    resolved_rows.append({"vuln_key": k, "agent_id": d[0], "agent_name": d[1], "cve": d[2],
                                          "package_name": d[3], "package_version": d[4],
                                          "score": "N/A", "reference": "", "description": ""})

    # AGING: still open, already reported, last notified longer than renotify_days ago
    aging_rows = []
    if not seed:
        for r in cur.execute("""SELECT vuln_key, agent_id, agent_name, cve, package_name, package_version, last_sent
                                  FROM sent_vulnerabilities
                                 WHERE status='active' AND send_count>=1
                                   AND last_sent IS NOT NULL AND last_sent < ?""", (cutoff,)):
            if not is_excluded(r[4]):
                aging_rows.append({"vuln_key": r[0], "agent_id": r[1], "agent_name": r[2], "cve": r[3],
                                   "package_name": r[4], "package_version": r[5],
                                   "score": "N/A", "reference": "", "description": "", "last_sent": r[6]})

    return new_rows, resolved_rows, aging_rows

def mark_reported(conn, rows, now):
    """Bump send_count / last_sent / notified_at for rows that were just emailed."""
    for r in rows:
        conn.execute(
            "UPDATE sent_vulnerabilities SET send_count=send_count+1, last_sent=?, notified_at=? WHERE vuln_key=?",
            (now, now, r["vuln_key"]))

def group_by_cve_product_version(rows):
    groups = {}
    for r in rows:
        key = (r["cve"], r["package_name"], r["package_version"])
        g = groups.get(key)
        if g is None:
            g = {"cve": r["cve"], "package_name": r["package_name"],
                 "package_version": r["package_version"], "agents": {},
                 "severity": r.get("severity"),
                 "score": r.get("score"), "reference": r.get("reference"),
                 "package_type": r.get("package_type", ""), "package_arch": r.get("package_arch", ""),
                 "package_installed": r.get("package_installed", ""), "package_path": r.get("package_path", "")}
            groups[key] = g
        g["agents"][r["agent_name"]] = r.get("agent_id", "")
        if (not g.get("score") or g["score"] == "N/A") and r.get("score"):
            g["score"] = r["score"]
        if not g.get("reference") and r.get("reference"):
            g["reference"] = r["reference"]
        # fill representative package metadata from the first row that has it
        for f in ("package_type", "package_arch", "package_installed", "package_path"):
            if not g.get(f) and r.get(f):
                g[f] = r[f]
    return sorted(groups.values(), key=lambda g: (-len(g["agents"]), g["cve"], g["package_name"]))

def build_open_csv(eligible_rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["agent_name", "cve", "package_name", "package_version",
                                        "package_type", "package_arch", "package_path",
                                        "severity", "score", "reference"])
    w.writeheader()
    for r in eligible_rows:
        w.writerow({k: r.get(k, "") for k in w.fieldnames})
    return buf.getvalue().encode("utf-8")

# ---------- subjects ----------

def severity_level(sev):
    return _SEV_LEVEL.get(str(sev or "").lower(), 0)

def fmt_date(dt):
    return f"{dt.day} {_MONTHS[dt.month]} {dt.year}"

def cve_subject(cve, groups, prefix="", resolved=False):
    """Wazuh-style ticket subject for a single CVE (one or many product groups)."""
    all_agents = {}
    for g in groups:
        all_agents.update(g["agents"])
    n = len(all_agents)
    if groups:
        rep = max(groups, key=lambda g: (len(g["agents"]), g.get("package_version") or ""))
        product, lvl = rep["package_name"], severity_level(rep.get("severity"))
    else:
        product, lvl = "?", 0
    who = sorted(all_agents)[0] if n == 1 else f"{n} agents"
    kind = "Vulnerability RESOLVED" if resolved else "Vulnerability"
    return f"{prefix}Wazuh: {kind} - {cve} affects {product} - Level: {lvl} - {who}"

def digest_subject(new_groups, resolved_groups, now_dt):
    return (f"Wazuh: Vulnerabilities - {fmt_date(now_dt)} - "
            f"{len(new_groups)} new, {len(resolved_groups)} resolved")

def report_subject(groups, totals, now_dt):
    return (f"Wazuh: Vulnerabilities Report - {fmt_date(now_dt)} - "
            f"{totals['eligible']} open, {len(groups)} groups")

def groups_by_cve(groups):
    """Bucket (cve,product,version) groups by CVE -> {cve: [groups]} for one-mail-per-CVE."""
    d = {}
    for g in groups:
        d.setdefault(g["cve"], []).append(g)
    return d

def build_ticket_text(cve, groups, resolved=False):
    n_agents = len({a for g in groups for a in g["agents"]})
    verb = "is no longer reported on" if resolved else "currently affects"
    L = [f"{cve} {verb} {n_agents} agent(s).", "=" * 78]
    for g in sorted(groups, key=lambda x: (-len(x["agents"]), x["package_name"])):
        ags = sorted(g["agents"])
        line = f"- {g['cve']} | {g['package_name']} {g['package_version']}"
        if g.get("severity"):
            line += f" | {g['severity']}"
        if g.get("score") and g["score"] != "N/A":
            line += f" | CVSS {g['score']}"
        L.append(line)
        L.append(f"    affected agents ({len(ags)}): {', '.join(ags)}")
        if g.get("reference"):
            L.append(f"    reference: {g['reference']}")
    return "\n".join(L)

# ---------- per-product grouping (one ticket = one remediation) ----------

def product_base(name):
    """Package name with an embedded dotted version stripped, for per-product
    grouping. 'Python 3.14.6 (64-bit)' -> 'Python (64-bit)'; 'Hoppscotch' -> 'Hoppscotch';
    Linux 'python3.12' is unchanged (no whitespace before the version)."""
    base = re.sub(r'\s+v?\d+(?:\.\d+)+', '', str(name or ""))
    base = re.sub(r'\s{2,}', ' ', base).strip(" -")
    return base or str(name or "")

# Curated families for products whose Debian packages have no common name stem
# (the heuristic below can't unify them). canonical -> substrings identifying a member.
# Edit/extend as you find other noisy multi-package products.
_FAMILY_ALIASES = (
    ("samba", ("samba", "smbclient", "wbclient", "libldb", "python3-ldb",
               "libtevent", "libtalloc", "libtdb")),
)

def product_family(name):
    """Internal grouping key = a remediation 'family'. First applies the curated
    aliases (e.g. samba), then strips the embedded version, a leading 'lib', and
    common Debian sub-package suffixes so e.g. python3.12, libpython3.12-minimal,
    libpython3.12-stdlib, libpython3.12t64 collapse to one key."""
    raw = product_base(name).strip().lower()
    for canon, subs in _FAMILY_ALIASES:
        if any(sub in raw for sub in subs):
            return canon
    s = raw
    if s.startswith("lib") and len(s) > 4:
        s = s[3:]
    sufs = ("-minimal", "-stdlib", "-runtime", "-common", "-utils", "-tools",
            "-data", "-doc", "-dbg", "-dev", "-bin", "-libs", "-lib", "-venv", "t64")
    changed = True
    while changed:
        changed = False
        for suf in sufs:
            if s.endswith(suf) and len(s) > len(suf) + 1:
                s = s[:-len(suf)]
                changed = True
    return s.strip(" -") or product_base(name).lower()

def product_display(groups):
    """Human-readable product name for a family. Curated families use their canonical
    name (e.g. 'samba'); otherwise the shortest member, version-stripped."""
    names = [g["package_name"] for g in groups if g.get("package_name")] or ["?"]
    fam = product_family(names[0])
    if fam in {c for c, _ in _FAMILY_ALIASES}:
        return fam
    return product_base(min(names, key=len))

def groups_by_product(groups):
    """Bucket (cve,product,version) groups by remediation family -> {family: [groups]}."""
    d = {}
    for g in groups:
        d.setdefault(product_family(g["package_name"]), []).append(g)
    return d

def product_subject(groups, resolved=False):
    product = product_display(groups)
    cves = sorted({g["cve"] for g in groups})
    agents = set()
    for g in groups:
        agents |= set(g["agents"])
    n = len(agents)
    lvl = max((severity_level(g.get("severity")) for g in groups), default=0)
    who = sorted(agents)[0] if n == 1 else f"{n} agents"
    cvepart = cves[0] if len(cves) == 1 else f"{len(cves)} CVEs"
    kind = "Vulnerability RESOLVED" if resolved else "Vulnerability"
    return f"Wazuh: {kind} - {product} - Level: {lvl} - {cvepart} - {who}"

def build_product_text(groups, resolved=False):
    product = product_display(groups)
    cves = sorted({g["cve"] for g in groups})
    agents = set()
    for g in groups:
        agents |= set(g["agents"])
    verb = "is no longer reported on" if resolved else "currently affects"
    L = [f"{product} {verb} {len(agents)} agent(s) via {len(cves)} CVE(s).", "=" * 78]
    for cve in cves:
        cg = [g for g in groups if g["cve"] == cve]
        sev = next((g.get("severity") for g in cg if g.get("severity")), "")
        score = next((g.get("score") for g in cg if g.get("score") and g["score"] != "N/A"), "")
        line = f"- {cve}"
        if sev:
            line += f" | {sev}"
        if score:
            line += f" | CVSS {score}"
        L.append(line)
        for g in sorted(cg, key=lambda x: x["package_version"]):
            L.append(f"    {g['package_name']} {g['package_version']}: {', '.join(sorted(g['agents']))}")
        ref = next((g.get("reference") for g in cg if g.get("reference")), "")
        if ref and not resolved:
            L.append(f"    reference: {ref}")
    return "\n".join(L)

# ---------- HTML rendering ----------

def _esc(s):
    return html.escape(str(s if s is not None else ""))

def agent_link(dash, agent_id):
    dash = (dash or "").rstrip("/")
    return (dash + WAZUH_AGENT_PATH.format(id=agent_id)) if (dash and agent_id) else ""

def _ref_links_html(reference):
    parts = [p.strip() for p in str(reference or "").replace(";", ",").split(",") if p.strip()]
    links = [f'<a href="{_esc(p)}" style="color:#2563eb;">{_esc(p)}</a>'
             for p in parts if p.lower().startswith("http")]
    return " &middot; ".join(links)

def _agents_html(agents, dash):
    out = []
    for name in sorted(agents):
        url = agent_link(dash, agents[name])
        out.append(f'<a href="{_esc(url)}" style="color:#2563eb;text-decoration:none;">{_esc(name)}</a>'
                   if url else _esc(name))
    return ", ".join(out)

def _pkg_detail_html(g):
    bits = []
    name, ver = g.get("package_name"), g.get("package_version")
    if name and name != "unknown":
        label = _esc(name) + (f" ({_esc(ver)})" if ver and ver != "unknown" else "")
        bits.append(f"<strong>Package:</strong> {label}")
    ta = "/".join(x for x in [g.get("package_type"), g.get("package_arch")] if x)
    if ta:
        bits.append(_esc(ta))
    if g.get("package_installed"):
        bits.append("installed " + _esc(str(g["package_installed"])[:10]))
    if g.get("package_path"):
        bits.append("<strong>path:</strong> " + _esc(g["package_path"]))
    return " &middot; ".join(bits)

def _group_card_html(g, dash, show_score=True):
    sev = (g.get("severity") or "").lower()
    color = _SEV_COLOR.get(sev, "#7f8c8d")
    badge = ""
    if g.get("severity"):
        badge += (f'<span style="background:{color};color:#ffffff;padding:2px 8px;'
                  f'border-radius:3px;font-size:12px;font-weight:bold;">{_esc(g["severity"])}</span>')
    if show_score and g.get("score") and g["score"] != "N/A":
        badge += f'&nbsp;&nbsp;<span style="color:#475569;font-size:12px;">CVSS {_esc(g["score"])}</span>'
    pkg = _pkg_detail_html(g)
    refs = _ref_links_html(g.get("reference"))
    content = (
        f'<div style="font-size:15px;font-weight:bold;color:#0f172a;margin-bottom:5px;">'
        f'{_esc(g["cve"])} <span style="color:#64748b;font-weight:normal;">affects</span> '
        f'{_esc(g["package_name"])} {_esc(g.get("package_version") or "")}</div>'
        + (f'<div style="margin-bottom:7px;">{badge}</div>' if badge else "")
        + (f'<div style="font-size:12px;color:#475569;margin-bottom:6px;">{pkg}</div>' if pkg else "")
        + f'<div style="font-size:13px;color:#0f172a;"><strong>Affected agents ({len(g["agents"])}):</strong> '
          f'{_agents_html(g["agents"], dash)}</div>'
        + (f'<div style="font-size:12px;color:#64748b;margin-top:6px;">References: {refs}</div>'
           if (show_score and refs) else "")
    )
    # Flat look: full-height severity stripe (4px) via the padding-left trick.
    # The inner background matches the panel (#ffffff) so there is NO visible card
    # box -- only the colored left stripe and a thin separator line per item.
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="{color}" '
        f'style="background:{color};"><tr><td style="padding-left:4px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffffff" '
        'style="background:#ffffff;"><tr><td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;">'
        + content + '</td></tr></table>'
        '</td></tr></table>'
    )

def _section_bar_html(label, count, barcolor):
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:18px 0 6px;"><tr>'
        f'<td bgcolor="{barcolor}" style="background:{barcolor};color:#ffffff;padding:6px 12px;'
        f'font-size:14px;font-weight:bold;">{_esc(label)} ({count})</td></tr></table>'
    )

def _html_page(title_html, intro_html, body_html, accent="#b3261e"):
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<meta name="color-scheme" content="light dark">'
        '<meta name="supported-color-schemes" content="light dark"></head>'
        '<body style="margin:0;padding:0;background:#eef2f6;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#eef2f6">'
        '<tr><td align="center" style="padding:18px;">'
        '<table role="presentation" width="840" cellpadding="0" cellspacing="0" '
        "style=\"width:840px;max-width:840px;font-family:'Segoe UI',Arial,sans-serif;\">"
        f'<tr><td bgcolor="{accent}" style="background:{accent};color:#ffffff;padding:14px 18px;'
        f'font-size:18px;font-weight:bold;">{title_html}</td></tr>'
        '<tr><td bgcolor="#ffffff" style="background:#ffffff;color:#1f2933;padding:16px 18px;'
        'border:1px solid #e3e8ef;border-top:none;">'
        f'{intro_html}{body_html}'
        '<div style="margin-top:18px;font-size:11px;color:#94a3b8;border-top:1px solid #e3e8ef;'
        f'padding-top:8px;">Automated message from Wazuh ({_esc(WAZUH_DASHBOARD)}). '
        'Grouped by CVE + product + version.</div>'
        '</td></tr></table></td></tr></table></body></html>'
    )

def build_ticket_html(cve, groups, dash, is_test=False, resolved=False):
    n_agents = len({a for g in groups for a in g["agents"]})
    sev = (groups[0].get("severity") if groups else "") or ""
    accent = "#1a7f37" if resolved else _SEV_COLOR.get(sev.lower(), "#b3261e")
    kind = "Vulnerability RESOLVED" if resolved else "Vulnerability ticket"
    title = f"{'[TEST] ' if is_test else ''}{kind} &mdash; {_esc(cve)}"
    intro = '<p style="margin:0 0 12px;">'
    if is_test:
        intro += ('<strong>This is a manual TEST mail.</strong> Exclusions are not applied and '
                  'the dedup database was not modified.<br>')
    verb = "is no longer reported on" if resolved else "currently affects"
    intro += f'{_esc(cve)} {verb} <strong>{n_agents}</strong> agent(s).</p>'
    body = ("".join(_group_card_html(g, dash) for g in groups) if groups
            else '<p style="color:#94a3b8;">No agent currently reports this CVE in the inventory.</p>')
    return _html_page(title, intro, body, accent=accent)

def build_product_html(groups, dash, resolved=False):
    product = product_display(groups)
    cves = sorted({g["cve"] for g in groups})
    agents = set()
    for g in groups:
        agents |= set(g["agents"])
    top = max(groups, key=lambda g: severity_level(g.get("severity")), default=None)
    top_sev = (top.get("severity") if top else "") or ""
    accent = "#1a7f37" if resolved else _SEV_COLOR.get(top_sev.lower(), "#b3261e")
    kind = "Vulnerability RESOLVED" if resolved else "Vulnerability ticket"
    verb = "is no longer reported on" if resolved else "currently affects"
    title = f"{kind} &mdash; {_esc(product)}"
    intro = (f'<p style="margin:0 0 12px;">{_esc(product)} {verb} '
             f'<strong>{len(agents)}</strong> agent(s) via <strong>{len(cves)}</strong> CVE(s).</p>')
    cards = []
    for cve in cves:
        cg = [g for g in groups if g["cve"] == cve]
        sev = next((g.get("severity") for g in cg if g.get("severity")), "")
        color = _SEV_COLOR.get((sev or "").lower(), "#7f8c8d")
        score = next((g.get("score") for g in cg if g.get("score") and g["score"] != "N/A"), "")
        ref = next((g.get("reference") for g in cg if g.get("reference")), "")
        badge = (f'<span style="background:{color};color:#ffffff;padding:2px 8px;border-radius:3px;'
                 f'font-size:12px;font-weight:bold;">{_esc(sev)}</span>') if sev else ""
        if score:
            badge += f'&nbsp;&nbsp;<span style="color:#475569;font-size:12px;">CVSS {_esc(score)}</span>'
        vlines = "".join(
            f'<div style="font-size:13px;color:#0f172a;margin-top:3px;">'
            f'<strong>{_esc(g["package_name"])} {_esc(g.get("package_version") or "")}</strong> '
            f'({len(g["agents"])}): {_agents_html(g["agents"], dash)}</div>'
            for g in sorted(cg, key=lambda x: x["package_version"]))
        refhtml = (f'<div style="font-size:12px;color:#64748b;margin-top:5px;">References: {_ref_links_html(ref)}</div>'
                   if (not resolved and ref) else "")
        content = (f'<div style="font-size:15px;font-weight:bold;color:#0f172a;margin-bottom:4px;">{_esc(cve)}</div>'
                   + (f'<div style="margin-bottom:6px;">{badge}</div>' if badge else "")
                   + vlines + refhtml)
        cards.append(
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="{color}" '
            f'style="background:{color};"><tr><td style="padding-left:4px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffffff" '
            'style="background:#ffffff;"><tr><td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;">'
            + content + '</td></tr></table></td></tr></table>')
    return _html_page(title, intro, "".join(cards), accent=accent)

def build_digest_html(new_groups, resolved_groups, aging_groups, totals, dash, now_dt):
    title = f"Vulnerabilities &mdash; {_esc(fmt_date(now_dt))}"
    intro = (f'<p style="margin:0 0 12px;">Open (eligible/total): '
             f'<strong>{totals["eligible"]}</strong>/{totals["total"]} across '
             f'{totals["agents"]} agents.<br>'
             f'<strong>{len(new_groups)}</strong> new &middot; '
             f'<strong>{len(resolved_groups)}</strong> resolved &middot; '
             f'<strong>{len(aging_groups)}</strong> open &gt; {totals["renotify_days"]} days</p>')
    def section(label, groups, barcolor, show_score=True):
        head = _section_bar_html(label, len(groups), barcolor)
        if not groups:
            return head + '<div style="color:#94a3b8;font-size:13px;padding-left:2px;">none</div>'
        return head + "".join(_group_card_html(g, dash, show_score=show_score) for g in groups)
    body = (section("New vulnerabilities", new_groups, "#b3261e")
            + section("Resolved since last run", resolved_groups, "#1a7f37", show_score=False)
            + section(f"Still open > {totals['renotify_days']} days", aging_groups, "#b06a00", show_score=False))
    return _html_page(title, intro, body, accent="#b3261e")

def build_report_html(groups, totals, dash, now_dt):
    title = f"Vulnerabilities report &mdash; {_esc(fmt_date(now_dt))}"
    intro = (f'<p style="margin:0 0 12px;">Open (eligible/total): '
             f'<strong>{totals["eligible"]}</strong>/{totals["total"]} across '
             f'{totals["agents"]} agents &middot; {len(groups)} groups (CVE + product + version).</p>')
    body = _section_bar_html("Open vulnerabilities", len(groups), "#b3261e")
    body += ("".join(_group_card_html(g, dash) for g in groups) if groups
             else '<div style="color:#94a3b8;font-size:13px;padding-left:2px;">none</div>')
    return _html_page(title, intro, body, accent="#b3261e")

def build_report_text(groups, totals, now):
    L = [f"Wazuh Vulnerabilities Report ({now}).",
         f"Open (eligible/total): {totals['eligible']}/{totals['total']} "
         f"across {totals['agents']} agents, {len(groups)} groups (CVE+product+version).",
         "=" * 78]
    for g in groups:
        ags = sorted(g["agents"])
        head = f"- {g['cve']} | {g['package_name']} {g['package_version']}"
        if g.get("score") and g["score"] != "N/A":
            head += f" | CVSS {g['score']}"
        L.append(head)
        L.append(f"    agents ({len(ags)}): {', '.join(ags)}")
    return "\n".join(L)

def build_digest(new_groups, resolved_groups, aging_groups, totals, now):
    L = []
    L.append("This is an automatic vulnerability digest from your Wazuh instance.")
    L.append("")
    L.append(f"Generated: {now}")
    L.append(f"Open (eligible/total): {totals['eligible']}/{totals['total']} "
             f"across {totals['agents']} agents")
    L.append(f"NEW: {len(new_groups)} | RESOLVED: {len(resolved_groups)} | "
             f"Open > {totals['renotify_days']}d: {len(aging_groups)} (grouped by CVE+product+version)")
    L.append("=" * 78)

    def render(title, groups, show_score=True):
        L.append("")
        L.append(f"## {title} ({len(groups)} groups)")
        if not groups:
            L.append("  (none)")
            return
        for g in groups:
            ags = sorted(g["agents"])
            head = f"- {g['cve']} | {g['package_name']} {g['package_version']}"
            if show_score and g.get("score") and g["score"] != "N/A":
                head += f" | CVSS {g['score']}"
            L.append(head)
            L.append(f"    affected agents ({len(ags)}): {', '.join(ags)}")
            if show_score and g.get("reference"):
                L.append(f"    reference: {g['reference']}")

    render("NEW vulnerabilities", new_groups)
    render("RESOLVED since last digest", resolved_groups, show_score=False)
    render(f"Still open longer than {totals['renotify_days']} days", aging_groups, show_score=False)
    L.append("")
    L.append("Full current eligible vulnerability inventory is attached as CSV.")
    return "\n".join(L)

def send_mail(recipients, subject, text_body, html_body=None, csv_bytes=None):
    em = EmailMessage()
    em["From"] = MAIL_FROM
    em["To"] = ", ".join(recipients)
    em["Subject"] = subject
    em.set_content(text_body)                       # plain-text fallback
    if html_body:
        em.add_alternative(html_body, subtype="html")
    if csv_bytes:
        em.add_attachment(csv_bytes, maintype="text", subtype="csv",
                          filename="open_vulnerabilities.csv")
    with smtplib.SMTP(SMTP_SERVER, 25, timeout=30) as s:
        s.ehlo()
        s.send_message(em)

def run_notify(args):
    verify = False if args.no_verify else (args.ca if args.ca else True)
    # Fail fast with a clear message if the CA path is set but unreadable.
    if isinstance(verify, str) and not os.access(verify, os.R_OK):
        raise SystemExit(f"CA file not readable: {verify} (run as a user that can read it, or use --no-verify)")
    client = _get_client(args.index_url, args.user, args.password, verify=verify)

    severities = [s.strip() for s in (args.severity or "").split(",") if s.strip()]
    rows = collect_open_vuln_docs(client, args.index_pattern, severities)
    total = len(rows)
    eligible = [r for r in rows if not is_excluded(r["package_name"], r.get("description", ""))]
    agents = len({r["agent_id"] for r in rows})
    now_dt = datetime.now(timezone.utc)
    now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[notify] indexer={args.index_url} index={args.index_pattern} severity={severities or 'ALL'} "
          f"total={total} eligible={len(eligible)} excluded={total - len(eligible)} agents={agents}")
    if total == 0:
        print("[notify] WARNING: 0 documents matched — check the index pattern, that the state "
              "index is populated, and that any --severity values exactly match the data.")

    conn = sqlite3.connect(args.state_db)
    try:
        init_db(conn)

        # Safety net: a non-seed run against an EMPTY db would email the whole
        # backlog (~136 groups) as "new". Require an explicit baseline first.
        pre_count = conn.execute("SELECT COUNT(*) FROM sent_vulnerabilities").fetchone()[0]
        if pre_count == 0 and not args.seed and not args.dry_run:
            raise SystemExit("State DB is empty. Run once with --seed to record the current "
                             "baseline (no email), then schedule --mode notify. "
                             "Use --dry-run to preview without seeding.")

        new_rows, resolved_rows, aging_rows = persist_and_diff(
            conn, rows, seed=args.seed, renotify_days=args.renotify_days,
            resolve_grace_hours=args.resolve_grace_hours, now=now)

        if args.seed:
            conn.commit()
            print(f"[seed] recorded {total} vulnerability rows "
                  f"({len(eligible)} eligible / {total - len(eligible)} excluded) "
                  f"into {args.state_db}. No email sent.")
            return

        new_groups = group_by_cve_product_version(new_rows)
        resolved_groups = group_by_cve_product_version(resolved_rows)
        aging_groups = group_by_cve_product_version(aging_rows)
        totals = {"total": total, "eligible": len(eligible), "agents": agents,
                  "renotify_days": args.renotify_days}
        dash = args.dashboard_url or WAZUH_DASHBOARD
        new_by_prod = groups_by_product(new_groups)        # one email per product
        resolved_by_prod = groups_by_product(resolved_groups)

        if args.dry_run:
            conn.rollback()   # a dry run must not change state
            print(f"[dry-run] would send {len(new_by_prod)} new product-ticket(s), "
                  f"{len(resolved_by_prod)} resolved ticket(s), "
                  f"{1 if aging_groups else 0} aging digest ({len(aging_groups)} groups); "
                  f"recipients={args.recipients or DEFAULT_RECIPIENTS!r}")
            for prod, grps in sorted(new_by_prod.items()):
                print("  NEW     :", product_subject(grps))
            for prod, grps in sorted(resolved_by_prod.items()):
                print("  RESOLVED:", product_subject(grps, resolved=True))
            return

        if not (new_by_prod or resolved_by_prod or aging_groups) and not args.always:
            conn.commit()     # persist inventory upserts even when no email
            print("[notify] nothing new / resolved / aging this run; no email sent.")
            return

        recipients = [x.strip() for x in (args.recipients or DEFAULT_RECIPIENTS).split(",") if x.strip()]
        if not recipients:
            raise SystemExit("No recipients configured (set DEFAULT_RECIPIENTS or --recipients).")

        # One email per PRODUCT (NEW), one per product (RESOLVED); the 30-day aging
        # reminder stays a single digest so it can't flood. Each send is isolated,
        # then we mark only what was sent -> one bad send can't cause mass re-send.
        sent_rows, sent_n, res_n, aged, errs = [], 0, 0, 0, 0
        for prod, grps in sorted(new_by_prod.items()):
            try:
                send_mail(recipients, product_subject(grps),
                          build_product_text(grps), build_product_html(grps, dash))
                sent_rows += [r for r in new_rows if product_family(r["package_name"]) == prod]
                sent_n += 1
            except Exception as e:
                errs += 1; print(f"[notify] NEW send failed for {prod}: {e}")
        for prod, grps in sorted(resolved_by_prod.items()):
            try:
                send_mail(recipients, product_subject(grps, resolved=True),
                          build_product_text(grps, resolved=True),
                          build_product_html(grps, dash, resolved=True))
                res_n += 1
            except Exception as e:
                errs += 1; print(f"[notify] RESOLVED send failed for {prod}: {e}")
        if aging_groups:
            try:
                subj = (f"Wazuh: Vulnerabilities - {fmt_date(now_dt)} - "
                        f"{len(aging_groups)} still open > {args.renotify_days}d")
                send_mail(recipients, subj,
                          build_digest([], [], aging_groups, totals, now),
                          build_digest_html([], [], aging_groups, totals, dash, now_dt),
                          build_open_csv(eligible))
                sent_rows += aging_rows
                aged = 1
            except Exception as e:
                errs += 1; print(f"[notify] aging digest send failed: {e}")

        mark_reported(conn, sent_rows, now)
        conn.commit()
        print(f"[notify] sent {sent_n} new ticket(s), {res_n} resolved, {aged} aging digest "
              f"to {recipients}" + (f" ({errs} send error(s))" if errs else ""))
    finally:
        conn.close()

def run_test_cve(args):
    """Send a one-off TEST ticket for a single CVE. Does NOT touch the dedup DB."""
    verify = False if args.no_verify else (args.ca if args.ca else True)
    if isinstance(verify, str) and not os.access(verify, os.R_OK):
        raise SystemExit(f"CA file not readable: {verify} (or use --no-verify)")
    client = _get_client(args.index_url, args.user, args.password, verify=verify)

    cve = args.test_cve.strip()
    rows = collect_docs_for_cve(client, args.index_pattern, cve)
    groups = group_by_cve_product_version(rows)
    n_agents = len({r["agent_id"] for r in rows})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dash = args.dashboard_url or WAZUH_DASHBOARD

    subject = cve_subject(cve, groups, prefix="[TEST] ")
    preamble = (f"TEST ticket for {cve} (generated {now}). This is a manual test mail; the dedup "
                f"DB was NOT modified and exclusions are NOT applied here.\n\n")
    text_body = preamble + (build_ticket_text(cve, groups) if groups
                            else f"No agent currently reports {cve} in the inventory.")
    html_body = build_ticket_html(cve, groups, dash, is_test=True)

    print(f"[test-cve] {cve}: {len(rows)} hits / {n_agents} agents / {len(groups)} groups")
    if args.dry_run:
        print("----- SUBJECT -----"); print(subject)
        print("----- TEXT BODY -----"); print(text_body)
        print(f"----- [dry-run] HTML {len(html_body)} bytes -----")
        return
    recipients = [x.strip() for x in (args.recipients or DEFAULT_RECIPIENTS).split(",") if x.strip()]
    if not recipients:
        raise SystemExit("No recipients (set --recipients or DEFAULT_RECIPIENTS).")
    send_mail(recipients, subject, text_body, html_body)
    print(f"[test-cve] test ticket for {cve} sent to {recipients}")

def run_test_report(args):
    """Send a sample weekly digest built from the CURRENT inventory. No DB change."""
    verify = False if args.no_verify else (args.ca if args.ca else True)
    if isinstance(verify, str) and not os.access(verify, os.R_OK):
        raise SystemExit(f"CA file not readable: {verify} (or use --no-verify)")
    client = _get_client(args.index_url, args.user, args.password, verify=verify)

    severities = [s.strip() for s in (args.severity or "").split(",") if s.strip()]
    rows = collect_open_vuln_docs(client, args.index_pattern, severities)
    eligible = [r for r in rows if not is_excluded(r["package_name"], r.get("description", ""))]
    groups = group_by_cve_product_version(eligible)
    sample = groups[:15]                              # keep the preview readable
    now_dt = datetime.now(timezone.utc)
    now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    dash = args.dashboard_url or WAZUH_DASHBOARD
    totals = {"total": len(rows), "eligible": len(eligible),
              "agents": len({r["agent_id"] for r in rows}), "renotify_days": args.renotify_days}

    subject = "[TEST] " + report_subject(sample, totals, now_dt)
    text_body = ("PREVIEW of the report - sample of the current open vulnerability inventory "
                 f"({len(sample)} of {len(groups)} groups).\n\n"
                 + build_report_text(sample, totals, now))
    html_body = build_report_html(sample, totals, dash, now_dt)
    csv_bytes = build_open_csv(eligible)

    print(f"[test-report] preview {len(sample)}/{len(groups)} groups, "
          f"{len(eligible)} eligible / {totals['total']} total")
    if args.dry_run:
        print("----- SUBJECT -----"); print(subject)
        print("----- TEXT BODY -----"); print(text_body)
        print(f"----- [dry-run] HTML {len(html_body)} bytes, CSV {len(csv_bytes)} bytes -----")
        return
    recipients = [x.strip() for x in (args.recipients or DEFAULT_RECIPIENTS).split(",") if x.strip()]
    if not recipients:
        raise SystemExit("No recipients (set --recipients or DEFAULT_RECIPIENTS).")
    send_mail(recipients, subject, text_body, html_body, csv_bytes)
    print(f"[test-report] sample report sent to {recipients}")

def run_report(args):
    """Send the periodic REPORT: a snapshot of all currently-open vulnerabilities.
    Stateless - reads the indexer only, never touches the dedup DB, so it can run
    on its own schedule + recipients without affecting the ticket stream."""
    verify = False if args.no_verify else (args.ca if args.ca else True)
    if isinstance(verify, str) and not os.access(verify, os.R_OK):
        raise SystemExit(f"CA file not readable: {verify} (or use --no-verify)")
    client = _get_client(args.index_url, args.user, args.password, verify=verify)

    severities = [s.strip() for s in (args.severity or "").split(",") if s.strip()]
    rows = collect_open_vuln_docs(client, args.index_pattern, severities)
    eligible = [r for r in rows if not is_excluded(r["package_name"], r.get("description", ""))]
    groups = group_by_cve_product_version(eligible)
    now_dt = datetime.now(timezone.utc)
    now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    dash = args.dashboard_url or WAZUH_DASHBOARD
    totals = {"total": len(rows), "eligible": len(eligible),
              "agents": len({r["agent_id"] for r in rows}), "renotify_days": args.renotify_days}

    subject = report_subject(groups, totals, now_dt)
    text_body = build_report_text(groups, totals, now)
    html_body = build_report_html(groups, totals, dash, now_dt)
    csv_bytes = build_open_csv(eligible)

    print(f"[report] {len(eligible)} eligible / {len(rows)} total, {len(groups)} groups")
    if args.dry_run:
        print("----- SUBJECT -----"); print(subject)
        print(f"----- [dry-run] HTML {len(html_body)} bytes, CSV {len(csv_bytes)} bytes; "
              f"recipients={args.recipients or DEFAULT_RECIPIENTS!r} -----")
        return
    recipients = [x.strip() for x in (args.recipients or DEFAULT_RECIPIENTS).split(",") if x.strip()]
    if not recipients:
        raise SystemExit("No recipients (set --recipients or DEFAULT_RECIPIENTS).")
    send_mail(recipients, subject, text_body, html_body, csv_bytes)
    print(f"[report] report sent to {recipients}")

def main():
    ap = argparse.ArgumentParser(
        description="Email a per-product digest of vulnerabilities read from the Wazuh Indexer.")
    ap.add_argument("--index-url", default='https://127.0.0.1:9200', help="Wazuh Indexer URL, e.g. https://indexer:9200")
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", 'admin'), help="indexer user")
    ap.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASSWORD", ''),
                    help="indexer password (prefer the WAZUH_INDEXER_PASSWORD env var)")
    ap.add_argument("--no-verify", action="store_true", help="skip TLS verification of the indexer certificate")
    ap.add_argument("--ca", default='/etc/filebeat/certs/root-ca.pem', help="CA bundle for indexer TLS verification")
    ap.add_argument("--index-pattern", default="wazuh-states-vulnerabilities-*")
    ap.add_argument("--severity", default=os.environ.get("DIGEST_SEVERITY", ""),
                    help="comma-separated severities to include, e.g. 'Critical,High'; empty (default) = all")
    ap.add_argument("--seed", action="store_true", help="record current findings as baseline, send no email")
    ap.add_argument("--dry-run", action="store_true", help="print what would be sent; send no email, no DB change")
    ap.add_argument("--always", action="store_true", help="send even when there is nothing new/resolved/aging")
    ap.add_argument("--recipients", default=DEFAULT_RECIPIENTS, help="comma-separated recipient list")
    ap.add_argument("--renotify-days", type=int, default=DEFAULT_RENOTIFY_DAYS, help="aging threshold in days")
    ap.add_argument("--resolve-grace-hours", type=int, default=RESOLVE_GRACE_HOURS,
                    help="hours a finding must be absent before it counts as resolved (anti-flap)")
    ap.add_argument("--state-db", default=STATE_DB_DEFAULT, help="sqlite dedup DB path")
    ap.add_argument("--test-cve", default=None,
                    help="send a one-off TEST ticket for this CVE id, then exit; does not touch the dedup DB")
    ap.add_argument("--test-report", action="store_true",
                    help="send a sample report from current inventory, then exit; no DB change")
    ap.add_argument("--report", action="store_true",
                    help="send the periodic REPORT (full current-state snapshot); stateless, no DB change")
    ap.add_argument("--dashboard-url", default=WAZUH_DASHBOARD,
                    help="Wazuh dashboard base URL for clickable agent links in the HTML mail")
    args = ap.parse_args()

    if args.test_cve:
        run_test_cve(args)
    elif args.test_report:
        run_test_report(args)
    elif args.report:
        run_report(args)
    else:
        run_notify(args)

if __name__ == "__main__":
    main()
