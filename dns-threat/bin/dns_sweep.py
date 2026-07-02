#!/usr/bin/env python3
"""
DNS anomaly sweep for Wazuh archives (Sysmon Event 22 / DNS Query).

Catches the volume-based anomalies the stateless dns_threat rules (100700-100703)
cannot: DGA bursts, many-distinct-subdomain tunneling, and (lightweight) beaconing,
in addition to mirroring the rule signatures (denylist / suspicious-TLD / dynamic-DNS /
long-label tunneling).

Usage:
  dns_sweep.py [FILE ...]      # scan given archive files (.json or .json.gz)
  dns_sweep.py                 # default: yesterday's rotated archive

Cron example (06:10 daily, scan yesterday, exit 2 if anything actionable):
  10 6 * * *  /usr/bin/python3 /opt/wazuh-recipes/dns_sweep.py >> /var/log/dns_sweep.log 2>&1

Environment:
  DNS_SWEEP_OUT       report output dir            (default ~/dns-sweep-reports)
  DNS_SWEEP_MANYSUBS  distinct-subdomains-per-parent threshold for tunneling (default 60)
  DNS_SWEEP_GOOD      comma-separated INTERNAL/known-good domain suffixes to ignore in the
                      volume heuristics, e.g. "corp.example,example.com"
  DNS_SWEEP_OWN       comma-separated OWN domains to exclude from the suspicious-TLD count,
                      e.g. "example.lol"

Exit code: 0 = clean, 2 = actionable hits (denylist/dynamic-DNS/tunneling) found.
"""
import sys, os, gzip, json, re, math, collections, datetime, glob

DENYLIST = "/var/ossec/etc/lists/malicious-ioc/malicious-domains"
ARCHIVE_DIR = "/var/ossec/logs/archives"
OUTDIR = os.environ.get("DNS_SWEEP_OUT", os.path.expanduser("~/dns-sweep-reports"))
MANYSUBS = int(os.environ.get("DNS_SWEEP_MANYSUBS", "60"))   # distinct subdomains/parent to flag tunneling

TLD = re.compile(r"(?i)\.(top|xyz|tk|ml|ga|cf|gq|click|monster|quest|cfd|sbs|zip|mov|lol|work|buzz)\.?$")
DDNS = re.compile(r"(?i)(duckdns\.org|no-ip\.|noip\.com|ddns\.net|dyndns|ngrok|nip\.io|sslip\.io|workers\.dev|trycloudflare|hopto\.org|zapto\.org|serveo|loca\.lt|afraid\.org|dynu\.com)")
TUN = re.compile(r"(?i)[a-z0-9\-]{50,}\.")

# Your own domain(s) that legitimately use a flagged TLD -- excluded from the TLD count.
_own = [d.strip().lower() for d in os.environ.get("DNS_SWEEP_OWN", "").split(",") if d.strip()]
OWN = re.compile(r"(?i)(^|\.)(" + "|".join(re.escape(d) for d in _own) + r")\.?$") if _own else None

# Known-good suffixes stripped before the volume heuristics. Add your INTERNAL domains
# via DNS_SWEEP_GOOD (these org-specific ones are deliberately NOT hard-coded here).
_internal = [g.strip().lower() for g in os.environ.get("DNS_SWEEP_GOOD", "").split(",") if g.strip()]
GOOD = tuple(_internal) + (
        ".local", ".arpa",
        "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "office.net",
        "microsoftonline.com", "azure.com", "azure.net", "azureedge.net", "windows.net",
        "akamai.net", "akamaiedge.net", "akadns.net", "edgekey.net", "msftncsi.com",
        "google.com", "googleapis.com", "gstatic.com", "apple.com", "digicert.com",
        "cloudflare.com", "veeam.com", "github.com", "githubusercontent.com")

def entropy(s):
    if not s: return 0.0
    c = collections.Counter(s); n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def is_good(d):
    return any(d == g or d.endswith("." + g) or d.endswith(g) for g in GOOD)

def default_files():
    y = datetime.date.today() - datetime.timedelta(days=1)
    mon = y.strftime("%b")                      # Jun
    p = os.path.join(ARCHIVE_DIR, str(y.year), mon, "ossec-archives-%02d.json.gz" % y.day)
    if os.path.exists(p): return [p]
    return [os.path.join(ARCHIVE_DIR, "archives.json")]   # fallback: live

def opener(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, "r", errors="replace")

def load_denylist():
    s = set()
    try:
        with open(DENYLIST) as f:
            for ln in f:
                k = ln.split(":")[0].strip().lower()
                if k: s.add(k)
    except Exception as e:
        print("WARN: denylist not loaded:", e, file=sys.stderr)
    return s

def main():
    files = sys.argv[1:] or default_files()
    expanded = []
    for f in files: expanded += sorted(glob.glob(f)) or [f]
    files = [f for f in expanded if os.path.exists(f)]
    if not files:
        print("No archive files found:", expanded, file=sys.stderr); return 1

    mal = load_denylist()
    cat = {k: collections.Counter() for k in ("denylist", "tld", "ddns", "tunnel")}
    parent_subs = collections.defaultdict(set)
    parent_hosts = collections.defaultdict(set)
    host_ext = collections.defaultdict(set)
    qn_host = collections.defaultdict(set)
    n = 0; tmin = "z"; tmax = ""

    for path in files:
        with opener(path) as fh:
            for line in fh:
                if '"eventID"' not in line: continue          # cheap, spacing-agnostic prefilter
                try: o = json.loads(line)
                except Exception: continue
                win = ((o.get("data") or {}).get("win")) or {}
                if str((win.get("system") or {}).get("eventID")) != "22": continue
                ed = (win.get("eventdata")) or {}
                qn = ed.get("queryName")
                if not qn: continue
                n += 1
                host = ((o.get("agent") or {}).get("name")) or "?"
                ts = o.get("timestamp") or ""
                if ts:
                    tmin = min(tmin, ts); tmax = max(tmax, ts)
                d = qn.rstrip(".").lower()
                if d in mal: cat["denylist"][d] += 1; qn_host[("denylist", d)].add(host)
                if TLD.search(d) and not (OWN and OWN.search(d)): cat["tld"][d] += 1; qn_host[("tld", d)].add(host)
                if DDNS.search(d): cat["ddns"][d] += 1; qn_host[("ddns", d)].add(host)
                if TUN.search(d): cat["tunnel"][d] += 1; qn_host[("tunnel", d)].add(host)
                if not is_good(d):
                    labels = d.split(".")
                    parent = ".".join(labels[-2:]) if len(labels) >= 2 else d
                    parent_subs[parent].add(d); parent_hosts[parent].add(host)
                    host_ext[host].add(parent)

    manysubs = [(p, len(s)) for p, s in parent_subs.items() if len(s) >= MANYSUBS]
    manysubs.sort(key=lambda x: -x[1])
    actionable = sum(len(cat[k]) for k in ("denylist", "ddns", "tunnel"))

    os.makedirs(OUTDIR, exist_ok=True)
    stamp = (tmax[:10] if tmax else datetime.date.today().isoformat())
    report = os.path.join(OUTDIR, "dns_sweep_%s.txt" % stamp)
    lines = []
    lines.append("DNS anomaly sweep")
    lines.append("files: %s" % ", ".join(files))
    lines.append("queries scanned: %d   span: %s .. %s" % (n, tmin, tmax))
    lines.append("SUMMARY  denylist=%d  dynamic-dns=%d  tunneling-label=%d  sus-tld=%d  many-subdomain-parents=%d"
                 % (len(cat["denylist"]), len(cat["ddns"]), len(cat["tunnel"]), len(cat["tld"]), len(manysubs)))
    for k, label in (("denylist", "KNOWN-MALICIOUS (denylist)"), ("ddns", "DYNAMIC-DNS / TUNNELING SERVICE"),
                     ("tunnel", "LONG-LABEL (possible tunneling)"), ("tld", "SUSPICIOUS TLD")):
        if cat[k]:
            lines.append("\n[%s] %d distinct" % (label, len(cat[k])))
            for dom, c in cat[k].most_common(40):
                lines.append("  %6d  %-55s hosts=%s" % (c, dom[:55], ",".join(sorted(qn_host[(k, dom)])[:4])))
    if manysubs:
        lines.append("\n[MANY-SUBDOMAIN PARENTS >= %d distinct]  (DNS-tunneling / data-exfil candidate)" % MANYSUBS)
        for p, cnt in manysubs[:25]:
            lines.append("  %5d subs  %-40s hosts=%s" % (cnt, p, ",".join(sorted(parent_hosts[p])[:4])))
    body = "\n".join(lines)
    with open(report, "w") as f:
        f.write(body + "\n")
    print(body)
    print("\nreport written: %s" % report)
    print("RESULT:", "ACTIONABLE" if actionable else "clean")
    return 2 if actionable else 0

if __name__ == "__main__":
    sys.exit(main())
