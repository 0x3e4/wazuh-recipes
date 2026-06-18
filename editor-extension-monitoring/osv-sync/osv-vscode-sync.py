#!/usr/bin/env python3
"""
osv-vscode-sync.py — generate version-aware Wazuh rules from the OSV VSCode malware feed.

Pulls https://osv.dev VSCode ecosystem (all.zip), and writes one rule per OSV record that
matches the malicious extension_id AND only its OSV-listed affected version(s). This avoids
false positives on legitimate versions of compromised-but-legit extensions
(e.g. nrwl.angular-console is malicious only at v18.95.0; 18.101.x is fine).

Rules are children of 102010 (the editor-extensions inventory base rule), IDs from 102100.
Run from cron on the manager, then reload:  /var/ossec/bin/wazuh-control reload

Usage: osv-vscode-sync.py [output.xml]   (default: /var/ossec/etc/rules/editor_extensions_osv.xml)
"""
import urllib.request, zipfile, io, json, re, sys

URL = "https://osv-vulnerabilities.storage.googleapis.com/VSCode/all.zip"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/var/ossec/etc/rules/editor_extensions_osv.xml"
START_ID = 102100

def xml_text(s):  # escape XML-special chars in element text
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def rx_lit(s):    # escape pcre2 metacharacters (publisher.name and versions are literals)
    return re.sub(r'([.\\+*?()\[\]{}|^$])', r'\\\1', s)

data = urllib.request.urlopen(URL, timeout=30).read()
z = zipfile.ZipFile(io.BytesIO(data))

records = []
for n in z.namelist():
    if not n.endswith(".json"):
        continue
    d = json.loads(z.read(n))
    oid = d.get("id", "")
    summ = (d.get("summary") or d.get("details") or "").replace("\n", " ").strip()
    for a in d.get("affected", []):
        name = a.get("package", {}).get("name", "")
        if not name:
            continue
        versions = sorted(set(a.get("versions") or []))
        records.append((oid, name, versions, summ))

# dedupe identical (name, versions) — OSV lists the same id for both VSCode and OpenVSX
seen, uniq = set(), []
for r in records:
    k = (r[1].lower(), tuple(r[2]))
    if k not in seen:
        seen.add(k); uniq.append(r)
uniq.sort(key=lambda x: x[1].lower())

out = []
out.append("<!-- AUTO-GENERATED from OSV (osv.dev VSCode ecosystem) by osv-vscode-sync.py. DO NOT EDIT BY HAND. -->")
out.append("<!-- Version-aware: only OSV-listed affected versions match, so legit versions of compromised -->")
out.append("<!-- extensions (e.g. nrwl.angular-console 18.101.x) are NOT flagged. Children of rule 102010. -->")
out.append('<group name="editor_extensions,editor_extension_inventory,osv,">')
rid = START_ID
for oid, name, versions, summ in uniq:
    out.append(f'  <rule id="{rid}" level="12">')
    out.append('    <if_sid>102010</if_sid>')
    out.append(f'    <field name="extension_id" type="pcre2">(?i)^{xml_text(rx_lit(name))}$</field>')
    if versions:
        vrx = "^(" + "|".join(rx_lit(v) for v in versions) + ")$"
        out.append(f'    <field name="version" type="pcre2">{xml_text(vrx)}</field>')
        vnote = " v$(version)"
    else:
        vnote = " (all versions)"
    out.append(f'    <description>{xml_text(oid)}: malicious/compromised editor extension {xml_text(name)}{vnote} [$(editor)] user $(dstuser).</description>')
    out.append('    <mitre><id>T1176</id><id>T1195.002</id></mitre>')
    out.append('    <group>editor_extension_malicious,</group>')
    out.append('  </rule>')
    rid += 1
out.append("</group>")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")

vspec = sum(1 for _, _, v, _ in uniq if v)
print(f"wrote {rid - START_ID} OSV rules ({vspec} version-specific) -> {OUT}")
