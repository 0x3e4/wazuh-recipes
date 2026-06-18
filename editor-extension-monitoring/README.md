# VS Code & Visual Studio Extension Monitoring

Inventory the VS Code and Visual Studio extensions installed across your Windows fleet, and get
alerted when a banned or known-malicious extension appears — with an automated, **version-aware**
malware feed sourced from [OSV.dev](https://osv.dev).

Editor extensions execute with the developer's privileges and update silently, which makes them an
attractive and under-watched supply-chain target (MITRE **T1176**, **T1195.002**). Wazuh's built-in
Syscollector inventories installed *programs* and *browser* extensions, but not the extensions inside
VS Code or Visual Studio — those live as files in the user profile and are invisible to ordinary
software inventory. This recipe closes that gap using only native Wazuh primitives: File Integrity
Monitoring, a small PowerShell collector, custom decoders and rules, and a denylist that can refresh
itself.

## What you get

- **Real-time detection** of extension installs, changes and removals via FIM.
- **A structured inventory** — publisher, name, version and user for every installed extension — queryable in the dashboard.
- **Malware / typosquat detection** against a curated denylist *and* an automated OSV feed.
- **Version-aware matching**: a compromised release of an otherwise-legitimate extension (e.g. one bad version of a popular Angular tool) is flagged without false-positiving every legitimate install.
- **A prebuilt dashboard**, importable in one step.

## How it works

Two complementary sources feed a small set of custom rules on the manager:

```
 Windows agent (runs as SYSTEM)
 ├─ syscheck ── realtime ─────────────▶ FIM events ─▶ rules 102000–102003   (install/change/delete)
 └─ Get-EditorExtensions.ps1 (daily) ─▶ JSON ─▶ command localfile
                                              │
       editor-extensions decoder (JSON_Decoder) ─▶ rules 102010–102012 + OSV rules 102100+
                                              │
                                      wazuh-alerts-* ─▶ dashboard
```

FIM is kept deliberately narrow: it watches only each extension's *manifest* file, so a workstation
with hundreds of extensions contributes a handful of entries instead of tens of thousands. The
collector walks every user profile, parses each manifest, and emits one compact JSON object per
extension; a command localfile ships that to the manager, where a JSON decoder turns it into fields
that rules and the dashboard can use.

Because VS Code extension folders are named `publisher.name-version`, FIM alone already identifies them
from the path. Visual Studio uses hash-named folders, so the collector is what resolves their real
identity from the VSIX manifest.

## Repository layout

```
agent/
  agent.conf                         # <agent_config> block for your dev group
  Get-EditorExtensions.ps1           # SYSTEM collector (VS Code + Visual Studio)
ruleset/
  decoders/editor_extensions_decoders.xml
  rules/editor_extensions_rules.xml  # FIM rules + inventory rules + curated denylist
  rules/editor_extensions_osv.xml    # version-aware rules (auto-generated from OSV; sample included)
osv-sync/
  osv-vscode-sync.py                 # OSV feed -> version-aware ruleset generator
  osv-vscode-sync.sh                 # cron wrapper (validate -> restart-on-change -> rollback)
dashboard/
  editor-extensions-dashboard.ndjson # importable dashboard (5 panels)
```

## Requirements

- Wazuh manager **4.x** and Windows agents.
- The collector runs as SYSTEM and uses PowerShell 5.1+ (built into Windows).
- For the inventory command to run from shared config, each agent needs
  `logcollector.remote_commands=1` in `local_internal_options.conf` (push it with your endpoint
  management — it cannot be set from shared config by design).
- For the OSV auto-sync (optional): outbound HTTPS from the manager to `storage.googleapis.com`, plus a root cron.

## Installation

### 1. Ruleset (manager)

```bash
cp ruleset/decoders/editor_extensions_decoders.xml /var/ossec/etc/decoders/
cp ruleset/rules/editor_extensions_rules.xml       /var/ossec/etc/rules/
cp ruleset/rules/editor_extensions_osv.xml         /var/ossec/etc/rules/   # optional; the sync can generate it
chown root:wazuh /var/ossec/etc/decoders/editor_extensions_decoders.xml /var/ossec/etc/rules/editor_extensions_*.xml
chmod 0640       /var/ossec/etc/decoders/editor_extensions_decoders.xml /var/ossec/etc/rules/editor_extensions_*.xml
systemctl restart wazuh-manager     # rules are not hot-reloaded; a restart is required
```

### 2. Agent configuration + collector

Add the `<agent_config>` block from [`agent/agent.conf`](agent/agent.conf) to the shared `agent.conf`
of the group that holds your developer workstations, and drop the collector into the same folder so
Wazuh distributes it:

```bash
cp agent/Get-EditorExtensions.ps1 /var/ossec/etc/shared/<group>/
chown root:wazuh /var/ossec/etc/shared/<group>/Get-EditorExtensions.ps1
```

Then enable `logcollector.remote_commands=1` on the target agents (GPO/SCCM/etc.) and restart the
agent service.

### 3. OSV auto-sync (recommended)

```bash
install -d /opt/wazuh-osv
install -m 0755 osv-sync/osv-vscode-sync.py /opt/wazuh-osv/
install -m 0750 osv-sync/osv-vscode-sync.sh /opt/wazuh-osv/
# root crontab — OSV changes rarely, weekly is plenty:
(crontab -l 2>/dev/null; echo '30 3 * * 1 /opt/wazuh-osv/osv-vscode-sync.sh >> /var/log/osv-vscode-sync.log 2>&1') | crontab -
```

The wrapper fetches OSV, validates the generated XML, restarts the manager **only if the ruleset
changed**, and rolls back if the manager fails to come up.

### 4. Dashboard

Import [`dashboard/editor-extensions-dashboard.ndjson`](dashboard/editor-extensions-dashboard.ndjson)
via **Dashboards Management → Saved Objects → Import**. First refresh the `wazuh-alerts-*` index
pattern field list so the new `data.*` fields are aggregatable. If a panel can't locate the index
pattern, remap it in the import dialog (your saved-object ID may differ from the default).

## Rules and fields

| Rule ID  | Level | Source            | Fires when |
|----------|:-----:|-------------------|------------|
| `102000` |   5   | FIM (`if_sid 554`)| File added under an extensions directory |
| `102001` |  12   | FIM child         | Added path matches a banned extension |
| `102002` |   5   | FIM (`if_sid 553`)| Extension content removed |
| `102003` |   3   | FIM (`if_sid 550`)| Extension content modified |
| `102010` |   0   | Inventory base    | Any inventory event (no alert) |
| `102011` |   3   | Inventory child   | One record per installed extension |
| `102012` |  12   | Inventory child   | `extension_id` matches the curated denylist |
| `102100+`|  12   | OSV (generated)   | `extension_id` **and** version match an OSV malware record |

The decoder flattens the JSON to event-root fields: `integration`, `editor`, `extension_id`,
`extension_name`, `publisher`, `version`, `display_name`, `path`, `host`. Note that Wazuh's JSON
decoder remaps the key `user` to the built-in field **`dstuser`** — reference it as `$(dstuser)` in
rules. Match `data.*` fields at the root in rule conditions; they appear under `data.*` in the indexer.

## Keeping the denylist current

There are two layers, both alerting at level 12:

**Curated list** (`editor_extensions_rules.xml`, rules `102001`/`102012`) — an exact, anchored list of
`publisher.name` IDs seeded from public advisories. Anchoring matters: the entries are typosquats and
must not match the legitimate originals they impersonate (e.g. malicious `juan-blanco.solidity` versus
the genuine `JuanBlanco.solidity`). Add an IOC by extending the alternation and restarting the manager.

**OSV feed** (`editor_extensions_osv.xml`, rules `102100+`) — generated from the OSV VSCode ecosystem
and **version-aware**. Several OSV entries are compromised *versions* of legitimate extensions, so the
generator matches both the ID and the affected version(s). Legitimate versions are never flagged. Wire
up `osv-sync/` (step 3) to keep this fresh automatically.

## Verifying

Validate the decoder and rules offline — no live data required:

```bash
/var/ossec/bin/wazuh-logtest -v
# paste, e.g.:
# Jun 18 12:00:00 HOST editor-extensions: ossec: output: 'editor-extensions': {"integration":"editor-extensions","editor":"vscode","user":"jdoe","extension_id":"ahban.shiba","version":"1.0.0","path":"..."}
```

Watch alerts directly in `alerts.json` (no indexer credentials needed):

```bash
grep -hE '"id":"102011"' /var/ossec/logs/alerts/alerts.json \
  | jq -c '{agent:.agent.name,ext:.data.extension_name,ver:.data.version,user:.data.dstuser,editor:.data.editor}'
grep -hE '"id":"(10200[12]|102012|1021[0-9][0-9])"' /var/ossec/logs/alerts/alerts.json   # malicious hits
```

The *current* inventory (extensions present before deployment are baselined silently) lives in
**Integrity Monitoring → Files**, not in the alert stream.

## Operational notes

- **FIM file limit.** Monitoring a directory full of `node_modules` will exhaust the default 100k
  `file_limit` and cause event loss. The provided config avoids this with `restrict` (manifests only)
  and a global `<ignore>node_modules</ignore>`.
- **Rule changes require a manager restart** — Wazuh 4.x does not hot-reload rules. Agent config changes
  push automatically.
- **Field remap:** `user` → `dstuser` (see above).
- **Inventory re-sends** the full set each run; deduplicate in the dashboard by `agent.name` +
  `data.extension_id`, and keep `102011` at a low level.
- **Upgrade-safe:** custom files live under `etc/rules`, `etc/decoders`, `etc/lists`. Never place
  custom content under `ruleset/`, which upgrades overwrite.

## Limitations

- Visual Studio extension identity comes only from the collector (hash-named folders); FIM alone cannot
  name them.
- Extensions inside WSL distros or dev containers are invisible to the host agent.
- The curated denylist matches by ID/path only; version-aware matching comes from the OSV ruleset.
