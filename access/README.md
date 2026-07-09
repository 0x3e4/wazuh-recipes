# Account Access & Activity (RDP/SSH → what the account did)

One importable dashboard that shows **which accounts connect to your servers over RDP/SSH, from
where, and what they did once in** — reading the reliable **`wazuh-alerts-*`** index (level ≥3),
with a small ruleset that raises the access events to level 3 so you never have to depend on the
raw archive.
(MITRE ATT&CK: [T1021 Remote Services](https://attack.mitre.org/techniques/T1021/),
[T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/).)

## What you get

- **A combined dashboard** with two sections:
  - **Logins** — metrics (RDP / SSH / failed / distinct accounts), a logon timeline, tables for
    **RDP logons** and **SSH logons** (`account × server × source IP`), **failed logons**
    (Windows + SSH/PAM), a **logons-per-server bar** and a **logon auth-method donut**
    (Kerberos vs NTLM — an NTLM/pass-the-hash signal). Machine accounts (`…$`) are excluded and
    failed logons are scoped to real named accounts to cut false positives.
  - **Post-logon activity** — metrics + timeline, top users / processes, PowerShell scripts,
    **Linux sudo commands**, and two bottom "session activity" tables: **Windows** (Sysmon Event 1,
    full command lines) and **Linux** (SSH logins + sudo).
- **Session drill-down:** Sysmon Event 1's `logonId` equals Security 4624's `targetLogonId`, so you
  can filter the Windows session table to one RDP session and see exactly the processes run in it.
- **A ruleset** (`rules/`) that raises the archive-only access events to level ≥3 so the whole
  dashboard works on `wazuh-alerts-*`.

## How it works

Everything is stock Wazuh log data (no custom decoders). The dashboard reads **`wazuh-alerts-*`**
(level ≥3 only). Logins and Linux commands already alert; the Windows process feed is elevated by
this recipe's rules:

| Signal | Filter | In `wazuh-alerts-*`? | Key fields |
|--------|--------|----------------------|-----------|
| RDP logon | `data.win.system.eventID:4624 and data.win.eventdata.logonType:10` | yes (rule 92653) | `targetUserName`, `ipAddress`, `agent.name`, `targetLogonId` |
| SSH logon | `rule.id:5715` | yes | `data.dstuser`, `data.srcip`, `agent.name` |
| Failed logon | Windows `4625` (real user, non-`$`, non-service) · SSH/PAM `5716`/`5503` | yes | `targetUserName`/`dstuser`, `ipAddress`/`srcip` |
| RDP session | TerminalServices `1149` / `21`–`25` | **only with Tier 1 rules** | `param1`/`user`, `param3`/`address`, `sessionID` |
| Windows activity | `data.win.system.eventID:1` (Sysmon ProcessCreate) | **only with Tier 3 rules** | `user`, `commandLine`, `image`, `logonId`, `parentImage` |
| PowerShell | `data.win.system.eventID:4104` | **only with Tier 3 rules** | `path`, `scriptBlockText` |
| Linux command | `rule.id:5402 or rule.id:5407` (sudo) | yes | `data.srcuser`, `data.command`, `agent.name` |

## Repository layout

```
access/
  dashboard/access-activity.ndjson   # import this (reads wazuh-alerts-*)
  rules/access_level3_rules.xml       # raise access events to level >=3
```

## Requirements

- Wazuh 4.x manager + agents. Windows agents forwarding **Security**, **Sysmon/Operational** and the
  two **TerminalServices** channels (RDP); Linux agents with sshd/PAM/sudo logging.
- No archive dependency — the dashboard reads `wazuh-alerts-*`. (You *can* point it at
  `wazuh-archives-*` for debugging via `INDEX_PATTERN`, but that's optional.)

## Installation

1. **Rules.** Copy `rules/access_level3_rules.xml` to `etc/rules/` (`chown root:wazuh`,
   `chmod 0640`), then restart the manager.
   - **Tier 1/2** (RDP session lifecycle + interactive logoff) are **active** — low volume.
   - **Tier 3** (all Sysmon Event 1 + PowerShell → level 3) is **commented out**. Uncomment it to
     populate the Windows *activity* panels on `wazuh-alerts-*` — but note it pushes the whole
     process-creation firehose (~0.75M Event 1/day + ~0.85M 4104/day in a mid-size estate) into the
     alerts index, so size your indexer accordingly. Left off, the activity panels show only
     already-flagged events.
2. **Dashboard.** Dashboards Management → Saved Objects → **Import** →
   `dashboard/access-activity.ndjson`. It references `wazuh-alerts-*` by name (id == title), so there
   is **no index-pattern conflict to resolve**.

## Usage

Open **"Account Access & Activity"** and set a time range. Click any account/host row to filter the
Windows panels. To inspect one RDP session: copy `targetLogonId` from an RDP logon, then in
**Windows session activity** filter `data.win.eventdata.logonId : "<luid>"` **and**
`agent.name : "<server>"` (scope to the host + the session's time window; LUIDs repeat across reboots).

## Configuration

- The dashboard reads `wazuh-alerts-*` by name (id == title), so it imports with no remap. To target
  a different index pattern (e.g. `wazuh-archives-*` for a debug build on the raw archive), change the
  `index-pattern` id in the `references` of the objects in `access-activity.ndjson`.
- Failed-logon panels exclude `…$` machine accounts, empty/unknown users and service logonType 5;
  broaden/narrow the `4625` query in the ndjson to taste.

## Verifying

```bash
python3 -c "import json;[json.loads(l) for l in open('dashboard/access-activity.ndjson') if l.strip()]"
/var/ossec/bin/wazuh-logtest -v     # paste an RDP 1149 / LSM 21 event -> expect rule 100730/100731
```

## Limitations

- **Linux command visibility is `sudo` only** — no execve/auditd feed, so interactive shell commands
  on Linux are not captured.
- **Windows 4688 has no command line** (auditing off) and **PowerShell 4104 has no user field** — the
  activity view relies on **Sysmon Event 1** (user + command line + logonId), which requires Sysmon
  on the endpoint and Tier 3 to reach `wazuh-alerts-*`.
- The `logonId` session join is per-host and per-boot; always scope by host + time window.

## License

MIT (inherits the repository [LICENSE](../LICENSE)).
