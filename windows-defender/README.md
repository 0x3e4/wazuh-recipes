# Windows Defender → Wazuh

Bring **Microsoft Defender Antivirus** detections, remediation, tamper and health events into
Wazuh 4.x. Relevant to
[T1588.001 (Malware)](https://attack.mitre.org/techniques/T1588/001/) and, for defense
tampering, [T1562.001 (Impair Defenses: Disable or Modify Tools)](https://attack.mitre.org/techniques/T1562/001/).

Defender logs to its own eventchannel, **`Microsoft-Windows-Windows Defender/Operational`**,
which Wazuh does **not** collect by default. This recipe turns that collection on for your
`windows` agent group and adds high-value detection/tamper rules on top of Wazuh's stock
Defender coverage.

## What you get

- **One `<localfile>`** enabling the Defender Operational eventchannel on the `windows` group.
- Once collected, Wazuh's base rule **60005** matches the channel and the **stock** rules fire
  (62100–62111 scan lifecycle + severity; 83001–83002 PUA detection/action).
- **Augmentation rules** (`100900–100929`) for the events stock coverage is thin on:
  malware detected (with threat name), action failed / critical failure, suspicious behavior,
  **real-time-protection disabled**, **scanning disabled**, **exclusion/setting changed**
  (tamper), signature/engine update failure, quarantine-restore / history-deletion, and a
  malware **outbreak** correlation — with MITRE + PCI/GDPR/NIST/HIPAA/TSC tags.
- **A dashboard** — detections, top threats, tamper, health, and top hosts.

## How it works

```
Windows endpoint (Defender)                         Wazuh
Microsoft-Windows-Windows Defender/Operational ──►  agent (windows group, eventchannel)
                                                     └► manager: 60005 (channel base)
                                                            ├► stock 62100–62111 / 83001–83002
                                                            └► recipe 100900–100929 (detect + tamper + outbreak)
                                                                   └► wazuh-alerts-* → dashboard
```

## Repository layout

```
agent/agent.conf.snippet              # <localfile eventchannel> for the windows group
ruleset/rules/windows_defender_rules.xml   # augmentation rules 100900-100929
bin/av_alert_digest.py                # notify-once HTML email digest (Defender + ClamAV)
systemd/windows-defender-mail.{service,timer,env.example}   # email digest timer
dashboard/build_dashboard.py + windows-defender.ndjson
samples/sample-events.jsonl           # illustrative eventchannel events
```

## Requirements

- Wazuh 4.x manager + a Windows agent (in the `windows` group) with Microsoft Defender AV.
- No `logcollector.remote_commands` change (eventchannel source, not a command).

## Installation

1. **Agent (windows group).** On the manager, add the `<localfile>` from
   `agent/agent.conf.snippet` inside `<agent_config>` in
   `/var/ossec/etc/shared/windows/agent.conf`. Agents pick it up on the next pull (or run
   `sudo /var/ossec/bin/agent_groups`), then the Defender channel starts flowing.
2. **Rules (manager).**
   ```bash
   sudo install -o root -g wazuh -m 0640 ruleset/rules/windows_defender_rules.xml /var/ossec/etc/rules/
   sudo systemctl restart wazuh-manager
   ```
3. **Dashboard.** Import `dashboard/windows-defender.ndjson` via **Dashboards Management →
   Saved Objects → Import** (targets the `wazuh-alerts-*` index pattern). After the first
   Defender alerts, **refresh the index pattern** so `data.win.eventdata.*` fields resolve.

## Verifying

```bash
/var/ossec/bin/wazuh-logtest        # paste a line from samples/sample-events.jsonl
grep -hE '"id":"(1009|62)[0-9]{2,3}"' /var/ossec/logs/alerts/alerts.json | tail
```
Trigger a real detection with the EICAR test file on an endpoint and confirm a `100901`
(malware detected) alert in `wazuh-alerts-*`. Disabling real-time protection should raise
`100906`.

## Email notifications (HTML digest)

Detections are mailed by **`bin/av_alert_digest.py`** — a notify-once HTML digest that reads
the Indexer and sends one ticket per new detection, exactly like the `vuln-email-digest` /
`win-security-email` recipes (stdlib + `opensearch-py`, SQLite dedup with a `seeded_at`
marker, `--seed`/`--dry-run`/`--test`, systemd timer). It is **not** Wazuh's native
`alert_by_email`. The same script serves both recipes via `--source defender|clamav|both`.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-recipes 2>/dev/null
sudo install -d -o wazuh-recipes -g wazuh-recipes /opt/antivirus-mail
sudo -u wazuh-recipes python3 -m venv /opt/antivirus-mail/venv
sudo -u wazuh-recipes /opt/antivirus-mail/venv/bin/pip install opensearch-py
sudo install -o wazuh-recipes -g wazuh-recipes -m 0750 bin/av_alert_digest.py /opt/antivirus-mail/
sudo cp systemd/windows-defender-mail.env.example /opt/antivirus-mail/antivirus-mail.env
sudoedit /opt/antivirus-mail/antivirus-mail.env      # set INDEX_PASSWORD, RECIPIENTS, SMTP_SERVER
sudo chown wazuh-recipes:wazuh-recipes /opt/antivirus-mail/antivirus-mail.env && sudo chmod 600 /opt/antivirus-mail/antivirus-mail.env
# baseline (no mail), then enable the timer:
sudo -u wazuh-recipes /opt/antivirus-mail/venv/bin/python /opt/antivirus-mail/av_alert_digest.py --seed --source defender --state-db /opt/antivirus-mail/defender-state.db
sudo cp systemd/windows-defender-mail.{service,timer} /etc/systemd/system/
sudo systemctl enable --now windows-defender-mail.timer
```
`--test --recipients you@example.com` sends one sample from the newest detection. One instance
with `--source both` covers Defender **and** ClamAV; or run per-recipe timers.

## Troubleshooting

- **A host is subscribed to the channel but sends no Defender events** (while other channels /
  other agents work): a **stale eventchannel bookmark**. On that agent: stop the Wazuh service,
  delete `C:\Program Files (x86)\ossec-agent\queue\logcollector\file_status.json`, start the
  service. Eventchannel is forward-only, so detections from before the fix are not back-filled.
- **Threat name shows blank / `()`**: Defender's structured eventdata uses field names **with a
  space** — the threat name is `win.eventdata.threat Name` (not `threatName`) and severity is
  `win.eventdata.severity Name`. This recipe's rules/dashboard use the spaced names; verify with
  `wazuh-logtest` on a real event if your build differs.

## Notes / limitations

- **Detection is handled by Wazuh's stock rules** (`0600`: 62113/62122/62123 …). This recipe
  *enriches* those (threat name + MITRE + email via a superseding child, rule 100901) and adds
  the **tamper** events stock omits (5001 RTP-disabled, 5010/5012 scanning-disabled, 5007
  setting/exclusion changed) plus an outbreak correlation.
- Event `5007` fires for *any* setting change (including legitimate ones); it's level 8 as a
  review signal, not a definitive tamper.
- Defender for Endpoint (EDR) events use a different channel
  (`Microsoft-Windows-SENSE/Operational`); this recipe targets **Defender Antivirus**.

## License

MIT (inherits the repository [LICENSE](../LICENSE)).
