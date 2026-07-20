# ClamAV → Wazuh (Ubuntu / Debian)

Bring **ClamAV** malware detections, scan errors and signature-update health into Wazuh 4.x
for your `ubuntu` and `debian` agent groups. Relevant to
[T1588.001 (Malware)](https://attack.mitre.org/techniques/T1588/001/).

Wazuh ships `clamd`/`freshclam` decoders + rules (52500–52509), but they key on
**`program_name`** — i.e. ClamAV logging via **syslog**. On Debian/Ubuntu, ClamAV writes to
**files** (`/var/log/clamav/clamav.log`, `freshclam.log`) with no syslog program tag, so the
stock decoder doesn't match a file read. This recipe ships a **log-file decoder** + rules so
detections flow whether or not you use syslog.

## What you get

- **`<localfile>`** blocks for `/var/log/clamav/clamav.log` + `freshclam.log` (ubuntu + debian).
- **A file-log decoder** (`clamav-file`) extracting `data.clamav.signature` / `data.clamav.path`.
- **Rules `100930–100959`**: malware detected, **outbreak** correlation, scan/daemon error,
  **signature-update failed** (stale protection), and update-OK — with MITRE + PCI/GDPR/NIST/
  HIPAA/TSC tags.
- **A dashboard** — detections, top signatures, outbreaks, per-host, errors, update health.

## How it works

```
Ubuntu/Debian host (ClamAV)                       Wazuh
/var/log/clamav/clamav.log     ── agent ──►  manager: clamav-file decoder
/var/log/clamav/freshclam.log     (ubuntu/       └► rules 100930–100959 (detect/outbreak/update)
                                    debian)          └► wazuh-alerts-* → dashboard
```

Prefer syslog? Set `LogSyslog yes` in `clamd.conf` (and clamonacc) and Wazuh's **stock** clamd
rules (52500–52509) fire from your existing syslog collection — this recipe still complements
them (outbreak + update-health rules, dashboard).

## Repository layout

```
agent/agent.conf.snippet                    # <localfile> for the ubuntu + debian groups
ruleset/decoders/clamav_logfile_decoders.xml # clamav-file decoder (log-file format)
ruleset/rules/clamav_rules.xml               # rules 100930-100959
active-response/bin/clamav-quarantine.sh     # AR: quarantine the infected file on detection
ossec/clamav-active-response.snippet.xml     # <command> + <active-response> for ossec.conf
bin/av_alert_digest.py                       # notify-once HTML email digest (ClamAV + Defender)
systemd/clamav-mail.{service,timer,env.example}   # email digest timer
dashboard/build_dashboard.py + clamav.ndjson
samples/sample-events.log                    # sample clamav.log / freshclam.log lines
```

## Requirements

- Wazuh 4.x manager + Linux agents (in `ubuntu` / `debian` groups) with ClamAV installed
  (`clamav`, `clamav-daemon`, `clamav-freshclam`).
- For **real-time** detection, enable the on-access scanner `clamonacc` (part of
  `clamav-daemon`); otherwise detections come only from scheduled/manual `clamscan`.

## Installation

1. **Agent (ubuntu + debian groups).** On the manager, add the `<localfile>` blocks from
   `agent/agent.conf.snippet` inside `<agent_config>` in **both**
   `/var/ossec/etc/shared/ubuntu/agent.conf` and `/var/ossec/etc/shared/debian/agent.conf`.
2. **Decoder + rules (manager).**
   ```bash
   sudo install -o root -g wazuh -m 0640 ruleset/decoders/clamav_logfile_decoders.xml /var/ossec/etc/decoders/
   sudo install -o root -g wazuh -m 0640 ruleset/rules/clamav_rules.xml /var/ossec/etc/rules/
   sudo systemctl restart wazuh-manager
   ```
3. **Dashboard.** Import `dashboard/clamav.ndjson` (Saved Objects → Import). After the first
   detections, **refresh the `wazuh-alerts-*` index pattern** so `data.clamav.*` fields resolve.

## Auto-quarantine (optional, Active Response)

ClamAV only *detects* by default (unlike Defender, which auto-quarantines) — that's why an
EICAR file stays on disk. Wazuh Active Response closes the gap: on detection (rule `100931`)
it runs a script on the endpoint that **moves** the infected file to `/var/ossec/quarantine`
(mode 000 — reversible, not deleted) and refuses to touch system directories.

```bash
# on EACH ubuntu/debian agent:
sudo install -o root -g wazuh -m 0750 active-response/bin/clamav-quarantine.sh /var/ossec/active-response/bin/
```
Then add `ossec/clamav-active-response.snippet.xml` to the manager's `ossec.conf` and restart.
Pilot on a test host first, and scope `<rules_id>`/`<location>` if you only want it on some
hosts. (Native alternative: clamd on-access `OnAccessPrevention yes`, or `clamdscan --move`.)

## Email notifications (HTML digest)

Detections are mailed by **`bin/av_alert_digest.py`** — a notify-once HTML digest that reads
the Indexer and emails one ticket per new detection (stdlib + `opensearch-py`, SQLite dedup
with a `seeded_at` marker, `--seed`/`--dry-run`/`--test`, systemd timer) — the same pattern as
`vuln-email-digest`. It is **not** Wazuh native `alert_by_email`. The identical script ships in
both AV recipes; scope it with `--source clamav|defender|both`.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-recipes 2>/dev/null
sudo install -d -o wazuh-recipes -g wazuh-recipes /opt/antivirus-mail
sudo -u wazuh-recipes python3 -m venv /opt/antivirus-mail/venv
sudo -u wazuh-recipes /opt/antivirus-mail/venv/bin/pip install opensearch-py
sudo install -o wazuh-recipes -g wazuh-recipes -m 0750 bin/av_alert_digest.py /opt/antivirus-mail/
sudo cp systemd/clamav-mail.env.example /opt/antivirus-mail/antivirus-mail.env
sudoedit /opt/antivirus-mail/antivirus-mail.env      # set INDEX_PASSWORD, RECIPIENTS, SMTP_SERVER
sudo chown wazuh-recipes:wazuh-recipes /opt/antivirus-mail/antivirus-mail.env && sudo chmod 600 /opt/antivirus-mail/antivirus-mail.env
sudo -u wazuh-recipes /opt/antivirus-mail/venv/bin/python /opt/antivirus-mail/av_alert_digest.py --seed --source clamav --state-db /opt/antivirus-mail/clamav-state.db
sudo cp systemd/clamav-mail.{service,timer} /etc/systemd/system/
sudo systemctl enable --now clamav-mail.timer
```
One instance with `--source both` covers ClamAV **and** Windows Defender; or run per-recipe timers.

## Verifying

```bash
/var/ossec/bin/wazuh-logtest        # paste a line from samples/sample-events.log -> expect 100930 -> 100931
# On an agent: create the EICAR test file and scan it
curl -s https://secure.eicar.org/eicar.com.txt -o /tmp/eicar.com && clamdscan /tmp/eicar.com
grep -hE '"id":"1009(3[0-9])"' /var/ossec/logs/alerts/alerts.json | tail
```

## Notes / limitations

- **Fields are normalized to `data.clamav.signature` / `data.clamav.path`** for both
  collection modes. The file decoder sets them directly; for **syslog** delivery, Wazuh's
  stock `clamd` decoder matches but its legacy `clamd-found` extractor only understands the
  old `Signature(md5:offset)` format — modern ClamAV output (`path: Signature FOUND`, e.g.
  `Eicar-Test-Signature`) decodes with **no fields**. This recipe adds a `clamd` child decoder
  that parses the modern format into the same `data.clamav.*` fields, so the dashboard's
  signature panels work whether ClamAV logs to syslog (stock rule 52502) or to the file
  (recipe rule 100931).
- The path capture assumes the `<path>: <signature> FOUND` format; a path containing `: ` is
  captured greedily to the last delimiter. Validate with `wazuh-logtest` if your paths are
  unusual.
- On-access (`clamonacc`) is what gives real-time coverage; scheduled `clamscan` alerts only
  when it runs.

## License

MIT (inherits the repository [LICENSE](../LICENSE)).
