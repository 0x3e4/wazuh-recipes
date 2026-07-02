# Suspicious PowerShell / LOLBins

A dashboard plus a weekly email summary for Wazuh's suspicious-**PowerShell** and
**living-off-the-land-binary** detections — UAC bypass via FodHelper, PrintNightmare, WMI-launched
Base64 commands, encoded/compressed payloads, PowerShell reaching into Explorer/RDP — so Windows
endpoints get one recurring overview instead of a stream of individual alerts.
(MITRE ATT&CK: [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/),
[T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/),
[T1548 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/).)

## What you get

- **An importable dashboard** ("Suspicious PowerShell / LOLBins") with eight panels: an **Investigate**
  notes/links panel, **metrics** for total detections / affected agents, a **severity pie**
  (`rule.level`), a **stacked timeline** by detection, and data tables for **top detections**
  (`rule.description`), **top agents** (`agent.name`/`agent.id`) and **top users**
  (`data.win.eventdata.user`) — all scoped to this recipe's rules.
- **A weekly HTML email digest** — one mail per run summarising the last *N* days: total count, a
  breakdown by detection, by agent and by user (`data.win.eventdata.user`), plus the most recent
  events with the offending command line / image. Severity-coloured header, plain-text fallback.
- **Stateless and low-noise** — the digest just queries and aggregates the indexer; there is no
  database and no per-event spam. If nothing matched in the window, it sends nothing.

## Watched rules

| Rule ID | Level | Description |
|---------|:-----:|-------------|
| `91809` | 10 | PowerShell using a Base64 decoding method |
| `91822` | 12 | PowerShell `Invoke-command` used to execute a sub-script |
| `91846` | 10 | PowerShell .NET compression (possible data extraction) |
| `92041` | 10 | Value added to a registry key has a Base64-like pattern |
| `92055` | 12 | FodHelper.exe may have been used to bypass UAC |
| `92071` | 12 | PowerShell created by WMI executed a Base64-encoded command |
| `92206` | 12 | DLL created by the print spooler (possible PrintNightmare) |
| `92212` | 14 | Suspicious file-compression activity by PowerShell |
| `92910` | 12 | Explorer process accessed by PowerShell (possible injection) |
| `92920` | 14 | RDP utility accessed by PowerShell (possible injection) |

Indexer filter used by every dashboard panel and the digest query:

```
rule.id:(91809 OR 91822 OR 91846 OR 92041 OR 92055 OR 92071 OR 92206 OR 92212 OR 92910 OR 92920)
```

These are **stock Wazuh rules** (the Sysmon / PowerShell rulesets) — there is no custom decoder or
rule to install. They depend on **Sysmon** and/or **PowerShell Script-Block logging** being collected
from your Windows endpoints (Wazuh's `windows`/`sysmon` channels). Pick the rule set that matches your
appetite for noise — see *Tuning* below.

## Tuning (read this before enabling the digest)

The rule list above is deliberately broad. In an admin-heavy environment some of these are
**frequent / false-positive-prone** (notably `91809` Base64-decode, `91822` `Invoke-command`, and
`92206` PrintNightmare can fire on routine spooler activity), while others are **rare and
high-signal** (`92910`/`92920` PowerShell touching Explorer/RDP, `92212` suspicious compression).

Because this is a **weekly aggregate** (not a per-event mail) the noisy rules are far less of a
problem than they would be for real-time alerting — but if you want a tighter summary, trim
`RULE_IDS` in `bin/powershell-lolbins_digest.py` and the matching `rule.id:(...)` query in
`dashboard/powershell-lolbins.ndjson` to just the high-signal IDs.

## How it works

```
 Windows endpoints (Sysmon + PowerShell logging)  ──▶  Wazuh agent  ──▶  Wazuh manager
        (stock rules fire: 91809/91822/91846/92041/92055/92071/92206/92212/92910/92920)
                                                   │
                                                   ▼
                                       Wazuh Indexer (wazuh-alerts-*)
                                          │                     │
                  Saved-object dashboard ◀┘                     └▶ powershell-lolbins_digest.py
                  (metric / timeline / 2 tables,                   (weekly: query → aggregate
                   filtered to the rule IDs)                        → ONE HTML email)
```

The digest is a **stateless periodic summary**, not an event forwarder. Each run sends a single
aggregation request to the indexer for the watched rule IDs over the last `RANGE_DAYS`, then renders
one email (top detections, top agents, top users, most-recent events with the command line) and sends
it. There is no dedup database, so re-running it just re-summarises the same window.

## Repository layout

```
bin/
  powershell-lolbins_digest.py             # the weekly summary (query → aggregate → email)
dashboard/
  powershell-lolbins.ndjson                # importable saved objects (4 visualizations + 1 dashboard)
systemd/
  powershell-lolbins-digest.service/.timer # weekly run (Mon 07:00), oneshot
  powershell-lolbins-digest.env.example    # secrets + overrides (copy to a 0600 env file)
```

## Requirements

- **Wazuh 4.x** manager and agents, with **Sysmon** and/or **PowerShell Script-Block logging**
  collected from Windows endpoints so the stock rules fire.
- A **Wazuh Indexer / OpenSearch** (default `https://127.0.0.1:9200`) with the alerts index
  (`wazuh-alerts-*`) and **OpenSearch Dashboards** for importing the saved objects.
- Read access from the host running the script to the indexer — ideally a **dedicated read-only
  indexer user**.
- An **SMTP** relay the host may send through.
- Python **3.8+** and [`opensearch-py`](https://pypi.org/project/opensearch-py/) (installed in a venv
  below). No other third-party dependency.

## Installation

### 1. Import the dashboard

In **OpenSearch Dashboards → Dashboards Management → Saved Objects → Import**, import
`dashboard/powershell-lolbins.ndjson`. The objects reference the existing `wazuh-alerts-*` index
pattern by name, so no index-pattern object is bundled — make sure that pattern already exists (it
does on a standard Wazuh install). Open the **"Suspicious PowerShell / LOLBins"** dashboard and pick a
time range.

### 1b. (Optional) make agent / host names clickable

The data tables include `agent.id`. To turn it into a link straight to the host's page in Wazuh, add a
**URL field-formatter** once: **Dashboards Management → Index Patterns → `wazuh-alerts-*`**, search the
`agent.id` field, **edit** it, set **Format = Url**, **Type = Link**, **URL template**
`/app/wazuh#/agents?agent={{value}}` (adjust the route to your Wazuh version if needed), then **Save**.
Every dashboard that shows `agent.id` then links to the agent. The **Investigate** panel on the
dashboard also links to Discover, the Wazuh app and the relevant MITRE techniques.

### 2. Service user, directory and venv

The script only needs to **read** the indexer and **send** mail — no root required. Run it as a
dedicated, unprivileged user; the unit files assume `wazuh-recipes`.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-recipes
sudo install -d -o wazuh-recipes -g wazuh-recipes /opt/powershell-lolbins-digest
sudo -u wazuh-recipes python3 -m venv /opt/powershell-lolbins-digest/venv
sudo -u wazuh-recipes /opt/powershell-lolbins-digest/venv/bin/pip install opensearch-py
sudo install -o wazuh-recipes -g wazuh-recipes -m 0750 \
  bin/powershell-lolbins_digest.py /opt/powershell-lolbins-digest/
```

### 3. Secrets (read-only indexer user recommended)

Create a read-only user on the indexer for this tool, then store its password in an env file readable
only by the service user (keeps it out of `ps`, the unit file and git):

```bash
sudo cp systemd/powershell-lolbins-digest.env.example /etc/powershell-lolbins-digest.env
sudoedit /etc/powershell-lolbins-digest.env          # set INDEX_PASSWORD, RECIPIENTS, SMTP_SERVER, ...
sudo chown wazuh-recipes:wazuh-recipes /etc/powershell-lolbins-digest.env
sudo chmod 600 /etc/powershell-lolbins-digest.env
```

TLS: by default the script verifies against `/etc/filebeat/certs/root-ca.pem`. If `wazuh-recipes`
can't read that path, point `CA` at a readable copy of the indexer CA, or set `NO_VERIFY=1` for a
localhost connection.

### 4. Install the timer

Edit `--recipients` (or set `RECIPIENTS` in the env file) in the `.service` file, then:

```bash
sudo cp systemd/powershell-lolbins-digest.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now powershell-lolbins-digest.timer
systemctl list-timers | grep powershell-lolbins
```

> The service is `Type=oneshot`, so `systemctl status …service` normally shows `inactive (dead)` —
> that's expected; the **timer** is what matters.

## Usage

```bash
PY=/opt/powershell-lolbins-digest/venv/bin/python
APP=/opt/powershell-lolbins-digest/powershell-lolbins_digest.py

sudo -u wazuh-recipes $PY $APP --dry-run                                # preview, send nothing
sudo -u wazuh-recipes $PY $APP --range-days 30 --dry-run                # summarise 30 days
sudo -u wazuh-recipes $PY $APP --recipients soc@example.com,you@example.com   # send now
sudo -u wazuh-recipes $PY $APP --always --recipients you@example.com    # send even with 0 alerts
```

| Option | Meaning |
|--------|---------|
| `--dry-run` | Print the rendered summary; send no email |
| `--range-days N` | Days back to summarise (env `RANGE_DAYS`; default 7) |
| `--recipients a@x,b@y` | Recipient list (or `RECIPIENTS` env / per-unit) |
| `--always` | Send the email even when there are 0 alerts in the window |
| `--index-url` / `--user` / `--password` | Indexer connection (prefer the env vars) |
| `--index-pattern` | Alerts index pattern (default `wazuh-alerts-*`) |
| `--no-verify` / `--ca PATH` | Indexer TLS handling (env `NO_VERIFY` / `CA`) |

All options also have an environment variable (see `systemd/powershell-lolbins-digest.env.example`):
`INDEX_URL`, `INDEX_USER`, `INDEX_PASSWORD`, `INDEX_PATTERN`, `CA`, `NO_VERIFY`, `SMTP_SERVER`,
`MAIL_FROM`, `RECIPIENTS`, `RANGE_DAYS`, `DASHBOARD_URL`, `WAZUH_RECIPES_LIB`.

## Verifying

```bash
# Does it reach the indexer and aggregate the alerts? (no mail)
sudo -u wazuh-recipes /opt/powershell-lolbins-digest/venv/bin/python \
  /opt/powershell-lolbins-digest/powershell-lolbins_digest.py --dry-run

# Trigger a run on demand and read its output:
sudo systemctl start powershell-lolbins-digest.service
journalctl -u powershell-lolbins-digest.service -n 30 --no-pager
```

A healthy `--dry-run` prints a `[digest] … total=… detections=… agents=… users=…` line followed by
the rendered subject and text body.

## Limitations

- **Stateless summary, not alerting.** This is a weekly overview; it does not replace real-time
  alerting and intentionally has no dedup/state — re-running re-summarises the same window.
- **Some watched rules are noisy.** See *Tuning* — `91809`/`91822`/`92206` can be frequent in
  admin-heavy or print-server environments; trim the rule list for a tighter summary.
- **Depends on Windows telemetry.** If Sysmon / PowerShell Script-Block logging isn't collected from
  the endpoints, these rules never fire and there is nothing to summarise.
- HTML is built for broad client support (table + `bgcolor`); exotic dark-mode clients may recolour
  backgrounds, but the layout and severity accent always render.

## License

MIT (inherits the repository [LICENSE](../LICENSE)).
