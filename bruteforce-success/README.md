# Brute Force → Successful Logon

A dashboard plus a weekly email summary for Wazuh's **rule 40112** — *multiple authentication
failures followed by a success* — so credential brute-forcing that actually **worked** shows up as one
clean recurring overview instead of being buried in the alert stream.
(MITRE ATT&CK: [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/),
[T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/).)

## What you get

- **An importable dashboard** ("Brute Force → Successful Logon") with eleven panels: an **Investigate**
  notes/links panel; **metrics** for total successful logons / accounts reached / attacker IPs /
  **target hosts**; a **timeline**; and data tables for **attacker source IPs** (+ distinct accounts),
  **targeted accounts** (+ distinct attacker IPs), the **target host + its IP** (`agent.name` /
  `agent.ip`) and **service** (`decoder.name`), plus a full **attacker → account → target host**
  detail table. SSH/auth logs carry no separate destination IP, so the **agent host *is* the target**
  (its address is `agent.ip`) — all scoped to this recipe's rule.
- **A weekly HTML email digest** — one mail per run summarising the last *N* days: total count, a
  breakdown by source IP, by account and by affected host, plus the most recent events
  (time, source, account, host). Severity-coloured header, plain-text fallback.
- **Stateless and low-noise** — the digest just queries and aggregates the indexer; there is no
  database and no per-event spam. If nothing matched in the window, it sends nothing.

## Watched rules

| Rule ID | Level | Description |
|---------|:-----:|-------------|
| `40112` | 12 | Multiple authentication failures followed by a success |

Indexer filter used by every dashboard panel and the digest query:

```
rule.id:40112
```

This is a **stock Wazuh rule** (the `ossec` ruleset) — there is no custom decoder or rule to install.
It is a correlation rule: it fires when a burst of failed logons for a host is followed by a success,
which is the signal you care about (a brute-force attempt that broke through). It works for any log
source that produces authentication events Wazuh understands (e.g. Linux `sshd`/`pam`, etc.).

## How it works

```
 Hosts (auth logs: sshd, pam, ...)  ──▶  Wazuh agent  ──▶  Wazuh manager
        (stock rule 40112 fires: failures followed by a success)
                                                   │
                                                   ▼
                                       Wazuh Indexer (wazuh-alerts-*)
                                          │                     │
                  Saved-object dashboard ◀┘                     └▶ bruteforce-success_digest.py
                  (metric / timeline / 2 tables,                   (weekly: query → aggregate
                   filtered to rule 40112)                          → ONE HTML email)
```

The digest is a **stateless periodic summary**, not an event forwarder. Each run sends a single
aggregation request to the indexer for rule `40112` over the last `RANGE_DAYS`, then renders one
email (top source IPs, top accounts, top hosts, most-recent events) and sends it. There is no dedup
database, so re-running it just re-summarises the same window.

## Repository layout

```
bin/
  bruteforce-success_digest.py             # the weekly summary (query → aggregate → email)
dashboard/
  bruteforce-success.ndjson                # importable saved objects (4 visualizations + 1 dashboard)
systemd/
  bruteforce-success-digest.service/.timer # weekly run (Mon 07:00), oneshot
  bruteforce-success-digest.env.example    # secrets + overrides (copy to a 0600 env file)
```

## Requirements

- **Wazuh 4.x** manager and agents, with authentication logs being collected so the stock rule
  `40112` fires.
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
`dashboard/bruteforce-success.ndjson`. The objects reference the existing `wazuh-alerts-*` index
pattern by name, so no index-pattern object is bundled — make sure that pattern already exists (it
does on a standard Wazuh install). Open the **"Brute Force → Successful Logon"** dashboard and pick a
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
sudo install -d -o wazuh-recipes -g wazuh-recipes /opt/bruteforce-success-digest
sudo -u wazuh-recipes python3 -m venv /opt/bruteforce-success-digest/venv
sudo -u wazuh-recipes /opt/bruteforce-success-digest/venv/bin/pip install opensearch-py
sudo install -o wazuh-recipes -g wazuh-recipes -m 0750 \
  bin/bruteforce-success_digest.py /opt/bruteforce-success-digest/
```

### 3. Secrets (read-only indexer user recommended)

Create a read-only user on the indexer for this tool, then store its password in an env file readable
only by the service user (keeps it out of `ps`, the unit file and git):

```bash
sudo cp systemd/bruteforce-success-digest.env.example /etc/bruteforce-success-digest.env
sudoedit /etc/bruteforce-success-digest.env          # set INDEX_PASSWORD, RECIPIENTS, SMTP_SERVER, ...
sudo chown wazuh-recipes:wazuh-recipes /etc/bruteforce-success-digest.env
sudo chmod 600 /etc/bruteforce-success-digest.env
```

TLS: by default the script verifies against `/etc/filebeat/certs/root-ca.pem`. If `wazuh-recipes`
can't read that path, point `CA` at a readable copy of the indexer CA, or set `NO_VERIFY=1` for a
localhost connection.

### 4. Install the timer

Edit `--recipients` (or set `RECIPIENTS` in the env file) in the `.service` file, then:

```bash
sudo cp systemd/bruteforce-success-digest.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bruteforce-success-digest.timer
systemctl list-timers | grep bruteforce-success
```

> The service is `Type=oneshot`, so `systemctl status …service` normally shows `inactive (dead)` —
> that's expected; the **timer** is what matters.

## Usage

```bash
PY=/opt/bruteforce-success-digest/venv/bin/python
APP=/opt/bruteforce-success-digest/bruteforce-success_digest.py

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

All options also have an environment variable (see `systemd/bruteforce-success-digest.env.example`):
`INDEX_URL`, `INDEX_USER`, `INDEX_PASSWORD`, `INDEX_PATTERN`, `CA`, `NO_VERIFY`, `SMTP_SERVER`,
`MAIL_FROM`, `RECIPIENTS`, `RANGE_DAYS`, `DASHBOARD_URL`, `WAZUH_RECIPES_LIB`.

## Verifying

```bash
# Does it reach the indexer and aggregate the alerts? (no mail)
sudo -u wazuh-recipes /opt/bruteforce-success-digest/venv/bin/python \
  /opt/bruteforce-success-digest/bruteforce-success_digest.py --dry-run

# Trigger a run on demand and read its output:
sudo systemctl start bruteforce-success-digest.service
journalctl -u bruteforce-success-digest.service -n 30 --no-pager
```

A healthy `--dry-run` prints a `[digest] … total=… src_ips=… accounts=… hosts=…` line followed by the
rendered subject and text body.

## Limitations

- **Stateless summary, not alerting.** This is a weekly overview; it does not replace real-time
  alerting and intentionally has no dedup/state — re-running re-summarises the same window. A
  *successful* brute force is high-value: consider also forwarding rule `40112` to a real-time channel.
- **Depends on the stock rule firing.** Rule `40112` is a correlation rule; isolated failures or a
  clean success won't trigger it. If authentication logs aren't reaching Wazuh, there is nothing to
  summarise.
- **`data.srcip` / `data.dstuser` only.** These come straight from the auth-log decoders; behind a
  bastion/NAT the source IP may be the jump host's address.
- HTML is built for broad client support (table + `bgcolor`); exotic dark-mode clients may recolour
  backgrounds, but the layout and severity accent always render.

## License

MIT (inherits the repository [LICENSE](../LICENSE)).
