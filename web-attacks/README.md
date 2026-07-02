# Web Attacks

A dashboard plus a weekly email summary for Wazuh's built-in web-attack detection — multiple
attacks / XSS / 400-scans from a single source IP, and Shellshock attempts — so HTTP-facing servers
get one clean recurring overview instead of a stream of individual alerts.
(MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/).)

## What you get

- **An importable dashboard** ("Web Attacks") with ten panels: an **Investigate** notes/links panel,
  total-alert and distinct-targeted-host **metrics**, an **attack-type** pie and an **HTTP-status** pie,
  a **stacked timeline** by attack type, and data tables for **top attacked URLs / payloads**
  (`data.url`), **top targeted hosts** (`agent.name`/`agent.id`), **top real client IPs** and **source
  IPs** — all scoped to this recipe's rules. The **real client IP** table uses `data.clientip`
  (X-Forwarded-For, the true external client behind a proxy); the **source IP** table uses `data.srcip`
  (the proxy / as-logged address). The URL / attack-type / host panels are the proxy-independent signal.
- **A weekly HTML email digest** — one mail per run summarising the last *N* days: total count, a
  breakdown by attack type and by source IP, the top targeted agents, and the most recent events
  (with the offending URL / payload). Severity-coloured header, plain-text fallback.
- **Stateless and low-noise** — the digest just queries and aggregates the indexer; there is no
  database and no per-event spam. If nothing matched in the window, it sends nothing.

## Watched rules

| Rule ID | Level | Description |
|---------|:-----:|-------------|
| `31151` | 10 | Multiple web server 400 error codes from same source IP (web scan) |
| `31153` | 10 | Multiple common web attacks from same source IP |
| `31154` | 10 | Multiple XSS (Cross Site Scripting) attempts from same source IP |
| `31168` | 15 | Shellshock attack detected (CVE-2014-6271) |
| `31169` | 15 | Shellshock attack attempt |

Indexer filter used by every dashboard panel and the digest query:

```
rule.id:(31153 OR 31154 OR 31151 OR 31168 OR 31169)
```

These are **stock Wazuh rules** (the `web_rules`/`attack_rules` rulesets) — there is no custom
decoder or rule to install. They fire from your web servers' access logs, so the recipe only needs
those logs to be reaching Wazuh.

## How it works

```
 Web/HTTP servers  ──access logs──▶  Wazuh agent  ──▶  Wazuh manager
        (stock web_rules / attack_rules fire: 31151/31153/31154/31168/31169)
                                                   │
                                                   ▼
                                       Wazuh Indexer (wazuh-alerts-*)
                                          │                     │
                  Saved-object dashboard ◀┘                     └▶ web-attacks_digest.py
                  (metric / timeline / 2 tables,                   (weekly: query → aggregate
                   filtered to the rule IDs)                        → ONE HTML email)
```

The digest is a **stateless periodic summary**, not an event forwarder. Each run sends a single
aggregation request to the indexer for the watched rule IDs over the last `RANGE_DAYS`, then renders
one email (top attack types, top source IPs, top agents, most-recent events) and sends it. There is
no dedup database, so re-running it just re-summarises the same window.

## Repository layout

```
bin/
  web-attacks_digest.py             # the weekly summary (query → aggregate → email)
dashboard/
  web-attacks.ndjson                # importable saved objects (4 visualizations + 1 dashboard)
systemd/
  web-attacks-digest.service/.timer # weekly run (Mon 07:00), oneshot
  web-attacks-digest.env.example    # secrets + overrides (copy to a 0600 env file)
```

## Requirements

- **Wazuh 4.x** manager and agents, with web-server access logs being collected so the stock
  web-attack rules (`31151/31153/31154/31168/31169`) fire.
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
`dashboard/web-attacks.ndjson`. The objects reference the existing `wazuh-alerts-*` index pattern by
name, so no index-pattern object is bundled — make sure that pattern already exists (it does on a
standard Wazuh install). Open the **"Web Attacks"** dashboard and pick a time range.

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
sudo install -d -o wazuh-recipes -g wazuh-recipes /opt/web-attacks-digest
sudo -u wazuh-recipes python3 -m venv /opt/web-attacks-digest/venv
sudo -u wazuh-recipes /opt/web-attacks-digest/venv/bin/pip install opensearch-py
sudo install -o wazuh-recipes -g wazuh-recipes -m 0750 \
  bin/web-attacks_digest.py /opt/web-attacks-digest/
```

### 3. Secrets (read-only indexer user recommended)

Create a read-only user on the indexer for this tool, then store its password in an env file readable
only by the service user (keeps it out of `ps`, the unit file and git):

```bash
sudo cp systemd/web-attacks-digest.env.example /etc/web-attacks-digest.env
sudoedit /etc/web-attacks-digest.env          # set INDEX_PASSWORD, RECIPIENTS, SMTP_SERVER, ...
sudo chown wazuh-recipes:wazuh-recipes /etc/web-attacks-digest.env
sudo chmod 600 /etc/web-attacks-digest.env
```

TLS: by default the script verifies against `/etc/filebeat/certs/root-ca.pem`. If `wazuh-recipes`
can't read that path, point `CA` at a readable copy of the indexer CA, or set `NO_VERIFY=1` for a
localhost connection.

### 4. Install the timer

Edit `--recipients` (or set `RECIPIENTS` in the env file) in the `.service` file, then:

```bash
sudo cp systemd/web-attacks-digest.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now web-attacks-digest.timer
systemctl list-timers | grep web-attacks
```

> The service is `Type=oneshot`, so `systemctl status …service` normally shows `inactive (dead)` —
> that's expected; the **timer** is what matters.

## Usage

```bash
PY=/opt/web-attacks-digest/venv/bin/python
APP=/opt/web-attacks-digest/web-attacks_digest.py

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

All options also have an environment variable (see `systemd/web-attacks-digest.env.example`):
`INDEX_URL`, `INDEX_USER`, `INDEX_PASSWORD`, `INDEX_PATTERN`, `CA`, `NO_VERIFY`, `SMTP_SERVER`,
`MAIL_FROM`, `RECIPIENTS`, `RANGE_DAYS`, `DASHBOARD_URL`, `WAZUH_RECIPES_LIB`.

## Verifying

```bash
# Does it reach the indexer and aggregate the alerts? (no mail)
sudo -u wazuh-recipes /opt/web-attacks-digest/venv/bin/python \
  /opt/web-attacks-digest/web-attacks_digest.py --dry-run

# Trigger a run on demand and read its output:
sudo systemctl start web-attacks-digest.service
journalctl -u web-attacks-digest.service -n 30 --no-pager
```

A healthy `--dry-run` prints a `[digest] … total=… attack_types=… src_ips=… agents=…` line followed
by the rendered subject and text body.

## Limitations

- **Stateless summary, not alerting.** This is a weekly overview; it does not replace real-time
  alerting and intentionally has no dedup/state — re-running re-summarises the same window.
- **Depends on the stock rules firing.** If your web servers' access logs aren't reaching Wazuh, or
  those rules are tuned out, there is nothing to summarise. Rule `31151/31153/31154` are correlation
  rules (multiple events from one IP); single hits won't trigger them.
- **Source IP vs. real client.** `data.srcip` is the address the web server logged — behind a reverse
  proxy that's the **proxy**. The true external client is the **X-Forwarded-For** value, which Wazuh's
  IIS/web decoders capture into **`data.clientip`** (the dashboard's *Real client IP* panel uses it). It
  is only populated when the proxy sends XFF and the decoder maps it; direct hits show `-`.
- HTML is built for broad client support (table + `bgcolor`); exotic dark-mode clients may recolour
  backgrounds, but the layout and severity accent always render.

## License

MIT (inherits the repository [LICENSE](../LICENSE)).
