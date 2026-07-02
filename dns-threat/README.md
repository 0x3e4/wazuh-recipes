# DNS Threat Monitoring

Detection rules, a dashboard and a weekly email summary for **suspicious outgoing DNS** on Windows
endpoints, built on **Sysmon Event 22** (DNS query). Normal DNS stays archive-only (level 0); only
flagged queries — known-malicious domains, abuse-prone TLDs, dynamic-DNS / tunneling services, and
abnormally long labels — raise an alert. A separate offline **anomaly sweep** catches the
volume-based patterns the stateless rules can't (DGA bursts, many-subdomain tunneling).
(MITRE ATT&CK: [T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004/),
[T1568.002 Domain Generation / Dynamic Resolution](https://attack.mitre.org/techniques/T1568/002/),
[T1048.003 Exfiltration over DNS](https://attack.mitre.org/techniques/T1048/003/).)

## What you get

- **Detection rules** (`rules/dns_threat_rules.xml`, IDs 100700–100703, group `dns_threat`) chained
  off the built-in Sysmon Event 22 rule `61650`.
- **An importable dashboard** ("DNS Threat Monitoring") with ten panels: an **Investigate** notes/links
  panel (with the rule-ID legend), **metrics** for total alerts / distinct flagged domains / hosts, a
  **detection-rule pie**, a **stacked timeline** by rule, and data tables for **top flagged domains**
  (`data.win.eventdata.queryName`), **top hosts** (`agent.name`/`agent.id`), **top processes**
  (`data.win.eventdata.image`) and **top users**.
- **A companion "all DNS" dashboard** ("DNS Activity (all queries)", `dashboard/dns-activity.ndjson`)
  over **`wazuh-archives-*`** — the full Sysmon Event 22 firehose: query volume over time, distinct
  domains/hosts, top queried domains / hosts / processes / resolved IPs, and **failed-lookup** panels
  (NXDOMAIN / SERVFAIL — DGA / dead-C2 / typo / misconfig signal). Use it for visibility/ops; use the
  threat dashboard for the flagged subset.
- **A weekly HTML email digest** — total count, a breakdown by detection rule, by flagged domain, by
  host and by process, plus the most recent alerts. Severity-coloured header, plain-text fallback.
- **An offline anomaly sweep** (`bin/dns_sweep.py`) over the Wazuh archives for volume anomalies the
  stateless rules miss (DGA bursts, many-distinct-subdomain tunneling).

## Watched rules

| Rule ID | Level | Detects | MITRE |
|---------|:-----:|---------|-------|
| `100700` | 12 | Query to a **known-malicious** domain (CDB denylist, exact match) | T1071.004 |
| `100701` | 10 | Query to a **suspicious / abuse-prone TLD** (`.top .xyz .tk .ml .ga .cf .gq .click .monster .quest .cfd .sbs .zip .mov .lol .work .buzz`) | T1071.004 |
| `100702` | 10 | Query to a **dynamic-DNS / tunneling service** (duckdns, ngrok, no-ip, nip.io, workers.dev, …) | T1568.002 |
| `100703` | 10 | **Long single label** (≥ 50 chars) — possible DNS tunneling | T1048.003 |
| `100711` | 0 | Suppress your **own** domain that legitimately uses a flagged TLD (edit it — see *Tuning*) | — |

Indexer filter used by every dashboard panel and the digest query:

```
rule.groups:dns_threat
```

## How it works

```
 Windows endpoints (Sysmon, Event 22 = DNS query)  ──▶  Wazuh agent  ──▶  Wazuh manager
        built-in rule 61650 (level 0, archive only)
                          │  chained off by dns_threat_rules.xml (100700-100703)
                          ▼
                 alerts (rule.groups: dns_threat)  ──▶  Wazuh Indexer (wazuh-alerts-*)
                          │                                  │
       Saved-object dashboard ◀──────────────────────────────┘   └▶ dns-threat_digest.py
       (10 panels, filtered to dns_threat)                          (weekly: query → aggregate → ONE email)

 Wazuh archives (wazuh-archives-*, every Event 22)  ──▶  dns_sweep.py  (daily cron: volume anomalies)
```

Because Event 22 is level 0 it is **archived but not alerted** by default — that's why the raw DNS
data lives in `wazuh-archives-*` and only the flagged queries (100700–100703) reach `wazuh-alerts-*`.

## Repository layout

```
rules/
  dns_threat_rules.xml              # the detection rules (deploy to /var/ossec/etc/rules/)
dashboard/
  dns-threat.ndjson                 # threat dashboard, on wazuh-alerts-* (10 viz + 1 dashboard)
  dns-activity.ndjson               # all-DNS visibility dashboard, on wazuh-archives-* (11 viz + 1 dashboard)
bin/
  dns-threat_digest.py              # weekly alert summary (query → aggregate → email)
  dns_sweep.py                      # daily archive anomaly sweep (cron)
systemd/
  dns-threat-digest.service/.timer  # weekly run (Mon 07:00), oneshot
  dns-threat-digest.env.example     # secrets + overrides (copy to a 0600 env file)
```

## Requirements

- **Wazuh 4.x** manager + agents; **Sysmon** on the Windows endpoints with **DNS query logging
  (Event ID 22)** enabled and shipped to Wazuh (so the built-in `61650` fires).
- A populated CDB list `etc/lists/malicious-ioc/malicious-domains` for rule `100700` (one `domain:`
  per line), referenced under `<ruleset>` in `ossec.conf`.
- **Wazuh Indexer / OpenSearch** + **OpenSearch Dashboards** for the dashboard and digest.
- For the digest: Python **3.8+** and [`opensearch-py`](https://pypi.org/project/opensearch-py/) in a
  venv; an SMTP relay. For the sweep: read access to `/var/ossec/logs/archives`.

## Installation

### 1. Deploy the rules + enable the denylist

```bash
sudo install -o root -g wazuh -m 0660 rules/dns_threat_rules.xml /var/ossec/etc/rules/
```
Make sure `ossec.conf` references the malicious-ioc lists under `<ruleset>` and that
`etc/lists/malicious-ioc/malicious-domains` is populated, then validate and reload:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t        # parse rules + lists; expect no errors
sudo systemctl restart wazuh-manager
# smoke test: paste a Sysmon Event 22 with a denylisted queryName -> rule 100700
sudo /var/ossec/bin/wazuh-logtest
```

### 2. Import the dashboard

In **OpenSearch Dashboards → Dashboards Management → Saved Objects → Import**, import
`dashboard/dns-threat.ndjson`. It references the existing `wazuh-alerts-*` index pattern by name (no
index-pattern object is bundled), so there is no conflict to resolve. Open **"DNS Threat
Monitoring"** and pick a time range.

For full DNS visibility (not just flagged queries) also import `dashboard/dns-activity.ndjson` and
open **"DNS Activity (all queries)"**. It reads **`wazuh-archives-*`** (where the level-0 Event 22
data lives), so Wazuh archive indexing must be enabled. Unlike `wazuh-alerts-*`, the archives
index-pattern's saved-object id is install-specific — if the import can't resolve it, OpenSearch
Dashboards will prompt you to map it to your `wazuh-archives-*` index pattern.

**Clean resolved IPs (optional).** Sysmon stores `queryResults` as `::ffff:<ip>;`. To show just the
IP in the "Top resolved IPs" panel, add the scripted field in `dashboard/dns_resolved_ip.painless`
to the `wazuh-archives-*` index pattern (Scripted fields → Add), then point that panel's bucket field
at `dns_resolved_ip`. It works on existing archived data; no manager restart.

### 2b. (Optional) make agent / host names clickable

The data tables include `agent.id`. To link it to the host's page in Wazuh, add a **URL
field-formatter** once: **Dashboards Management → Index Patterns → `wazuh-alerts-*`**, edit the
`agent.id` field, set **Format = Url**, **Type = Link**, **URL template**
`/app/wazuh#/agents?agent={{value}}`, then **Save**.

### 3. Weekly digest (service user + venv + timer)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-recipes 2>/dev/null
sudo install -d -o wazuh-recipes -g wazuh-recipes /opt/dns-threat-digest
sudo -u wazuh-recipes python3 -m venv /opt/dns-threat-digest/venv
sudo -u wazuh-recipes /opt/dns-threat-digest/venv/bin/pip install opensearch-py
sudo install -o wazuh-recipes -g wazuh-recipes -m 0750 bin/dns-threat_digest.py /opt/dns-threat-digest/
sudo cp systemd/dns-threat-digest.env.example /etc/dns-threat-digest.env
sudoedit /etc/dns-threat-digest.env           # set INDEX_PASSWORD, RECIPIENTS, SMTP_SERVER, ...
sudo chown wazuh-recipes:wazuh-recipes /etc/dns-threat-digest.env && sudo chmod 600 /etc/dns-threat-digest.env
sudo cp systemd/dns-threat-digest.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now dns-threat-digest.timer
```

### 4. (Optional) daily anomaly sweep

```bash
sudo install -o root -g wazuh -m 0750 bin/dns_sweep.py /opt/wazuh-recipes/dns_sweep.py
# daily 06:10, scans yesterday's rotated archive; exit 2 + report if anything actionable:
echo '10 6 * * *  /usr/bin/python3 /opt/wazuh-recipes/dns_sweep.py >> /var/log/dns_sweep.log 2>&1' | sudo tee /etc/cron.d/dns-sweep
```
Tune with `DNS_SWEEP_MANYSUBS` (many-subdomain threshold), `DNS_SWEEP_GOOD` (your internal domains to
ignore), `DNS_SWEEP_OWN` (your own flagged-TLD domains). Reports land in `$DNS_SWEEP_OUT`.

## Usage (digest)

```bash
PY=/opt/dns-threat-digest/venv/bin/python
APP=/opt/dns-threat-digest/dns-threat_digest.py
sudo -u wazuh-recipes $PY $APP --dry-run                              # preview, send nothing
sudo -u wazuh-recipes $PY $APP --range-days 30 --dry-run             # summarise 30 days
sudo -u wazuh-recipes $PY $APP --recipients soc@example.com          # send now
```
Options mirror the env file: `--index-url/--user/--password`, `--index-pattern`, `--no-verify/--ca`,
`--range-days`, `--recipients`, `--dry-run`, `--always` (send even with 0 alerts).

## Tuning / false positives

- **Own domain on a flagged TLD.** If you own e.g. `example.lol`, edit rule **100711** (and set
  `DNS_SWEEP_OWN=example.lol`) so your own traffic is suppressed instead of firing 100701.
- **Suspicious-TLD list** (100701) is the most likely source of noise — trim the TLD set in the rule
  to match your risk appetite.
- **Long-label** (100703) can match legitimate base32/hash subdomains (some CDNs, AV cloud lookups);
  add such parents to `DNS_SWEEP_GOOD` / refine the rule if needed.

## Limitations

- **Windows + Sysmon Event 22 only.** Endpoints without Sysmon DNS logging are invisible; a DNS
  server's own forwarded queries (e.g. `dns.exe`) are not in Event 22 — collect the DNS-Server
  channel separately for those. Linux DNS needs a resolver query-log shipped to Wazuh.
- **Denylist quality.** Rule 100700 is only as good as `malicious-domains`; keep it fed from your
  threat-intel source.
- The digest is a **stateless weekly summary**, not real-time alerting; it has no dedup/state.

## License

MIT (inherits the repository [LICENSE](../LICENSE)).
