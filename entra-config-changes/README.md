# Entra / Intune Admin Config-Change Tickets

Get a low-noise email the moment a **global administrator** changes configuration in
Microsoft Entra ID or Intune — showing **who** changed **what**, and the exact
**old → new** value of every property that actually changed. Relevant to
[MITRE T1098 (Account Manipulation)](https://attack.mitre.org/techniques/T1098/) and
[T1484 (Domain/Policy Modification)](https://attack.mitre.org/techniques/T1484/).

It reads Microsoft Graph **audit** events straight from the Wazuh Indexer
(`wazuh-alerts-4.x-*`, rule group `ms-graph`) — no new Wazuh rules or decoders — and
sends one notify-once ticket per change (SQLite dedup).

## What you get

- **Two audit sources, one recipe** — Intune `deviceManagement/auditEvents` (collected
  out of the box by the `ms-graph` integration) and, once enabled, Entra ID
  `auditLogs/directoryAudits` (roles, Conditional Access, app registrations, users/groups).
- **Global-admin only** — Intune events are matched on `actor.userPermissions == ["*"]`;
  Entra events are matched by a **live Microsoft Graph lookup** of the Global
  Administrator role members (cached).
- **Only real diffs** — a "Patch" carries a full property snapshot; the ticket shows only
  the properties whose value actually changed. An all-no-op event sends nothing. Opaque
  `.NET` placeholder values are suppressed.
- **Notify-once** — each change is emailed exactly once (keyed on the Graph audit event id).
- **HTML email** — Segoe-UI, three sections (Who / What / What changed), with a
  plain-text fallback.
- **Optional dashboard** — an importable saved-object set for a visual overview.

## How it works

```
 Wazuh Indexer  (wazuh-alerts-4.x-*, rule group "ms-graph")   = MS Graph audit events
        │  HTTPS query (last LOOKBACK_HOURS)
        ▼
 entra-config-changes_digest.py ─┬─ classify: Intune (actor/resources) | Entra (initiatedBy/targetResources)
                                 ├─ keep global-admin changes  (userPermissions[*]  |  Graph role lookup, cached)
                                 ├─ diff modifiedProperties     (old != new only)
                                 ├─ SQLite state DB             (notify-once)
                                 └─ SMTP ─▶ HTML ticket (who / what / old→new)

 systemd timer:  every 15 min  → notify-once tickets
```

Global-admin attribution differs by source because the data does: Intune audit events
carry `actor.userPermissions` (a global admin has `["*"]`), but Entra directory-audit
events don't — so for those the script calls
`GET /directoryRoles(roleTemplateId='62e90394-…')/members` and caches the member set.
If the Graph lookup is unavailable and there is no cache, Entra events are **skipped**
(logged) rather than mis-attributed.

## Repository layout

```
bin/
  entra-config-changes_digest.py          # query → classify → diff → de-dup → email
systemd/
  entra-config-changes-digest.service/.timer   # 15-minute notify-once job
  entra-config-changes-digest.env.example       # secrets + overrides (copy to a 0600 env file)
ossec/
  ms-graph-directoryaudits.snippet.xml     # <resource> to add for the Entra ID half
dashboard/
  entra-config-changes.ndjson              # importable overview dashboard (optional)
```

## Requirements

- **Wazuh 4.x** with the [`ms-graph` integration](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/ms-graph.html)
  configured (`deviceManagement/auditEvents` is enough for the Intune half).
- Read access from the host running the script to the Wazuh Indexer (default
  `https://127.0.0.1:9200`) — ideally a **read-only indexer user**.
- An SMTP relay the host may send through.
- Python **3.8+** and [`opensearch-py`](https://pypi.org/project/opensearch-py/) in a venv.
  Graph calls use the standard library — no other third-party dependency.
- **For the Entra half only:** the `auditLogs/directoryAudits` resource enabled (below) and
  a Graph app with `AuditLog.Read.All` + `RoleManagement.Read.Directory` (admin consent).

## Installation

The script only **reads** the indexer, **writes** a small SQLite file, and **sends** mail —
none of which needs root. Run it as a dedicated, unprivileged service user.

### 1. Service user, directory and venv

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-recipes
sudo install -d -o wazuh-recipes -g wazuh-recipes /opt/entra-config-changes-digest
sudo -u wazuh-recipes python3 -m venv /opt/entra-config-changes-digest/venv
sudo -u wazuh-recipes /opt/entra-config-changes-digest/venv/bin/pip install opensearch-py
sudo install -o wazuh-recipes -g wazuh-recipes -m 0750 \
  bin/entra-config-changes_digest.py /opt/entra-config-changes-digest/
```

### 2. Secrets (read-only indexer user recommended)

```bash
sudo cp systemd/entra-config-changes-digest.env.example \
        /opt/entra-config-changes-digest/entra-config-changes.env
sudoedit /opt/entra-config-changes-digest/entra-config-changes.env   # set INDEX_PASSWORD (+ MS_GRAPH_* for Entra)
sudo chown wazuh-recipes:wazuh-recipes /opt/entra-config-changes-digest/entra-config-changes.env
sudo chmod 600 /opt/entra-config-changes-digest/entra-config-changes.env
```

TLS: the script verifies against `/etc/wazuh-indexer/certs/root-ca.pem` by default. If the
service user can't read it, point `--ca` at a readable copy or use `--no-verify` for a
localhost connection. To authenticate by **mTLS** instead of a password, set
`INDEX_CLIENT_CERT`/`INDEX_CLIENT_KEY` (or `--cert`/`--key`) to a readable client cert —
e.g. run as root with `/etc/wazuh-indexer/certs/admin.pem`.

### 3. Seed the baseline (no email)

```bash
sudo -u wazuh-recipes /opt/entra-config-changes-digest/venv/bin/python \
  /opt/entra-config-changes-digest/entra-config-changes_digest.py --seed --lookback-hours 168
```

### 4. Install the timer

Edit `--recipients` and `--smtp-server` on the `.service` `ExecStart` line, then:

```bash
sudo cp systemd/entra-config-changes-digest.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now entra-config-changes-digest.timer
systemctl list-timers | grep entra-config-changes
```

> The service is `Type=oneshot`, so `systemctl status …service` shows `inactive (dead)`
> between runs — that's expected; the **timer** is what matters.

### 5. Dashboard (optional)

Import `dashboard/entra-config-changes.ndjson` via **Dashboards Management → Saved Objects →
Import**. It targets the `wazuh-alerts-*` index pattern and rule id `99652`.

## Enable the Entra ID directory-audit half (optional)

1. **ossec.conf** (manager): add the block from `ossec/ms-graph-directoryaudits.snippet.xml`
   inside your existing `<ms-graph>` block, then `sudo systemctl restart wazuh-manager`.
2. **Azure**: grant the Graph app **application** permissions `AuditLog.Read.All` (ingestion)
   and `RoleManagement.Read.Directory` (the recipe's Global-Admin lookup), with admin consent.
3. Put that app's tenant/client/secret in `MS_GRAPH_*` in the env file.

## Usage

```bash
PY=/opt/entra-config-changes-digest/venv/bin/python
APP=/opt/entra-config-changes-digest/entra-config-changes_digest.py

sudo -u wazuh-recipes $PY $APP --dry-run --lookback-hours 168      # preview; no mail, no DB change
sudo -u wazuh-recipes $PY $APP --seed   --lookback-hours 168       # (re)set the baseline, no mail
sudo -u wazuh-recipes $PY $APP --test --recipients you@example.com # send one sample ticket, no DB change
```

| Option | Meaning |
|--------|---------|
| `--dry-run` | Print what would be sent; send nothing, change nothing |
| `--seed` | Baseline current changes (no mail), then exit |
| `--test` | Send a sample ticket from the most recent matching change (no DB change) |
| `--lookback-hours N` | How far back each run scans (default 24; dedup covers overlap) |
| `--recipients a@x,b@y` | Recipient list (or `RECIPIENTS` env) |
| `--smtp-server H` / `--smtp-port P` | SMTP relay (or `SMTP_SERVER`/`SMTP_PORT` env; default port 25) |
| `--state-db PATH` | SQLite dedup DB (default `/opt/entra-config-changes-digest/state.db`) |
| `--cert` / `--key` | Client cert/key for indexer mTLS (else `INDEX_PASSWORD`) |
| `--ca PATH` / `--no-verify` | Indexer TLS handling |

## Configuration

Near the top of `bin/entra-config-changes_digest.py`, all overridable by env:

- **`GLOBAL_ADMIN_ROLE_TEMPLATE_IDS`** — role template ids treated as "global admin" for the
  Entra lookup (default: Global Administrator `62e90394-…`; add e.g. Privileged Role Admin).
- **`GRAPH_ROLE_CACHE_HOURS`** — how long the Global-Admin member set is cached (default 6).
- **`SUPPRESS_NOISE`** — drop opaque `.NET` placeholder property values (default on).
- **`LOOKBACK_HOURS`**, **`INDEX_*`**, **`SMTP_*`**, **`MAIL_FROM`**, **`DASHBOARD_URL`** — see the env example.

## Verifying

```bash
# Reaches the indexer and finds admin changes? (counts only, no mail)
sudo -u wazuh-recipes /opt/entra-config-changes-digest/venv/bin/python \
  /opt/entra-config-changes-digest/entra-config-changes_digest.py --dry-run --lookback-hours 168

# Trigger a run on demand and read its output:
sudo systemctl start entra-config-changes-digest.service
journalctl -u entra-config-changes-digest.service -n 30 --no-pager
```

A healthy `--dry-run` prints `[gather] … intune=… entra=…` and a `[notify] new …` line.

## Limitations

- **Global admin, two ways.** Intune uses `userPermissions[*]` from the event; Entra needs a
  Graph role lookup (extra app permission + outbound call). App-initiated directory changes
  are not matched (no human global admin).
- **Going-forward only.** Notify-once fires on new events; it does not back-fill history
  (seed baselines what already exists so it isn't re-announced).
- **Field names.** Panels/queries assume Wazuh's default `data.ms-graph.*` mapping; adjust if
  your pipeline differs.
- HTML is built for broad client support (tables + explicit fonts); exotic dark-mode clients
  may still recolour backgrounds.

## License

MIT (inherits the repository [LICENSE](../LICENSE)).
