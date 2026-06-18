# <Recipe name>

One sentence: what this recipe monitors or detects, and why it matters (link the relevant MITRE
technique if applicable).

## What you get

- ...
- ...

## How it works

Short description of the data flow — which Wazuh primitives are used (FIM, logcollector, wodle,
decoder, rules) and how the data reaches alerts/dashboards.

## Repository layout

```
agent/        # <agent_config> snippet + any agent-side scripts (optional)
ruleset/
  decoders/   # custom decoders
  rules/      # custom rules (use a free custom ID range, e.g. 1020xx)
dashboard/    # importable .ndjson (optional)
```

## Requirements

- Wazuh 4.x manager and agents (state OS scope).
- Any prerequisites (e.g. `logcollector.remote_commands=1`, outbound network).

## Installation

1. **Ruleset (manager).** Copy decoders/rules into `etc/decoders` / `etc/rules`, set
   `chown root:wazuh` + `chmod 0640`, then `systemctl restart wazuh-manager`.
2. **Agent config.** Add the `<agent_config>` block to your target group's `agent.conf`.
3. **Dashboard (optional).** Import the `.ndjson` via Dashboards Management → Saved Objects → Import.

## Verifying

```bash
/var/ossec/bin/wazuh-logtest -v        # paste a sample event
grep -hE '"id":"<rule-id>"' /var/ossec/logs/alerts/alerts.json | tail
```

## Limitations

- ...

## License

MIT (inherits the repository [LICENSE](../LICENSE)).
