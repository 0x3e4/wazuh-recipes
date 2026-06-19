# wazuh-recipes

A collection of complete, drop-in [Wazuh](https://wazuh.com) setups for monitoring and detections
that aren't covered out of the box. Each recipe is **self-contained** — agent configuration,
decoders, rules, dashboards and any automation — with its own README and install steps.

## Recipes

| Recipe | What it does |
|--------|--------------|
| [editor-extension-monitoring](editor-extension-monitoring/) | Inventory installed VS Code / Visual Studio extensions across Windows endpoints and alert on banned or known-malicious ones — version-aware, with an automated [OSV.dev](https://osv.dev) feed. |
| [critical-vuln-email-digest](critical-vuln-email-digest/) | Turn Wazuh's vulnerability inventory into low-noise email tickets — one per product to remediate (CVEs, versions and agents merged), de-duplicated, with hourly tickets and a weekly report. |

## Using a recipe

Each folder is independent: open its README and follow the install steps. Recipes target **Wazuh 4.x**.
Custom rules and decoders go under `etc/rules` / `etc/decoders` (upgrade-safe); changes load on a
manager restart.

## Adding a recipe

Copy [`_template/`](_template/) to a new folder named after the use case, fill in its README, drop in
your `ruleset/` (and `agent/`, `dashboard/`, automation as needed), and add a row to the table above.
Validate rules and decoders with `wazuh-logtest` before submitting.

## License

MIT — see [LICENSE](LICENSE).
