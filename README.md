# wazuh-recipes

A collection of complete, drop-in [Wazuh](https://wazuh.com) setups for monitoring and detections
that aren't covered out of the box. Each recipe is **self-contained** — agent configuration,
decoders, rules, dashboards and any automation — with its own README and install steps.

## Recipes

| Recipe | What it does |
|--------|--------------|
| [bruteforce-success](bruteforce-success/) | A dashboard + weekly email summary for Wazuh rule 40112 (auth failures followed by a success) — credential brute-forcing that actually worked, with top source IPs, targeted accounts and affected hosts. |
| [dns-threat](dns-threat/) | Detection rules, dashboards and a weekly email summary for suspicious outgoing DNS on Windows (Sysmon Event 22) — DGA/long domains, bad TLDs and odd resolvers; normal DNS stays archive-only. |
| [editor-extension-monitoring](editor-extension-monitoring/) | Inventory installed VS Code / Visual Studio extensions across Windows endpoints and alert on banned or known-malicious ones — version-aware, with an automated [OSV.dev](https://osv.dev) feed. |
| [entra-config-changes](entra-config-changes/) | Notify-once email tickets for Microsoft Entra / Intune configuration changes made by a global administrator — who changed what, with the exact old → new value of each changed property. |
| [powershell-lolbins](powershell-lolbins/) | A dashboard + weekly email summary for suspicious PowerShell and living-off-the-land-binary detections (UAC bypass, PrintNightmare, encoded commands, …), tuned for admin-heavy environments. |
| [vuln-email-digest](vuln-email-digest/) | Turn Wazuh's vulnerability inventory into low-noise email tickets — one per product to remediate (CVEs, versions and agents merged), de-duplicated, with hourly tickets and a weekly report. |
| [web-attacks](web-attacks/) | A dashboard + weekly email summary for Wazuh's built-in web-attack detection — scans, XSS and Shellshock from a single source IP, broken down by attack type, source and target. |

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
