# Post-auth Root RCE via `reload.reload_config`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_reload_reload_config_rce_report.md`
- PoC: `poc/postauth_reload_reload_config_rce.py`

## Classification

This issue is classified as CVE because it is a direct command injection in an exposed reload RPC method.
