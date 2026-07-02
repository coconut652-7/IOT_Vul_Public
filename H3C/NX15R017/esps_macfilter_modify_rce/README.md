# Post-auth Root RCE via `esps.macfilter.modify`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_esps_macfilter_modify_rce_report.md`
- PoC: `poc/postauth_esps_macfilter_modify_rce.py`

## Classification

This issue is classified as CVE because it is an authenticated command injection in a specific `/api/esps` RPC method that leads to immediate root command execution.
