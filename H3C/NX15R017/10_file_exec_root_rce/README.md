# Post-auth Root RCE via Exposed `file.exec`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/23_postauth_file_exec_rce_report.md`
- PoC: `poc/17_postauth_file_exec_rce.py`

## Classification

This issue is classified as CVE because `/api/esps` exposes a dangerous native command-execution RPC method to authenticated web sessions.

