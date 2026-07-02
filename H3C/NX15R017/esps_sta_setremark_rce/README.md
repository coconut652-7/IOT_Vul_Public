# Post-auth Root RCE via `esps.sta.setremark`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_esps_sta_setremark_rce_report.md`
- PoC: `poc/postauth_esps_sta_setremark_rce.py`

## Classification

This issue is classified as CVE because it is an authenticated command injection in a specific `/api/esps` RPC method that immediately reaches a root `eval` sink.
