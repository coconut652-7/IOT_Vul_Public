# Post-auth Root RCE via Exposed `service.add`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_service_add_rce_report.md`
- PoC: `poc/postauth_service_add_rce.py`

## Classification

This issue is classified as CVE because `/api/esps` exposes a dangerous native service-management RPC method to authenticated web sessions.
