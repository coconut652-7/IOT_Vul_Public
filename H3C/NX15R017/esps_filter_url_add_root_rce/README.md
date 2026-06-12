# Post-auth Root RCE via `esps.filter.url.add`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_esps_filter_url_rce_report.md`
- Analysis guidance: `report/postauth_esps_filter_url_rce_analysis_guidance.md`
- PoC: `poc/postauth_esps_filter_url_rce.py`

## Classification

This issue is classified as CVE because it is an authenticated, single-object command injection in a specific `/api/esps` RPC method.
