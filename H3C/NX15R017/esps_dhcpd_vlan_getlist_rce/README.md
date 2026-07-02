# Post-auth Root RCE via `esps.dhcpd.vlan.getlist`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_esps_dhcpd_vlan_getlist_rce_report.md`
- PoC: `poc/postauth_esps_dhcpd_vlan_getlist_rce.py`

## Classification

This issue is classified as CVE because it is an authenticated command injection in a specific `/api/esps` RPC method that directly `eval`s attacker-controlled list items.
