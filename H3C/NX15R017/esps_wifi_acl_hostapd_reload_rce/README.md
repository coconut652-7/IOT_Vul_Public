# Post-auth Stored Root RCE via `esps.wifi.acl` -> `hostapd.sh`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_esps_wifi_acl_hostapd_reload_rce_report.md`
- PoC: `poc/postauth_esps_wifi_acl_hostapd_reload_rce.py`

## Classification

This issue is classified as CVE because it is a distinct authenticated stored command injection chain that persists attacker-controlled Wi-Fi ACL data and later reaches a root `eval` sink during Wi-Fi reload.
