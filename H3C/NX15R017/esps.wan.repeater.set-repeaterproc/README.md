# Post-auth Conditional Root RCE via `esps.wan.repeater.set` -> `repeaterproc`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_esps_wan_repeater_repeaterproc_rce_report.md`
- Analysis guidance: `report/postauth_esps_wan_repeater_repeaterproc_rce_analysis_guidance.md`
- PoC: `poc/postauth_esps_wan_repeater_repeaterproc_rce.py`

## Classification

This issue is classified as CVE because it is a distinct authenticated command injection in the repeater runtime, triggered by web-supplied repeater configuration input and resulting in root command execution when the device enters the vulnerable 2.4G repeater branch.
