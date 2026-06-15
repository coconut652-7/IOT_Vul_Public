# Pre-auth WAN Configuration Modification via `/api/wizard/networkSetup`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/preauth_wizard_networksetup_report.md`
- Analysis guidance: `report/preauth_wizard_networksetup_analysis_guidance.md`
- PoCs:
  - `poc/preauth_wizard_networksetup_hijack.py`
  - `poc/preauth_wizard_networksetup_toggle.py`

## Classification

This issue is classified as CVE because it is a direct unauthenticated configuration-write flaw exposed by wizard endpoint.
