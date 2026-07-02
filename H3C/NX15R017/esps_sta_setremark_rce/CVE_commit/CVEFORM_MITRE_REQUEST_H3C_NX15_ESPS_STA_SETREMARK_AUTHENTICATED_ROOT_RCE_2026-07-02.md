# MITRE CVE Form Submission Draft

## Scope

This filled draft is for the current `cveform.mitre.org` request type:

- `Report Vulnerability/Request CVE ID`
- vulnerability: H3C Magic NX15 `esps.sta.setremark` Authenticated OS Command Injection to Root Remote Code Execution

Use this as a fill-in draft before manually submitting the form on the MITRE CVE request site.

## Important Notes

- This draft follows the field structure in `CVEFORM_MITRE_REQUEST_TEMPLATE.md`.
- `Reference(s)` currently use local report-path placeholders per request. Replace them with public URLs before actual submission.
- `Contact email`, optional `PGP key`, the CAPTCHA / security code, and the final CNA/CVE verification checkboxes still need manual completion before submission.
- The technical content below is derived from these local evidence files:
  - `report/postauth_esps_sta_setremark_rce_report.md`
  - `poc/postauth_esps_sta_setremark_rce.py`

## Requestor Information

- Request type: `Report Vulnerability/Request CVE ID`
- Contact email: `<YOUR_EMAIL>`
- PGP key: `[[OPTIONAL]]`

```text
<ASCII-armored PGP public key, or leave blank>
```

## Request-Level Fields

- Number of vulnerabilities / CVE IDs requested: `1`
- `I have verified that this vulnerability is not in a CNA-covered product.`: `<NEEDS_CONFIRMATION>`
- `I have verified that the vulnerability has not already been assigned a CVE ID.`: `<NEEDS_CONFIRMATION>`
- Verification note: the final CNA-coverage check and duplicate-CVE search are intentionally left for manual confirmation at submission time.

Use this checklist before submission:

- Confirm whether H3C / the NX15 product line is outside CNA coverage before setting the CNA checkbox to `Yes`.
- Confirm no prior CVE has already been assigned for this exact issue.
- Replace the placeholder `Reference(s)` entry below with one or more public URLs before actual submission.

## Per-Vulnerability Section

---

### Vulnerability 1

#### Required

- Vulnerability type: `Other or Unknown`
- Other vulnerability type: `OS command injection / shell metacharacter injection`
- Vendor of the product(s): `H3C`

#### Product / version rows

| Product | Version |
|---|---|
| `H3C Magic NX15` | `Firmware NX15V100R017; verified affected version. Other affected or fixed versions not yet verified.` |

#### Reference(s)

```text
report/postauth_esps_sta_setremark_rce_report.md
```

## Optional Per-Vulnerability Fields

### Vendor confirmed or acknowledged?

- Has vendor confirmed or acknowledged the vulnerability? `No`

### Attack type

- Attack type: `Remote`

### Impact

- Impact: `Code Execution`, `Escalation of Privileges`

### Affected component(s)

```text
usr/libexec/rpcd/esps.sta setremark handler; attacker-controlled name reaches joint_json / para construction and the eval ubus call esps.macfilter modify sink
```

### Attack vector(s)

```text
An authenticated attacker sends `POST /api/esps` with `object="esps.sta"`, `method="setremark"`, and a crafted `name` value containing the literal JSON Unicode single-quote sequence `\u0027;<payload>;#`. The backend wrapper reparses the resulting shell command through `eval`, allowing arbitrary commands to execute as root even when the supplied MAC is invalid for later business logic.
```

### Suggested description of the vulnerability for use in the CVE

```text
H3C Magic NX15 firmware NX15V100R017 contains an authenticated OS command injection vulnerability in the esps.sta.setremark handler that allows remote attackers with a valid administrator session to execute arbitrary OS commands as root via a crafted name parameter sent to POST /api/esps.
```

### Discoverer(s) / Credits

```text
coconut
```

### Additional information

```text
Verified affected version: NX15V100R017. The issue was confirmed to be independent of downstream MAC handling because an exploit request using `mac="NOT_A_MAC"` still opened a root shell on TCP/2476 and proved root execution with `uid=0(root) gid=0(root)` and the marker string `STA_SETREMARK_RCE_OK`.
```

## Submission-Time Fields

These cannot be fully pre-filled in a static Markdown template:

- Security code / CAPTCHA: `<fill manually at submission time>`

## Recommended Preparation Checklist

- Replace the local report-path placeholder in `Reference(s)` with at least one real public URL.
- Perform a final duplicate-CVE search before setting the `already assigned` checkbox.
- Perform a final CNA coverage check before setting the `not in a CNA-covered product` checkbox.
- If you contact the vendor before submission, update the `vendor acknowledged` field accordingly.

## Fast Fill Template

```text
Request type: Report Vulnerability/Request CVE ID
Email: <YOUR_EMAIL>
PGP key: <OPTIONAL>

Number of vulnerabilities / CVE IDs requested: 1
I have verified that this vulnerability is not in a CNA-covered product.: <NEEDS_CONFIRMATION>
I have verified that the vulnerability has not already been assigned a CVE ID.: <NEEDS_CONFIRMATION>

Vulnerability 1
  Vulnerability type: Other or Unknown
  Other vulnerability type: OS command injection / shell metacharacter injection
  Vendor of the product(s): H3C
  Product/version rows:
    - Product: H3C Magic NX15
      Version: Firmware NX15V100R017; verified affected version. Other affected or fixed versions not yet verified.
  Reference(s):
    - report/postauth_esps_sta_setremark_rce_report.md
  Has vendor confirmed or acknowledged the vulnerability?: No
  Attack type: Remote
  Impact: `Code Execution`, `Escalation of Privileges`
  Affected component(s): usr/libexec/rpcd/esps.sta setremark handler; attacker-controlled name reaches joint_json / para construction and the eval ubus call esps.macfilter modify sink
  Attack vector(s): An authenticated attacker sends `POST /api/esps` with `object="esps.sta"`, `method="setremark"`, and a crafted `name` value containing the literal JSON Unicode single-quote sequence `\u0027;<payload>;#`. The backend wrapper reparses the resulting shell command through `eval`, allowing arbitrary commands to execute as root even when the supplied MAC is invalid for later business logic.
  Suggested description of the vulnerability for use in the CVE: H3C Magic NX15 firmware NX15V100R017 contains an authenticated OS command injection vulnerability in the esps.sta.setremark handler that allows remote attackers with a valid administrator session to execute arbitrary OS commands as root via a crafted name parameter sent to POST /api/esps.
  Discoverer(s)/Credits: coconut
  Additional information: Verified affected version: NX15V100R017. The issue was confirmed to be independent of downstream MAC handling because an exploit request using `mac="NOT_A_MAC"` still opened a root shell on TCP/2476 and proved root execution with `uid=0(root) gid=0(root)` and the marker string `STA_SETREMARK_RCE_OK`.

CAPTCHA / Security code: <manual at submit time>
```
