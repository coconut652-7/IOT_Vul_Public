# H3C NX15 R017 Exposed `service.add` Authenticated Root Command Execution

## Summary

H3C NX15 Router firmware NX15V100R017 exposes the raw ubus object `service` through the authenticated `/api/esps` web API. The `service.add` method allows callers to register a new procd service instance and define the service command. Because the service manager runs with root privileges, an authenticated web administrator can execute arbitrary commands as root.

## Vendor and Product

- Vendor: H3C
- Product: NX15 Router
- Affected firmware: NX15V100R017 / R017
- Component: `/api/esps` backend RPC
- Exposed object: `service`
- Exposed method: `add`

## Vulnerability Type

- Improper exposure of dangerous system function
- Command execution through exposed service-management RPC
- Suggested CWE: CWE-749 Exposed Dangerous Method or Function
- Attack vector: Remote
- Authentication required: Yes
- Privileges required: Administrator web session
- User interaction required: No

## Impact

An authenticated attacker can register a service instance that executes attacker-controlled commands as root. Confirmed impact includes starting a root shell service and executing commands with UID 0.

## Technical Details

Runtime object enumeration confirmed that the raw ubus object `service` exposes service-management methods including:

```text
service.add
service.set
service.delete
service.list
service.update_start
service.update_complete
```

The authenticated `/api/esps` backend can forward requests to this object. The `service.add` method accepts service metadata and instance definitions, including an attacker-controlled command array:

```json
{
  "name": "pocsvc",
  "script": "/bin/true",
  "instances": {
    "instance1": {
      "command": [
        "/bin/sh",
        "-c",
        "id >/tmp/service_rce_marker"
      ],
      "respawn": {
        "threshold": 3600,
        "timeout": 5,
        "retry": 1
      }
    }
  }
}
```

Because the service manager executes registered commands as root, exposing this method to the web management API crosses a critical trust boundary.

## Firmware Paths for Audit

The following paths are firmware-internal paths relative to the extracted firmware root filesystem:

- `/www/api`: web API binary that accepts authenticated `/api/esps` requests and forwards them to ubus objects.
- `service` ubus object provider: runtime ubus provider exposing `service.add`; locate it in the extracted firmware by searching for the object name `service` and method name `add`.
- `/sbin/procd`: service manager that processes registered service instances.
- `/bin/sh`: command interpreter used by the PoC service command.

## Reproduction

Run the included PoC with valid administrator credentials:

```bash
python3 poc/18_postauth_service_add_rce.py \
  --base http://192.168.8.1 \
  --username admin \
  --password '<admin-password>' \
  --port 2361
```

The PoC:

1. Authenticates to the web interface.
2. Calls `/api/esps` with object `service` and method `add`.
3. Registers a service instance whose command starts a temporary shell service.
4. Connects to the shell and verifies root execution.

Expected result:

```text
uid=0(root)
```

## Evidence

- Runtime object enumeration confirmed that `service.add` is present.
- Runtime testing confirmed that `/api/esps` can invoke `service.add` using an authenticated web session.
- The registered command runs as root and can start a root shell.

## Attachments

- Report: `report/24_postauth_service_add_rce_report.md`
- PoC: `poc/18_postauth_service_add_rce.py`

## Remediation

- Prevent `/api/esps` from forwarding requests to the raw `service` ubus object.
- Add a strict object and method allowlist for web-exposed RPC.
- Deny service creation, service update, and arbitrary command arrays from remote web callers.
- Enforce backend authorization checks based on caller identity and origin, not only web login state.
