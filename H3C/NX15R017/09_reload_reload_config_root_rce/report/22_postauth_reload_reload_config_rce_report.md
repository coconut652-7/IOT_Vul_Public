# H3C NX15 R017 `reload.reload_config` Authenticated Root Command Injection

## Summary

H3C NX15 Router firmware NX15V100R017 exposes the raw ubus object `reload` through the authenticated `/api/esps` web API. The `reload.reload_config` method concatenates the attacker-controlled `config` parameter into a shell command and executes it with `system()`, allowing an authenticated administrator to execute arbitrary commands as root.

## Vendor and Product

- Vendor: H3C
- Product: NX15 Router
- Affected firmware: NX15V100R017 / R017
- Component: `/api/esps` backend RPC
- Vulnerable object: `reload`
- Vulnerable method: `reload_config`
- Vulnerable parameter: `config`

## Vulnerability Type

- OS command injection
- Suggested CWE: CWE-78
- Attack vector: Remote
- Authentication required: Yes
- Privileges required: Administrator web session
- User interaction required: No

## Impact

An authenticated attacker can execute arbitrary commands as root. Runtime testing confirmed that a crafted `config` value can start a temporary shell service and execute commands with UID 0.

## Technical Details

The web backend `/api/esps` can forward authenticated requests to raw ubus objects, including the object:

```text
reload
```

The `reload_config` method accepts:

```text
config
method
status
```

Reverse analysis of the method handler shows that the `config` parameter is copied into a local buffer and later used to build a shell command:

```c
sprintf(cmd, "/sbin/config_reload %s", config);
system(cmd);
```

There is no strict allowlist, shell escaping, or metacharacter filtering before `system()` is called. Therefore, shell separators or command-substitution syntax in `config` can escape the intended `/sbin/config_reload <config>` call.

The `status` parameter controls whether the reload is executed immediately or queued asynchronously. In the immediate path, the vulnerable command construction reaches `system()` directly.

## Firmware Paths for Audit

The following paths are firmware-internal paths relative to the extracted firmware root filesystem:

- `/www/api`: web API binary that accepts authenticated `/api/esps` requests and forwards them to ubus objects.
- `reload` ubus object provider: runtime ubus provider that registers `reload.reload_config`; locate it in the extracted firmware by searching for `reload_config` and `/sbin/config_reload`.
- `/sbin/config_reload`: command invoked by `reload.reload_config`; the vulnerable handler builds `/sbin/config_reload <config>` and executes it through `system()`.

## Reproduction

Run the included PoC with valid administrator credentials:

```bash
python3 poc/16_postauth_reload_reload_config_rce.py \
  --base http://192.168.8.1 \
  --username admin \
  --password '<admin-password>' \
  --port 2350
```

The PoC:

1. Authenticates to the web interface.
2. Calls `/api/esps` with object `reload` and method `reload_config`.
3. Sends a crafted `config` value containing shell metacharacters.
4. Starts a temporary shell service.
5. Connects to the shell and verifies root execution.

Expected result:

```text
uid=0(root)
```

Manual request shape:

```json
[
  {
    "id": 1,
    "object": "reload",
    "method": "reload_config",
    "param": {
      "config": "network; <command>",
      "method": "reload",
      "status": 1
    }
  }
]
```

## Evidence

- Runtime object enumeration confirmed the `reload.reload_config` method is reachable.
- Reverse analysis identified `sprintf("/sbin/config_reload %s", config)` followed by `system(cmd)`.
- Runtime verification confirmed that a crafted `config` value executes commands as root.

## Attachments

- Report: `report/22_postauth_reload_reload_config_rce_report.md`
- PoC: `poc/16_postauth_reload_reload_config_rce.py`

## Remediation

- Do not pass user-controlled strings to `system()`.
- Replace shell invocation with `execve()` or equivalent argument-vector execution.
- Enforce a strict allowlist of valid configuration names.
- Prevent `/api/esps` from forwarding to raw system ubus objects unless explicitly required.
