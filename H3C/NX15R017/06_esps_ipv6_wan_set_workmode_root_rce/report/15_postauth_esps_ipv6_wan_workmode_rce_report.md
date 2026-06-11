# H3C NX15 R017 `esps.ipv6.wan.set` `workMode` Authenticated Root Command Injection

## Summary

H3C NX15 Router firmware NX15V100R017 contains an authenticated command injection vulnerability in the `/api/esps` RPC object `esps.ipv6.wan`, method `set`. The `workMode` parameter is used in unsafe shell expressions and later reaches an `eval` assignment, allowing arbitrary command execution as root.

## Vendor and Product

- Vendor: H3C
- Product: NX15 Router
- Affected firmware: NX15V100R017 / R017
- Component: `/api/esps` backend RPC
- Vulnerable object: `esps.ipv6.wan`
- Vulnerable method: `set`
- Vulnerable parameter: `workMode`

## Vulnerability Type

- OS command injection
- Suggested CWE: CWE-78
- Attack vector: Remote
- Authentication required: Yes
- Privileges required: Administrator web session
- User interaction required: No

## Impact

An authenticated attacker can execute arbitrary commands as root. Runtime testing confirmed that a crafted `workMode` value can start a root shell and execute commands with UID 0.

## Technical Details

The backend script reads the JSON value into `param_workMode` and uses it in an unquoted shell test:

```sh
json_get_var param_workMode workMode
if [ ${param_workMode} != "dynamic" ];then
    result=9730
    return_json ${result}
    return
fi
```

The same attacker-controlled value later reaches:

```sh
eval set_workmode${idx}="${param_workMode}"
```

Because `param_workMode` is not safely quoted and later enters `eval`, shell command substitution inside the parameter is executed by the shell. A payload that preserves the expected `dynamic` token while adding command substitution can pass the intended branch behavior and trigger command execution.

## Firmware Paths for Audit

The following paths are firmware-internal paths relative to the extracted firmware root filesystem:

- `/www/api`: web API binary that accepts authenticated `/api/esps` requests and forwards them to ubus objects.
- `/usr/libexec/rpcd/esps.ipv6.wan`: vulnerable backend script; the `set` branch reads `workMode`, performs an unsafe shell test, and later reaches `eval`.
- `/etc/config/network`: related UCI network configuration file affected by WAN/IPv6 WAN settings.

## Reproduction

Run the included PoC with valid administrator credentials:

```bash
python3 poc/13_postauth_esps_ipv6_wan_workmode_rce.py \
  --base http://192.168.8.1 \
  --username admin \
  --password '<admin-password>' \
  --port 2323 \
  --cleanup
```

The PoC:

1. Authenticates to the web interface.
2. Calls `/api/esps` with object `esps.ipv6.wan` and method `set`.
3. Sends a crafted `workMode` value containing shell command substitution.
4. Starts a temporary shell service.
5. Connects to the shell and verifies root execution.

Expected result:

```text
uid=0(root)
```

## Evidence

- Static analysis identified an unquoted shell test and an `eval` assignment using `workMode`.
- Runtime verification confirmed command execution through the `workMode` parameter.
- The spawned shell runs with root privileges.

## Attachments

- Report: `report/15_postauth_esps_ipv6_wan_workmode_rce_report.md`
- PoC: `poc/13_postauth_esps_ipv6_wan_workmode_rce.py`

## Remediation

- Quote all shell variables used in test expressions.
- Remove `eval` from the IPv6 WAN backend script.
- Enforce a strict allowlist for `workMode` values.
- Reject any value outside the expected enum before using it in shell logic.
