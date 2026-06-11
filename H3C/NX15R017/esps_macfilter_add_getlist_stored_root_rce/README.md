# `esps.macfilter.add` 到 `getlist` 存储型 root RCE

## 提交类型

- 分类：CNVD
- 产品：H3C NX15 路由器
- 影响版本：NX15V100R017 / R017
- 主报告：`report/postauth_esps_macfilter_getlist_rce_report.md`
- PoC：`poc/postauth_esps_macfilter_getlist_rce.py`

## 分类说明

该问题不是单次请求即时执行，而是先写入恶意配置，再由列表读取路径触发 `eval`，属于存储型 root 命令执行链，适合作为 CNVD 提交。

