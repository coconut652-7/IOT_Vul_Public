# `uci.add` 与 `reload.reload_config` 配置污染 root 链

## 提交类型

- 分类：CNVD
- 产品：H3C NX15 路由器
- 影响版本：NX15V100R017 / R017
- 主报告：`report/postauth_uci_reload_smartwaretrack_exec_chain.md`
- PoC：`poc/postauth_uci_smartwaretrack_exec_rce.py`

## 分类说明

该问题利用原始 UCI 写接口污染 `smartwaretrack` 配置，再通过合法 reload 流程触发后端执行，属于多对象组合链，适合作为 CNVD 深度材料提交。

