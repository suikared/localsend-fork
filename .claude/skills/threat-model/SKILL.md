---
name: threat-model
description: LocalSend LAN 文件传输 STRIDE 威胁建模模板。
---

# Threat Model（LocalSend）

信任模型：同局域网设备半可信，零配置。

## STRIDE

| 类别 | 资产 / 攻击面 | 缓解 |
|---|---|---|
| Spoofing | 设备伪装、中间人 | 自签证书 + SHA-256 指纹绑定、mTLS、PIN |
| Tampering | 文件内容 / 路径 | 路径白名单、token 绑定 fileId |
| Repudiation | 发送/接收否认 | 接收历史 `receive_history`、日志 |
| Info Disclosure | 错误信息泄露、文件名 | 错误信息脱敏、不回显绝对路径/sessionId 期望值 |
| DoS | 多播泛洪、连接耗尽 | 速率限制（待评估）、session 状态机 |
| Elevation | 越权写文件 | 保存路径限定下载目录，禁穿越 |

## 不可自动化部分

跨设备协议交互：单元层 mock HTTP 覆盖校验逻辑，端到端留手动测试清单（见 report）。
