# localsend-fork 安全规则

> 扩展全局 `rules/ecc/common/security.md`，补充 LocalSend LAN 文件传输场景。

## 信任模型

LocalSend 在**同局域网零配置**下工作，默认假设：同网段设备半可信。
所有跨信任边界输入（HTTP 请求、UDP 发现包、接收文件名/路径、PIN）必须显式校验。

## 强制检查（提交前）

- [ ] 无硬编码 secret（API key / 密码 / 私钥 / 证书指纹写死）
- [ ] HTTP 服务端所有端点校验 `fileId` / `token` / `sessionId` / 来源 IP
- [ ] 文件保存路径不允许 `..`、绝对路径、符号链接逃逸（见 `file_path_helper`、`file_saver_traversal` 测试）
- [ ] token / sessionId / PIN 来源为安全随机（UUID v4 / `Random.secure()`），非 `Random()`
- [ ] PIN 比较使用恒定时间（`pin_guard.constantTimeEquals`），防时序侧信道
- [ ] TLS：自签证书 + 指纹绑定；`verifyCertificates` 关闭仅限 mTLS 已校验客户端证书场景
- [ ] 错误信息不泄露内部状态（sessionId 期望值、文件路径绝对值、token 片段）

## LocalSend v2 协议要点

- `/api/localsend/v2/upload`：`sessionId`、`fileId`、`token` 三参缺一即 400
- `sessionId` 必须等于接收方当前 session，否则 403
- `token` 必须匹配 `receiveState.files[fileId].token`，否则 403
- 来源 IP 必须 = `receiveState.sender.ip`，否则 403

## 安全 bug 响应

发现安全问题时：停止 → `security-reviewer` agent → CRITICAL 先修 → 同类扫描 → 加 TDD 回归测试（`app/test/unit/security/`，`@Tags(['security'])`）。

## 已知回归（务必有测试守护）

- `send_provider.dart` sessionId 遮蔽 → upload 400（2026-06 修复）：`session_binding_test.dart` 守护
