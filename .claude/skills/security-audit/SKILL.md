---
name: security-audit
description: localsend-fork 端到端代码质量 + 安全审查 + 漏洞分析工作流，遵循 TDD。
---

# Security Audit（localsend-fork）

## 何时用

对本仓库做安全审查、漏洞分析，或修安全 bug 后补回归测试。

## 工作流

1. **勘察**：读 `.claude/contexts/threat-model.md` 确认范围
2. **静态**：`scripts/security/analyze.ps1`（dart analyze）+ `secret_scan.ps1`（密钥）
3. **TDD 红**：对每个威胁面在 `app/test/unit/security/` 写失败测试
4. **并行 agent 审查**：security-reviewer + flutter-reviewer + silent-failure-hunter
5. **绿化**：最小修复，`scripts/security/test_security.ps1` 转绿
6. **验证**：analyze 净、覆盖率、secret 扫描 PASS
7. **报告**：汇总到 `doc/security-audit-report.md`

## 关键文件

| 文件 | 关注点 |
|---|---|
| `app/lib/provider/network/server/controller/receive_controller.dart` | HTTP 参数校验、IP/session/token 绑定 |
| `app/lib/provider/network/send_provider.dart` | sessionId 遮蔽回归 |
| `app/lib/util/file_path_helper.dart` | 路径穿越 |
| `app/lib/util/pin_guard.dart` | PIN 恒定时间、熵 |
| `app/lib/util/security_helper.dart` | 通用安全原语 |
| `app/lib/util/rhttp.dart` | TLS / 客户端证书 |

## 输出

漏洞按 CRITICAL / HIGH / MEDIUM / LOW 分级（见全局 `code-review.md`）。CRITICAL/HIGH 必须先修且加回归测试。
