# localsend-fork 代码质量 + 安全审查 + 漏洞分析计划（TDD）

> 创建：2026-06-17｜模式：ponytail full（脚手架偷懒 / 审查不偷懒）｜语言：中文
> 计划来源：`/plan` 命令，用户确认「A 全计划（P0→P4）」

## 1. 目标

为 `E:\localsend-fork` 建立一套 Claude Code 组件包，支撑代码质量审查、安全漏洞分析，并遵循 TDD（红测试先行 → 实现修复 → 绿）。

## 2. 项目勘察结论


| 维度          | 现状                                                                                                        |
| ----------- | --------------------------------------------------------------------------------------------------------- |
| 语言/框架       | Flutter 3.38 + Dart（`app/`、`common/`）、Rust FFI（`app/rust`，多为 `frb_generated`）                             |
| 内置 HTTP 服务器 | `receive_controller.dart`（918 行）—— v2 协议参数校验、IP 绑定、session/token 校验，400/403/409 来源                        |
| 已有测试        | `app/test/unit`（含 `file_saver_traversal_test`、`pin_guard_test`、`security_helper_test`）、`common/test/unit` |
| `.claude/`  | 原不存在，本计划新建项目级组件                                                                                           |
| 已知回归        | `send_provider.dart:245` sessionId 遮蔽 → upload 400（已修，**此前无回归测试**）                                        |


## 3. 威胁模型（LocalSend LAN 零配置信任模型）

1. **HTTP 服务端**：参数校验、IP 绑定、session/token 重放、状态机滥用（400/403/409）
2. **路径穿越**：文件保存路径逃逸（`..`、绝对路径、符号链接）
3. **传输层**：自签证书、指纹绑定、mTLS、PIN
4. **令牌/熵**：fileId token、sessionId（UUID v4）、PIN 熵
5. **发现层**：UDP 多播欺骗、设备伪装
6. **依赖供应链**：pub 传递依赖、已知 CVE
7. **密钥泄露**：源码硬编码 secret
8. **Rust FFI**：unsafe/内存（本仓库极少，多为生成代码，不纳入安全审查范围）

## 4. 交付组件清单

### 4.1 Rules（`.claude/rules/`）

- `security.md` — LocalSend 专属安全清单
- `testing-dart.md` — Dart 测试约定 + 覆盖率 80% + 安全测试标签

### 4.2 Skills（`.claude/skills/`）

- `security-audit/SKILL.md` — 端到端审查工作流
- `threat-model/SKILL.md` — STRIDE 模板（可选）

### 4.3 Commands（`.claude/commands/`）

- `security-audit.md` — 执行全量审查
- `vuln-triage.md` — 发现转 TDD 回归测试
- `deps-audit.md` — 依赖审查（可选）

### 4.4 Agents

**复用全局，不新建**：`flutter-reviewer`、`security-reviewer`、`dart-build-resolver`、`tdd-guide`、`code-reviewer`、`silent-failure-hunter`

### 4.5 Hooks（`.claude/settings.json`）

- PreToolUse：secret 扫描 + >800 行文件拦截
- PostToolUse（`*.dart`）：`dart analyze` + 相关测试
- Stop：安全测试套件（防回归）

### 4.6 MCP

保留 `context7`（Dart/Flutter 文档）；`js-reverse`/`playwright` 与 Dart 无关，不引入

### 4.7 Scripts（`scripts/security/`）

- `analyze.ps1` — app + common `dart analyze` 包装
- `test_security.ps1` — 跑 `@Tags(['security'])` 测试
- `secret_scan.ps1` — secret/PII 正则扫描
- `deps_audit.ps1` — `dart pub outdated` + pana

### 4.8 Tests（TDD 红测试先行）

`app/test/unit/security/` + `common/test/unit/security/`：

- `session_binding_test.dart` ⭐ sessionId 遮蔽回归
- `token_replay_test.dart`
- `ip_binding_test.dart`
- `traversal_test.dart`（扩展现有）
- `pin_guard_test.dart`（扩展现有：熵、锁定、时序）
- `fingerprint_binding_test.dart`

### 4.9 Contexts / Examples

- `.claude/contexts/threat-model.md`
- `.claude/examples/tdd-security-pattern.md`

## 5. 执行阶段


| 阶段         | 动作                                                                                             | 验证             |
| ---------- | ---------------------------------------------------------------------------------------------- | -------------- |
| **P0 脚手架** | 建 `.claude/{rules,skills,commands,contexts,examples}` + `settings.json` + `scripts/security/`* | hook 触发、脚本能跑   |
| **P1 红测试** | 逐威胁面写失败测试（含 sessionId 回归）                                                                      | `dart test` 红  |
| **P2 审查**  | 并行跑 security-reviewer + flutter-reviewer + silent-failure-hunter                               | 漏洞清单           |
| **P3 绿化**  | TDD 最小修复；扩展现有实现                                                                                | `dart test` 全绿 |
| **P4 验证**  | `dart analyze` 净、覆盖率 ≥80%（安全模块）、secret_scan PASS                                               | 全部门禁通过         |


## 6. 风险


| 风险                             | 级别  | 缓解                      |
| ------------------------------ | --- | ----------------------- |
| 过度脚手架（ponytail 债）              | M   | 复用全局 agent；标记可选项；短 diff |
| Rust pub-cache 修复脆弱（gal WinRT） | L   | 不纳入审查范围，单独标注            |
| 覆盖率门槛在大应用难达 80%                | M   | 仅安全关键模块要求，其余信息性         |
| 跨设备协议测试无法自动化                   | M   | 单元层 mock HTTP；端到端留手动    |


## 7. 复杂度：中

## 8. 进度跟踪

- [x] P0 脚手架
- [x] P1 红测试（session_binding 回归）
- [x] P2 审查（security-reviewer + silent-failure-hunter）
- [x] P3 绿化（C1/H4/H6）
- [x] P4 验证（analyze 0 error / secret CLEAN / 测试全绿）

