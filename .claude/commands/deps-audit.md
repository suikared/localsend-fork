---
description: 依赖供应链审查（pub outdated + pana + 已知 CVE 检索）
allowed-tools: Bash, WebSearch, Read
---

# /deps-audit

执行 `scripts/security/deps_audit.ps1`，对 app + common：
1. `dart pub outdated` 找过时包
2. `dart pub deps` 拓扑
3. 对安全相关包（rhttp/flutter_rust_bridge/shelf 等）检索已知 CVE
4. 汇总到 `doc/security-audit-report.md` 依赖章节
