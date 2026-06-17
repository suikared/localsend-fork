---
description: 执行 localsend-fork 全量代码质量 + 安全审查（TDD）
allowed-tools: Bash, Read, Grep, Glob, Edit, Write, Agent
---

# /security-audit

调用 `security-audit` skill 执行：
1. 静态分析 `scripts/security/analyze.ps1`
2. 密钥扫描 `scripts/security/secret_scan.ps1`
3. 并行 agent：security-reviewer + flutter-reviewer + silent-failure-hunter
4. 把 CRITICAL/HIGH 转为 `app/test/unit/security/` 红测试
5. 最小修复转绿
6. 汇总 `doc/security-audit-report.md`

参数：`$ARGUMENTS`（可指定文件/范围，留空则全仓库）
