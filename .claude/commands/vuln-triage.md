---
description: 把一个漏洞发现转成 TDD 回归红测试
allowed-tools: Read, Write, Edit, Bash, Grep
---

# /vuln-triage

入参 `$ARGUMENTS`：漏洞描述或文件:行。

步骤：
1. 定位受影响的校验/逻辑函数
2. 在 `app/test/unit/security/`（或 common）写 `@Tags(['security'])` 失败测试（AAA 结构）
3. `dart test` 确认红
4. 最小修复转绿
5. `scripts/security/test_security.ps1` 守护
