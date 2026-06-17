# Dart/Flutter 测试规则（localsend-fork）

> 扩展全局 `rules/ecc/common/testing.md`，补充 Dart 工具链细节。

## 框架

- `package:test`（纯 Dart 逻辑）+ `flutter_test`（widget）
- mock：`mockito` 5.5.0 + `build_runner`（`dart run build_runner build`）
- 约定见根 `CONTRIBUTING.md`

## 目录

| 包 | 测试根 |
|---|---|
| `app` | `app/test/unit/...` 镜像 `app/lib/...` 路径 |
| `common` | `common/test/unit/...` |
| **安全** | `app/test/unit/security/`、`common/test/unit/security/`，加 `@Tags(['security'])` |

## 运行

```powershell
# 全量分析
scripts/security/analyze.ps1
# 仅安全标签测试
scripts/security/test_security.ps1
# 单文件
cd app; dart test test/unit/security/session_binding_test.dart
```

## AAA + 描述命名

```dart
test('rejects upload when sessionId mismatches recipient session', () {
  // Arrange ...
  // Act ...
  // Assert ...
});
```

## 覆盖率门槛

- 安全关键模块（`receive_controller`、`send_provider`、`file_path_helper`、`pin_guard`、`security_helper`、`rhttp` 包装）：≥80%
- 其余：信息性，不阻塞

## TDD 顺序（强制）

1. 先写红测试（`dart test` 失败）
2. 最小实现转绿
3. 重构
4. 加 `@Tags(['security'])` 守护回归
