# TDD 安全测试范例（localsend-fork）

模式：先红（定义期望的安全行为，当前实现应违反），再绿（最小修复）。

## 红测试示例

```dart
@Tags(['security'])
library;

import 'package:test/test.dart';
// import 被测函数 ...

void main() {
  group('upload session binding', () {
    test('rejects upload when sessionId does not match recipient session', () {
      // Arrange: recipient session = 'abc', 请求带 sessionId='xyz'
      // Act: 调用校验
      // Assert: 返回 403 'Invalid session id'，不进入文件写入
    });
  });
}
```

## 守护已知回归

`send_provider.dart` 曾因局部变量遮蔽 `sessionId`，导致 upload 漏带 sessionId → 400。
对应 `app/test/unit/security/session_binding_test.dart` 必须覆盖：upload 请求 query 含正确 remoteSessionId。
