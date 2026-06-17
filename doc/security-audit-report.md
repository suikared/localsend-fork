# localsend-fork 安全审查 + 漏洞分析报告

> 日期：2026-06-17｜方法：security-reviewer + silent-failure-hunter 并行审查 + TDD 修复｜模式：ponytail lite

## 0. 门禁结果（P4 验证）

| 门禁 | 结果 |
|---|---|
| `dart analyze`（app + common） | ✅ 0 error |
| 安全/回归测试 | ✅ 全绿（session_binding 2、safeProgress 3、traversal 9、common 全 11） |
| 密钥扫描 `secret_scan.ps1` | ✅ CLEAN |
| 已修项回归 | ✅ 无回归 |

---

## 1. 本轮已修复（TDD）

| ID | 文件:行 | 问题 | 修复 | 测试 |
|---|---|---|---|---|
| **H4** | `app/lib/util/rhttp.dart:62` | 空文件上传时 `curr/total` 除零；`Content-Length` 缺失空指针 | 抽 `safeProgress(curr,total)` 纯函数，total=0 返回 1.0 | `app/test/unit/util/rhttp_progress_test.dart`（3 绿）|
| **C1** | `common/lib/src/isolate/parent/actions.dart:245` | isolate 流错误路径只 `addError`，未 `cancel/close` → 订阅泄漏 + stream 永不结束 | 对称补 `subscription.cancel(); controller.close();` | private 函数不可独立测；靠 common 全测试守护无回归 |
| **H6** | `app/lib/util/native/file_saver.dart:241,246` | `throw 'Path traversal detected'`（字符串）在 generic catch 中丢类型/栈 | 定义 `PathTraversalException implements Exception` | 现有 `file_saver_traversal_test.dart`（`throwsA(anything)`）守护，9 绿 |
| **H2-sec** | `pin_guard.dart` / `common.dart` / `server_state.dart` / `web_send_state.dart` | PIN 计数跨会话永久累积、成功不归零、锁定后无恢复（"只错一次就锁"=历史累计） | `evaluatePinAttempt` 返回 `newAttempts`（成功=0 重置）；新增 `isWithinLockWindow` + `pinCooldown`(30s) TTL；`ServerState`/`WebSendState` 加 `pinLockedAt` | `pin_guard_test.dart` 新增 7 测试（成功重置/累计/TTL/legacy 解锁）；30 测试全绿 |

> 注：C1 受测试可达性约束（`_convertResponseToStream` 文件私有、`IsolateConnector` 注入）无法低成本单测，标注为对称防御修复。

---

## 2. 待决策 Backlog（协议/设计变更，需评估兼容性后处理）

### CRITICAL

| ID | 文件:行 | 问题 | 建议 |
|---|---|---|---|
| **C1-sec** | `app/lib/util/rhttp.dart:77` | 发送端 `verifyCertificates: false`，MITM 可拦截 prepareUpload/upload（PIN 走 query 明文） | 默认启用证书校验并 pin 到对端 fingerprint，仅首次未信任设备降级到用户确认 |
| **C2-sec** | `receive_controller.dart:461` | prepareUpload 回显完整 sessionId + 全部 file token，无 PIN 时 LAN 任意主机可抢会话拿 token | token 仅在用户接受后下发；prepareUpload 只返回 sessionId |
| **C3-sec** | `receive_controller.dart:497,503` | v1 `/upload` 不校验 sessionId，仅 fileId+token；token 一旦泄露可越权写入 | v1 也把 token 绑定到当前 session；token 随 session 结束失效 |
| **C4-sec** | `receive_controller.dart:540` | `/upload` 不校验声明文件大小，可流式写入超大数据耗尽磁盘 | 校验 `Content-Length <= 声明 size + 容差`，超限返回 413 |
| **C5-sec** | `persistence_provider.dart:438` | PIN 明文存 SharedPreferences，root/备份可直读 | 改 `flutter_secure_storage` + 盐值哈希 |

### HIGH

| ID | 文件:行 | 问题 | 建议 |
|---|---|---|---|
| H1-sec | `receive_controller.dart:224` | PIN 仅在 prepareUpload 检查，upload/cancel/show 无 PIN | PIN 与 session 绑定，所有写状态端点基于"已过 PIN 的 session" |
| H2-sec | `common.dart:25,40` + `server_state.dart:16` | PIN 锁定按 IP 计数：NAT 误伤、IPv6 /64 可绕过、无 TTL 无限累积 | **核心已修**（成功重置 + 30s TTL，见 §1 H2-sec）；剩余：按 IP+fingerprint 联合计数 + IPv6 /64 聚合 |
| H3-sec | `pin_guard.dart:14` | `constantTimeEquals` 长度差提前返回（长度泄露），注释自称恒定时间 | 先 HMAC-SHA256 再定长比较，或文档明确仅适用固定长度 PIN |
| H4-sec | `receive_controller.dart:753` | `/show` 无来源 IP 限制，token 明文持久化，信任 body `args` 加载文件选择（SSRF/数据外泄） | `/show` 限定 loopback/本机网卡；args 白名单校验 |
| H5-sec | `receive_controller.dart:188` + `multicast_discovery.dart:58` | 直接信任 body 声明的 fingerprint/alias（设备伪装/社工） | UI 展示前标注"未验证"，仅 TLS 握手证书指纹标"已验证" |
| H6-sec | `receive_controller.dart:720` | v1 cancel 无 sessionId 校验，LAN 任意主机可取消他人会话（DoS） | v1 也要求 IP 一致 + 近期通信校验 |
| **H2-sf** | `upload_isolate.dart:131` | 裸 `catch (e)` 吞 Error + 丢栈，上传失败日志只剩字符串 | `on Exception catch (e, st)` + 传递 stackTrace |
| **H3-sf** | `rhttp.dart:16-39` | RhttpWrapper 对 4xx/5xx 不校验直接返回 body，cancel/register/info 失败被当成功 | 统一对 `statusCode >= 400` 抛 `RhttpStatusCodeException` 或设 `throwOnStatusCode: true` |
| **H5-sf** | `file_saver.dart:199` | 裸 `catch (_)` 丢上下文；清理分支失败留半截污染文件 | `catch (e, st)` + close/delete 独立 try；清理失败标 history |

### MEDIUM（精选，详见审查原始输出）

| ID | 文件:行 | 问题 |
|---|---|---|
| M1-sf | `receive_controller.dart:765` | `/show` body 处理 fire-and-forget，异常彻底丢失 |
| M2-sf | `receive_controller.dart:839` / `send_provider.dart:524` | cancel 通知失败仅 warning，本地照样关闭 → 幽灵 session |
| M3-sf | `simple_server.dart:15` | handler `void Function`，异步异常无人接 |
| M4-sf | `file_saver.dart:118` | `setLastModified` 空 `catch (_)` 静默吞错 |
| M5-sf | `send_provider.dart:243` | `response.response!` 强制解包，协议异常翻译成无意义报错 |
| M1-sec | `receive_controller.dart:505,512` | 错误日志回显期望 sessionId/fileId（信息泄露） |
| M2-sec | `receive_controller.dart:279` | `saveToGallery` 仅检 `/`，`\`/URL 编码可绕（file_saver 有二次校验兜底） |
| M3-sec | `receive_controller.dart:252` | 日志输出 sessionId/destinationDir（信息泄露） |
| M4-sec | `alias_generator.dart:6` | 用非安全 `Random()`（仅别名，影响有限）→ 改 `Random.secure()` |
| M5-sec | `security_helper.dart:23` | 自签证书 CN 固定 "LocalSend User"，10 年期 |
| M6-sec | `multicast_discovery.dart:131` | UDP 多播响应无速率限制（放大/反射） |

### LOW
L1-sf PIN 校验前未消费 body｜L2-sf `/show` 总返回 200｜L3-sf `parent_isolate_provider.dart:50` `throw 'Not initialized'` 字符串｜L4-sf `_finish` session 已移除时静默 return

---

## 3. 复合攻击链（Backlog 修完后才断链）

1. 攻击者入同 LAN，UDP 多播嗅探受害者 alias/fingerprint（H5-sec）
2. 默认无 PIN → prepareUpload 拿 sessionId + 全部 token（C2-sec）
3. v1 `/upload` 越权写文件（C3-sec），大小不校验耗尽磁盘（C4-sec）
4. `/show` 唤起窗口塞恶意脚本路径（H4-sec）

---

## 4. 不可自动化（手动测试清单）

跨设备协议交互需手动：
- [ ] 配 PIN 设备 A→B：prepareUpload 三次错 PIN 触发锁定
- [ ] IPv6 /64 轮换尝试绕过锁定（H2-sec）
- [ ] 关闭校验（C1-sec）下网关抓包 prepareUpload 验证明文 PIN
- [ ] v1 对端 token 泄露后越权 upload（C3-sec）

---

## 5. 正面发现（已有防御）

- `file_saver.dart` `normalize + isWithin + basename` 双重穿越防护（已修单段 `..` 历史 bug）
- `receive_controller.dart:68` `_verifiedPeerFingerprint` quickSaveFromFavorites 强制 TLS 证书指纹校验
- `receive_controller.dart:655` `isExecutableFile` 阻止自动打开可执行文件
- sessionId/token/fileId 均用 `Uuid().v4()`（密码学随机源）

---

## 6. 本轮交付物

- `.claude/`：rules（security、testing-dart）、skills（security-audit、threat-model）、commands（security-audit、vuln-triage、deps-audit）、contexts、examples、settings.json + hooks
- `scripts/security/`：analyze、test_security、secret_scan、deps_audit
- 测试：`common/test/unit/security/session_binding_test.dart`、`app/test/unit/util/rhttp_progress_test.dart`
- 计划：`doc/security-audit-plan.md`；报告：本文件

## 7. 下一步建议

Backlog 中 **C1-sec / C2-sec / C3-sec** 是复合攻击链的关键节点，建议优先评审（涉及 v1/v2 协议兼容性，需产品决策）。可逐项用 `/vuln-triage` 转 TDD 红测试再修。
