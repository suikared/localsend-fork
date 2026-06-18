# C1-sec 修复计划：握手期证书 pinning

> 日期：2026-06-17｜关联：`doc/security-audit-report.md` §2 C1-sec｜模式：TDD

## 问题定性（代码级，修正报告）

报告原述"rhttp.dart `verifyCertificates:false`"只覆盖 isolate 文件上传路径。
真正的 PIN 路径在 Rust `LsHttpClientV2`（`core/src/http/client/v2.rs`）：

- `danger_accept_invalid_certs(true)`（mod.rs:159）握手期放行任意证书；
- 已有事后公钥校验 `verify_cert_from_res`（mod.rs:169），但 **Dart 永远传 `publicKey: null`**（send_provider.dart:156 `// TODO`）→ pinning 失效；
- 即便启用，事后校验在**响应**到达后执行，**请求**里的 PIN（v2.rs:134 query）/文件字节（v2.rs:230 body）早已发给 MITM。

**结论**：只有握手期校验（rustls 自定义 `ServerCertVerifier`，pin 到期望公钥）才能在 PIN 发出前拒绝 MITM。

## 可行性（已验证）

- reqwest 0.13 `tls_backend_preconfigured` 对 `Option<rustls::ClientConfig>` 向下转型（client.rs:2172）→ `.use_preconfigured_tls(Some(cfg))` 接受自定义 ClientConfig；
- 仓库已有自定义 rustls 校验器范式：`core/src/http/server/client_cert_verifier.rs`；
- 复用已测试的 `crypto::cert::verify_cert_from_der`，核心逻辑不变，仅改触发时机（事后→握手期）。

## 分阶段

| Phase | 内容 | 可测性 |
|---|---|---|
| **1** | `core/src/crypto/pinned_server_cert_verifier.rs`：`PinnedServerCertVerifier` impl `ServerCertVerifier`，`verify_server_cert` 委托 `verify_cert_from_der(cert, expected_pubkey)`；签名校验委托 rustls 自由函数 | Rust `#[test]`（匹配/失配/TOFU/过期） |
| **2** | `core/src/http/client/mod.rs`：`create_reqwest_client` 支持 `Option<expected_pubkey>`，构造带校验器的 ClientConfig，喂给 reqwest；prepare_upload/upload 用按目标的 pinned client | 集成：mitm 证书被握手期拒绝 |
| **3** | Dart：discovery/register 捕获对端公钥存 `Device`；透传到 prepareUpload/upload，替换 `publicKey: null` | Dart 单测守护透传 |
| **4** | frb 重生成、build、analyze + security 测试绿、重打 Windows 包；更新 report 标记 C1-sec 已修 | 门禁 |

## 信任模型 / Bootstrap

- 首次发现（register/info）对端公钥未知 → TOFU（仅校验时效+自签名，不发 secret）。PIN/token 均不在该步。
- 后续 prepare_upload/upload（带 PIN/文件）公钥已知 → 必须握手期 pin。
- discovery 不发 secret，保持现有 `danger_accept_invalid_certs` 不变，最小风险。

## 不做（YAGNI）

- 不做全量 mTLS（接收方请求客户端证书）——另立议题。
- 不改 discovery 传输层。

## 状态（2026-06-17）

**已完成 —— PIN 凭据保护（攻击链基石）：**

- Phase 1：`core/src/crypto/pinned_server_cert_verifier.rs`，握手期 pin 到 `SHA-256(DER)`（LocalSend 指纹），复用 `verify_cert_from_der` 的时效+签名校验。6 单测绿（匹配/失配/大小写冒号归一/TOFU/过期/同值）。
- Phase 2：`core/src/http/client/mod.rs::build_pinned_reqwest_client` 经 `use_preconfigured_tls(Some(ClientConfig))` 注入校验器；`v2.rs` `prepare_upload`/`upload` 在指纹已知时握手期 pin，事后校验已移除（冗余）。
- Phase 3：`send_provider.dart` `prepareUpload` 传 `target.fingerprint`（经既有 `publicKey` 形参，**无需 frb 重生成**）。

锚点选**指纹**而非公钥：`Device.fingerprint` 在 prepareUpload 时恒存在（multicast 即提供），无需改 Device 模型或加 HTTPS 往返。

**留后续 —— 文件内容机密性（用户决策 C）：**

文件字节上传走 common isolate 的 **rhttp** 路径（`IsolateHttpUploadAction` → `httpUploadProvider` → rhttp `verifyCertificates:false`），rhttp **无法 pin**。MITM 仍可被动读取上传文件内容。

PIN pinning 已断掉主动攻击链（凭据窃取 → 发方冒充 → 恶意文件注入）。文件内容被动窃听留待后续，候选方案：
- A：上传改走 Rust `RsHttpClient.upload`（已 pin），弃 isolate rhttp 上传。
- B：isolate 新增 dart:io pinning `CustomHttpClient`（`badCertificateCallback` 复用 `calculateHashOfCertificate` + host→fingerprint 注册表）。

**2026-06-18 已修（方案 B）：** 新增 `common/lib/src/task/upload/pinned_upload_client.dart`——上传改走 dart:io `HttpClient`，`badCertificateCallback` 计算 `SHA-256(cert.der)` 与 `target.fingerprint` 常量时间比对（冒号/大小写归一），失配握手即拒；mTLS 客户端证书复用 `StoredSecurityContext`。`HttpUploadService` 改工厂注入、每上传一例 pinned client。纯函数 `fingerprintOfCertDer`/`fingerprintMatches` 6 单测守护（`common/test/unit/security/pinned_upload_client_test.dart`）。端到端 TLS 握手手动验证见报告 §4。

## 风险

- PIN 路径现严格校验证书（时效+签名+指纹），此前接受任意证书。与证书时效异常/非标准自签的对端可能握手失败（LocalSend 自签证书正常，不受影响）。

