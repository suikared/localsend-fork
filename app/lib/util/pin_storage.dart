import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:localsend_app/util/pin_guard.dart';

/// Production PBKDF2-HMAC-SHA256 iteration count for the receive PIN.
///
/// ponytail: 4 位 PIN 离线爆破成本 ≈ 10^4 × iter；iter=250000 抬到分钟级。
/// 手机端单次校验 ~30–60ms，prepareUpload 一次会话仅校验一次，可接受。
/// 需要更强可上调（旧记录仍可用——迭代数随记录存储）；注意移动端延迟。
const int kPinHashIterations = 250000;

/// Prefix that distinguishes a hashed PIN record from a legacy plaintext PIN,
/// so pre-fix stored values can be detected and migrated instead of mistaken
/// for records.
const String _kRecordPrefix = 'pbkdf2';

/// A salted PBKDF2 hash of the receive PIN, persisted instead of the plaintext.
class PinHashRecord {
  final String salt; // lowercase hex
  final String hash; // uppercase hex
  final int iterations;

  const PinHashRecord({
    required this.salt,
    required this.hash,
    required this.iterations,
  });

  /// Encodes as `pbkdf2$<iterations>$<saltHex>$<hashHex>`.
  String encode() => '$_kRecordPrefix\$$iterations\$$salt\$$hash';

  /// Decodes an encoded record.
  ///
  /// Returns null for null input, malformed input, or a value without the
  /// record prefix (e.g. a legacy plaintext PIN such as `1234`).
  static PinHashRecord? tryDecode(String? encoded) {
    if (encoded == null) return null;
    final parts = encoded.split(r'$');
    if (parts.length != 4) return null;
    if (parts[0] != _kRecordPrefix) return null;
    final iterations = int.tryParse(parts[1]);
    if (iterations == null || iterations <= 0) return null;
    final salt = parts[2];
    final hash = parts[3];
    if (salt.isEmpty || hash.isEmpty) return null;
    return PinHashRecord(salt: salt, hash: hash, iterations: iterations);
  }
}

/// Hashes a plaintext PIN into a [PinHashRecord]. A random 16-byte salt is
/// generated when [salt] (hex) is omitted.
PinHashRecord hashPin(String plaintext, {String? salt, int iterations = kPinHashIterations}) {
  final saltBytes = salt != null ? Uint8List.fromList(hexDecode(salt)) : _randomBytes(16);
  final derived = _pbkdf2(utf8.encode(plaintext), saltBytes, iterations, 32);
  return PinHashRecord(
    salt: hexEncode(saltBytes),
    hash: hexEncode(derived).toUpperCase(),
    iterations: iterations,
  );
}

/// Verifies a plaintext against a record.
///
/// Returns false for a null record (nothing to match). Callers gate the
/// "no PIN configured" case separately — `verifyPin` never means "allowed".
bool verifyPin(String? plaintext, PinHashRecord? record) {
  if (record == null) return false;
  final derived = _pbkdf2(
    utf8.encode(plaintext ?? ''),
    Uint8List.fromList(hexDecode(record.salt)),
    record.iterations,
    32,
  );
  return constantTimeEquals(hexEncode(derived).toUpperCase(), record.hash);
}

// --- PBKDF2-HMAC-SHA256 (RFC 8018) ---

List<int> _pbkdf2(List<int> password, List<int> salt, int iterations, int keyLength) {
  final hmac = Hmac(sha256, password);
  final blockCount = (keyLength + 31) ~/ 32;
  final out = <int>[];
  for (var i = 1; i <= blockCount; i++) {
    var u = hmac.convert([...salt, ..._int32Bytes(i)]).bytes;
    final t = List<int>.from(u);
    for (var j = 1; j < iterations; j++) {
      u = hmac.convert(u).bytes;
      for (var k = 0; k < t.length; k++) {
        t[k] ^= u[k];
      }
    }
    out.addAll(t);
  }
  return out.sublist(0, keyLength);
}

List<int> _int32Bytes(int i) => [(i >> 24) & 0xff, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff];

Uint8List _randomBytes(int length) {
  final rng = Random.secure();
  return Uint8List.fromList(List<int>.generate(length, (_) => rng.nextInt(256)));
}

String hexEncode(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

List<int> hexDecode(String hex) {
  if (hex.length % 2 != 0) {
    throw FormatException('odd-length hex string');
  }
  final out = <int>[];
  for (var i = 0; i < hex.length; i += 2) {
    out.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return out;
}
