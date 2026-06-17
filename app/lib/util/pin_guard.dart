/// Pure, HTTP-free PIN-evaluation helpers.
///
/// Extracted from `checkPin` so the security-critical logic (constant-time
/// comparison, attempt counting, lock window) is unit-testable without faking
/// `HttpRequest`.
library;

/// Number of failed attempts before a client is locked out.
const int maxPinAttempts = 3;

/// How long a client stays locked out after reaching [maxPinAttempts].
/// After this elapses the counter resets and the client may retry.
const Duration pinCooldown = Duration(seconds: 30);

/// Result of evaluating a single PIN attempt.
typedef PinAttemptResult = ({bool allowed, bool locked, int newAttempts});

/// Compares two strings in time independent of where (and whether) they differ.
///
/// ponytail: 固定时间逐字节比较，遍历较长串的全部字符并累积异或差。
/// Dart JIT 下并非密码学级保证，但消除了 `==` 的短路时序侧信道，PIN 这种短定长场景足够。
bool constantTimeEquals(String a, String b) {
  final int maxLen = a.length > b.length ? a.length : b.length;
  var diff = a.length ^ b.length;
  for (var i = 0; i < maxLen; i++) {
    final int ca = i < a.length ? a.codeUnitAt(i) : 0;
    final int cb = i < b.length ? b.codeUnitAt(i) : 0;
    diff |= ca ^ cb;
  }
  return diff == 0;
}

/// Evaluates a PIN attempt against the configured PIN.
///
/// [attempts] is the number of previously recorded failed attempts for this
/// client. Returns `newAttempts` so the caller can write back the exact next
/// counter value — including `0` on success, which resets the client's history
/// (a correct PIN clears prior failures).
///
/// Returns `allowed: true` when no PIN is configured or the PIN matches.
/// Returns `locked: true` when this failed attempt meets the lock threshold.
PinAttemptResult evaluatePinAttempt({
  required String? configuredPin,
  required String? requestPin,
  required int attempts,
}) {
  if (configuredPin == null) {
    return (allowed: true, locked: false, newAttempts: 0);
  }

  if (constantTimeEquals(requestPin ?? '', configuredPin)) {
    // Success resets the client's failure history.
    return (allowed: true, locked: false, newAttempts: 0);
  }

  final newAttempts = attempts + 1;
  return (allowed: false, locked: newAttempts >= maxPinAttempts, newAttempts: newAttempts);
}

/// Whether a client that has reached the attempt threshold is still inside the
/// cooldown window and must be rejected with 429.
///
/// [lockedAt] is when the lock took effect. A null [lockedAt] means the lock
/// time is unknown (e.g. state accumulated before this field existed): treat it
/// as elapsed so legacy clients are not permanently locked until process restart.
bool isWithinLockWindow({
  required int attempts,
  required DateTime? lockedAt,
  required DateTime now,
}) {
  if (attempts < maxPinAttempts) return false;
  if (lockedAt == null) return false;
  return now.difference(lockedAt) < pinCooldown;
}
