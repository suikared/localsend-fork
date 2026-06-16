/// Pure, HTTP-free PIN-evaluation helpers.
///
/// Extracted from `checkPin` so the security-critical logic (constant-time
/// comparison, attempt counting) is unit-testable without faking `HttpRequest`.
library;

/// Result of evaluating a single PIN attempt.
typedef PinAttemptResult = ({bool allowed, bool locked});

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
/// client. The caller is responsible for incrementing it on every rejection
/// (including an empty/missing PIN) — see K7.
///
/// Returns `allowed: true` when no PIN is configured or the PIN matches.
/// Returns `locked: true` when this failed attempt meets the lock threshold.
PinAttemptResult evaluatePinAttempt({
  required String? configuredPin,
  required String? requestPin,
  required int attempts,
}) {
  if (configuredPin == null) {
    return (allowed: true, locked: false);
  }

  if (constantTimeEquals(requestPin ?? '', configuredPin)) {
    return (allowed: true, locked: false);
  }

  // Threshold of 2 prior failures means this is the 3rd attempt → lock.
  return (allowed: false, locked: attempts >= 2);
}
