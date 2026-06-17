import 'dart:io';

import 'package:localsend_app/provider/network/server/server_utils.dart';
import 'package:localsend_app/util/pin_guard.dart';
import 'package:localsend_app/util/simple_server.dart';

/// Responds with 401 or 429 if the pin is invalid or too many attempts.
/// Returns true if the pin is correct, or if no pin is set.
///
/// Security notes (K7):
/// - PIN comparison is constant-time (see `pin_guard.dart`) to avoid a timing
///   side-channel.
/// - Every rejected attempt is counted, including an empty/missing PIN, so an
///   attacker cannot probe indefinitely by omitting the PIN.
/// - `request.ip` is the TCP peer address from the socket
///   (`connectionInfo.remoteAddress`), not a parsed `X-Forwarded-For`, so it
///   cannot be spoofed by a header.
/// - A correct PIN resets the client's failure history (no permanent shadow
///   from old mistakes), and a lockout expires after [pinCooldown] instead of
///   persisting for the lifetime of the server process.
Future<bool> checkPin({
  required ServerUtils server,
  required String? pin,
  required Map<String, int> pinAttempts,
  required Map<String, DateTime> pinLockedAt,
  required HttpRequest request,
  DateTime Function() now = DateTime.now,
}) async {
  if (pin != null) {
    final ip = request.ip;
    final attempts = pinAttempts[ip] ?? 0;

    if (isWithinLockWindow(attempts: attempts, lockedAt: pinLockedAt[ip], now: now())) {
      await request.respondJson(429, message: 'Too many attempts.');
      return false;
    }

    // Cooldown elapsed (or legacy state with no recorded lock time) -> give the
    // client a fresh set of attempts.
    if (attempts >= maxPinAttempts) {
      pinAttempts[ip] = 0;
      pinLockedAt.remove(ip);
    }

    final requestPin = request.uri.queryParameters['pin'];
    final result = evaluatePinAttempt(
      configuredPin: pin,
      requestPin: requestPin,
      attempts: pinAttempts[ip] ?? 0,
    );

    if (!result.allowed) {
      pinAttempts[ip] = result.newAttempts;

      if (result.locked) {
        pinLockedAt[ip] = now();
        await request.respondJson(429, message: 'Too many attempts.');
        return false;
      }
      await request.respondJson(401, message: 'Invalid pin.');
      return false;
    }

    // Allowed: evaluatePinAttempt already reports newAttempts == 0.
    pinAttempts[ip] = 0;
    pinLockedAt.remove(ip);
  }

  return true;
}
