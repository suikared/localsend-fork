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
Future<bool> checkPin({
  required ServerUtils server,
  required String? pin,
  required Map<String, int> pinAttempts,
  required HttpRequest request,
}) async {
  if (pin != null) {
    final attempts = pinAttempts[request.ip] ?? 0;
    if (attempts >= 3) {
      await request.respondJson(429, message: 'Too many attempts.');
      return false;
    }

    final requestPin = request.uri.queryParameters['pin'];
    final result = evaluatePinAttempt(
      configuredPin: pin,
      requestPin: requestPin,
      attempts: attempts,
    );

    if (!result.allowed) {
      // Count every failure, including an empty/missing PIN.
      pinAttempts[request.ip] = attempts + 1;

      if (result.locked) {
        await request.respondJson(429, message: 'Too many attempts.');
        return false;
      }
      await request.respondJson(401, message: 'Invalid pin.');
      return false;
    }
  }

  return true;
}
