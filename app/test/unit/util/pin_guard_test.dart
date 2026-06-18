import 'package:localsend_app/util/pin_guard.dart';
import 'package:localsend_app/util/pin_storage.dart';
import 'package:test/test.dart';

// Encoded PBKDF2 record for the PIN "1234" (low iterations keep the suite fast;
// production uses kPinHashIterations). evaluatePinAttempt now takes the record
// string, not the plaintext PIN.
final String _pin1234 = hashPin('1234', iterations: 1000).encode();

void main() {
  group('constantTimeEquals', () {
    test('returns true for equal strings', () {
      expect(constantTimeEquals('1234', '1234'), isTrue);
    });

    test('returns false for different strings of same length', () {
      expect(constantTimeEquals('1234', '1235'), isFalse);
      expect(constantTimeEquals('1234', '2234'), isFalse);
    });

    test('returns false for different lengths', () {
      expect(constantTimeEquals('1234', '123'), isFalse);
      expect(constantTimeEquals('1234', '12345'), isFalse);
      expect(constantTimeEquals('', '1'), isFalse);
    });

    test('returns true for two empty strings', () {
      expect(constantTimeEquals('', ''), isTrue);
    });

    test('does not short-circuit on early-byte mismatch (structure guard)', () {
      // A correct implementation accumulates a diff across all bytes rather
      // than returning on the first mismatched char. We assert the function is
      // referentially correct for a prefix-shared pair — the timing guarantee
      // itself is a code-structure property, not directly assertable here.
      expect(constantTimeEquals('abcdef', 'axcdef'), isFalse);
      expect(constantTimeEquals('abcdef', 'abcdez'), isFalse);
    });
  });

  group('evaluatePinAttempt', () {
    test('allows when no PIN is configured', () {
      final result = evaluatePinAttempt(configuredPin: null, requestPin: 'anything', attempts: 0);
      expect(result.allowed, isTrue);
      expect(result.locked, isFalse);
    });

    test('allows correct PIN', () {
      final result = evaluatePinAttempt(configuredPin: _pin1234, requestPin: '1234', attempts: 1);
      expect(result.allowed, isTrue);
    });

    test('rejects wrong PIN and does not lock before threshold', () {
      final result = evaluatePinAttempt(configuredPin: _pin1234, requestPin: '0000', attempts: 0);
      expect(result.allowed, isFalse);
      expect(result.locked, isFalse);
    });

    test('locks on the third failed attempt (attempts == 2)', () {
      final result = evaluatePinAttempt(configuredPin: _pin1234, requestPin: '0000', attempts: 2);
      expect(result.allowed, isFalse);
      expect(result.locked, isTrue);
    });

    test('counts an empty PIN as a failed attempt (K7 fix)', () {
      // The caller now increments the attempt counter for *every* rejection,
      // including an empty/missing PIN, so this must still be rejected.
      final result = evaluatePinAttempt(configuredPin: _pin1234, requestPin: null, attempts: 0);
      expect(result.allowed, isFalse);
      expect(result.locked, isFalse);
    });

    test('empty PIN at threshold locks (no infinite probing)', () {
      final result = evaluatePinAttempt(configuredPin: _pin1234, requestPin: '', attempts: 2);
      expect(result.allowed, isFalse);
      expect(result.locked, isTrue);
    });
  });

  group('evaluatePinAttempt attempt accounting', () {
    test('resets newAttempts to 0 on success', () {
      final result = evaluatePinAttempt(configuredPin: _pin1234, requestPin: '1234', attempts: 5);
      expect(result.allowed, isTrue);
      expect(result.newAttempts, 0);
    });

    test('increments newAttempts on failure', () {
      final result = evaluatePinAttempt(configuredPin: _pin1234, requestPin: '0000', attempts: 1);
      expect(result.allowed, isFalse);
      expect(result.newAttempts, 2);
    });

    test('increments newAttempts on empty PIN failure', () {
      final result = evaluatePinAttempt(configuredPin: _pin1234, requestPin: null, attempts: 0);
      expect(result.newAttempts, 1);
    });
  });

  group('isWithinLockWindow', () {
    final t0 = DateTime(2026, 1, 1, 0, 0, 0);

    test('false below threshold', () {
      expect(isWithinLockWindow(attempts: 2, lockedAt: null, now: t0), isFalse);
    });

    test('true when locked and within cooldown', () {
      expect(
        isWithinLockWindow(attempts: 3, lockedAt: t0, now: t0.add(const Duration(seconds: 10))),
        isTrue,
      );
    });

    test('false when cooldown elapsed', () {
      expect(
        isWithinLockWindow(
          attempts: 3,
          lockedAt: t0,
          now: t0.add(pinCooldown).add(const Duration(seconds: 1)),
        ),
        isFalse,
      );
    });

    test('false at threshold with no lock time (legacy accumulated state -> unlock)', () {
      // A device that hit the threshold before pinLockedAt existed must be
      // allowed to retry, otherwise the lock is permanent until process restart.
      expect(isWithinLockWindow(attempts: 5, lockedAt: null, now: t0), isFalse);
    });
  });
}
