@Tags(['security'])
library;

import 'package:localsend_app/util/pin_storage.dart';
import 'package:test/test.dart';

void main() {
  group('hashPin / verifyPin', () {
    test('verifyPin accepts the plaintext that was hashed', () {
      final record = hashPin('1234', iterations: 1000);
      expect(verifyPin('1234', record), isTrue);
    });

    test('verifyPin rejects a wrong plaintext', () {
      final record = hashPin('1234', iterations: 1000);
      expect(verifyPin('0000', record), isFalse);
      expect(verifyPin('12345', record), isFalse);
      expect(verifyPin('', record), isFalse);
    });

    test('different salts produce different hashes for the same PIN', () {
      final a = hashPin('1234', salt: 'aa', iterations: 1000);
      final b = hashPin('1234', salt: 'bb', iterations: 1000);
      expect(a.hash, isNot(equals(b.hash)));
      // Both still verify against the same plaintext.
      expect(verifyPin('1234', a), isTrue);
      expect(verifyPin('1234', b), isTrue);
    });

    test('verifyPin returns false for a null record (nothing to match)', () {
      expect(verifyPin('1234', null), isFalse);
    });

    test('hashPin generates a random salt when none is given', () {
      final a = hashPin('1234', iterations: 1000);
      final b = hashPin('1234', iterations: 1000);
      expect(a.salt, isNot(equals(b.salt)));
      expect(a.hash, isNot(equals(b.hash)));
    });

    test('default iterations meet the production minimum', () {
      // Guards against accidentally lowering the KDF cost.
      expect(hashPin('1234').iterations, greaterThanOrEqualTo(100000));
    });
  });

  group('PinHashRecord encode / tryDecode', () {
    test('round-trips an encoded record', () {
      final record = hashPin('482913', salt: 'deadbeef', iterations: 1000);
      final decoded = PinHashRecord.tryDecode(record.encode());
      expect(decoded, isNotNull);
      expect(decoded!.salt, equals(record.salt));
      expect(decoded.hash, equals(record.hash));
      expect(decoded.iterations, equals(record.iterations));
      expect(verifyPin('482913', decoded), isTrue);
    });

    test('tryDecode returns null for a legacy plaintext PIN (no prefix)', () {
      // Old versions stored the raw PIN; these must be detectable so the
      // persistence layer can migrate them instead of treating them as records.
      expect(PinHashRecord.tryDecode('1234'), isNull);
      expect(PinHashRecord.tryDecode(''), isNull);
    });

    test('tryDecode returns null for null / malformed input', () {
      expect(PinHashRecord.tryDecode(null), isNull);
      expect(PinHashRecord.tryDecode('pbkdf2\$notanumber\$aa\$bb'), isNull);
      expect(PinHashRecord.tryDecode('pbkdf2\$1000\$aa'), isNull);
    });
  });

  group('security properties', () {
    test('the encoded record never contains the plaintext PIN', () {
      final encoded = hashPin('s3cret-pin', iterations: 1000).encode();
      expect(encoded.contains('s3cret-pin'), isFalse);
      expect(encoded.contains('s3cret'), isFalse);
    });
  });
}
