import 'package:localsend_app/util/rhttp.dart';
import 'package:test/test.dart';

void main() {
  group('safeProgress', () {
    test('returns 1.0 for zero-length stream (no division by zero)', () {
      // Sending an empty file (0 bytes) must not crash upload progress.
      expect(safeProgress(0, 0), 1.0);
    });

    test('returns fraction for partial progress', () {
      expect(safeProgress(50, 200), 0.25);
    });

    test('returns 1.0 when fully sent', () {
      expect(safeProgress(200, 200), 1.0);
    });
  });
}
