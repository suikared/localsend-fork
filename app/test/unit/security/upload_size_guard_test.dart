@Tags(['security'])
library;

import 'dart:typed_data';

import 'package:localsend_app/util/upload_size_guard.dart';
import 'package:test/test.dart';

void main() {
  group('capUploadStream', () {
    test('passes all chunks through when total equals the cap exactly', () async {
      // Arrange — two chunks summing to exactly maxBytes (boundary allowed).
      final stream = Stream.fromIterable([
        Uint8List.fromList([1, 2, 3]),
        Uint8List.fromList([4, 5]),
      ]);
      const maxBytes = 5;

      // Act
      final out = await capUploadStream(stream, maxBytes).toList();

      // Assert
      expect(out.expand((c) => c).toList(), [1, 2, 3, 4, 5]);
    });

    test('passes all chunks through when total is below the cap', () async {
      final stream = Stream.fromIterable([
        Uint8List.fromList([1, 2]),
      ]);
      const maxBytes = 100;

      final out = await capUploadStream(stream, maxBytes).toList();

      expect(out.expand((c) => c).toList(), [1, 2]);
    });

    test('throws OversizedUploadException and never consumes more than the cap', () async {
      // Arrange — declared size 8 but peer streams 14 bytes (disk-exhaustion
      // DoS vector from C4-sec). Chunking is irrelevant: cumulative bytes must
      // never exceed the cap before the stream errors out.
      final stream = Stream.fromIterable([
        Uint8List.fromList(List.filled(7, 1)),
        Uint8List.fromList(List.filled(7, 2)),
      ]);
      const maxBytes = 8;

      // Act
      int consumed = 0;
      Object? caught;
      try {
        await for (final chunk in capUploadStream(stream, maxBytes)) {
          consumed += chunk.length;
        }
      } catch (e) {
        caught = e;
      }

      // Assert
      expect(caught, isA<OversizedUploadException>());
      expect(consumed, lessThanOrEqualTo(maxBytes));
    });

    test('rejects a single chunk larger than the cap before emitting anything', () async {
      final stream = Stream.fromIterable([
        Uint8List.fromList(List.filled(10, 9)),
      ]);
      const maxBytes = 8;

      int consumed = 0;
      Object? caught;
      try {
        await for (final chunk in capUploadStream(stream, maxBytes)) {
          consumed += chunk.length;
        }
      } catch (e) {
        caught = e;
      }

      expect(caught, isA<OversizedUploadException>());
      expect(consumed, 0);
    });
  });
}
