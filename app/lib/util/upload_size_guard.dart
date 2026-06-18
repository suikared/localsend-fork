import 'dart:async';
import 'dart:typed_data';

/// Thrown by [capUploadStream] when an upload stream emits more bytes than the
/// receiver declared it would (the file's `size`). This is the C4-sec
/// mitigation: a malicious peer cannot exhaust the receiver's disk by
/// streaming past its declared size, because the stream is aborted as soon as
/// the next chunk would exceed the cap.
class OversizedUploadException implements Exception {
  const OversizedUploadException(this.maxBytes);

  /// The byte ceiling that was exceeded.
  final int maxBytes;

  @override
  String toString() => 'OversizedUploadException: upload exceeded $maxBytes bytes';
}

/// Wraps [source], re-yielding its chunks unchanged until emitting the next
/// chunk would push the cumulative byte count above [maxBytes]. At that point
/// the offending chunk is dropped and [OversizedUploadException] is thrown,
/// so the total bytes a consumer can ever read is at most [maxBytes].
///
/// Pure stream transform — no I/O — so the trust-boundary cap is unit-testable
/// without standing up the HTTP server.
Stream<Uint8List> capUploadStream(Stream<Uint8List> source, int maxBytes) async* {
  int cumulative = 0;
  await for (final chunk in source) {
    if (cumulative + chunk.length > maxBytes) {
      throw OversizedUploadException(maxBytes);
    }
    cumulative += chunk.length;
    yield chunk;
  }
}
