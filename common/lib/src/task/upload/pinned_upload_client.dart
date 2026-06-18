import 'dart:async';
import 'dart:io';

import 'package:common/model/stored_security_context.dart';
import 'package:common/src/isolate/child/http_provider.dart';
import 'package:crypto/crypto.dart';

/// SHA-256(DER) of a peer certificate, uppercase hex — the same form as
/// `Device.fingerprint` and `security_helper.calculateHashOfCertificate`.
String fingerprintOfCertDer(List<int> der) {
  return sha256.convert(der).toString().toUpperCase();
}

/// Constant-time equality for two same-domain strings. Mirrors the app-side
/// `pin_guard.constantTimeEquals`; duplicated here because common cannot import
/// the app package. Do not simplify to `==` — this closes a timing side-channel
/// on the fingerprint comparison.
bool _constantTimeEquals(String a, String b) {
  final maxLen = a.length > b.length ? a.length : b.length;
  var diff = a.length ^ b.length;
  for (var i = 0; i < maxLen; i++) {
    final ca = i < a.length ? a.codeUnitAt(i) : 0;
    final cb = i < b.length ? b.codeUnitAt(i) : 0;
    diff |= ca ^ cb;
  }
  return diff == 0;
}

/// Normalizes a fingerprint string to uppercase hex with no separators, then
/// constant-time-compares it against the SHA-256(DER) of [der].
bool fingerprintMatches(List<int> der, String expected) {
  final normalized = expected.toUpperCase().replaceAll(':', '');
  if (normalized.isEmpty) return false;
  return _constantTimeEquals(normalized, fingerprintOfCertDer(der));
}

/// Verifies a presented TLS peer certificate against an expected fingerprint.
///
/// Returns false when no certificate is presented (refuse-closed) — the whole
/// point of C1-sec-file is that an upload must abort unless the peer proves
/// it owns the fingerprint the sender is sending to.
bool verifyPeerFingerprint(X509Certificate? cert, String expected) {
  if (cert == null) return false;
  return fingerprintMatches(cert.der, expected);
}

/// Upload progress as a fraction in [0, 1]; zero-length streams report 1.0.
/// Mirrors `app/lib/util/rhttp.dart::safeProgress` (common cannot import app).
double safeProgress(int curr, int total) => total == 0 ? 1.0 : curr / total;

/// A [CustomHttpClient] for the /upload path that pins the TLS handshake to a
/// single peer certificate fingerprint (C1-sec-file), replacing the
/// `verifyCertificates: false` rhttp upload transport.
///
/// One instance is built per upload (per [target.fingerprint]); the underlying
/// dart:io [HttpClient] is closed when the upload completes or is cancelled.
class PinnedIoHttpClient implements CustomHttpClient {
  PinnedIoHttpClient(this._expectedFingerprint, this._securityContext, this._timeout);

  final String _expectedFingerprint;
  final StoredSecurityContext _securityContext;
  final Duration _timeout;

  HttpClient _createClient() {
    // mTLS: present our own self-signed client certificate (mirrors the rhttp
    // ClientCertificate). LocalSend keys are unencrypted PEM; password unused.
    // ponytail: client-cert loading across dart:io backends is the one piece
    // not covered by unit tests — verified manually (see audit report §4).
    final context = SecurityContext(withTrustedRoots: true);
    context.usePrivateKeyBytes(_securityContext.privateKey.codeUnits);
    context.useCertificateChainBytes(_securityContext.certificate.codeUnits);

    final client = HttpClient(context: context)..connectionTimeout = _timeout;

    // Self-signed peers always fail standard verification, so this callback is
    // effectively our verification gate: accept only the pinned fingerprint.
    client.badCertificateCallback = (cert, host, port) =>
        verifyPeerFingerprint(cert, _expectedFingerprint);

    return client;
  }

  @override
  Future<String> get({required String uri, required Map<String, String> query}) {
    throw UnimplementedError('PinnedIoHttpClient only serves the upload POST stream');
  }

  @override
  Future<String> post({
    required String uri,
    Map<String, String> query = const {},
    required Map<String, dynamic> json,
  }) {
    throw UnimplementedError('PinnedIoHttpClient only serves the upload POST stream');
  }

  @override
  Future<void> postStream({
    required String uri,
    required Map<String, String> query,
    required Map<String, String> headers,
    required Stream<List<int>> stream,
    required void Function(double progress) onSendProgress,
    required CustomCancelToken cancelToken,
  }) async {
    final client = _createClient();

    final parsed = Uri.parse(uri).replace(queryParameters: {
      ...Uri.parse(uri).queryParameters,
      ...query,
    });
    final total = int.parse(headers['Content-Length']!);

    // Cancellation: force-close the per-upload client, tearing down the socket.
    cancelToken.setCancel(() {
      // ignore: discarded_futures
      client.close(force: true);
    });

    final HttpClientRequest request;
    try {
      request = await client.postUrl(parsed);
    } finally {
      cancelToken.setCancel(() {});
    }
    request.headers.contentLength = total;
    final contentType = headers['Content-Type'];
    if (contentType != null && contentType.isNotEmpty) {
      request.headers.contentType = ContentType.parse(contentType);
    }

    var sent = 0;
    try {
      await for (final chunk in stream) {
        request.add(chunk);
        sent += chunk.length;
        onSendProgress(safeProgress(sent, total));
      }
      await request.flush();
      final response = await request.close();
      if (response.statusCode >= 400) {
        throw HttpException('Upload failed with status ${response.statusCode}');
      }
      await response.drain<void>();
    } finally {
      // ignore: discarded_futures
      client.close(force: true);
    }
  }
}
