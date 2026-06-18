import 'package:common/api_route_builder.dart';
import 'package:common/model/device.dart';
import 'package:common/src/isolate/child/http_provider.dart';
import 'package:common/src/isolate/child/sync_provider.dart';
import 'package:common/src/task/upload/pinned_upload_client.dart';
import 'package:refena/refena.dart';

/// Builds the per-upload pinned TLS client for a given peer fingerprint.
/// Injected so unit tests can substitute a recording client and still assert
/// the upload query parameters.
typedef PinnedClientFactory = CustomHttpClient Function(String fingerprint);

final httpUploadProvider = ViewProvider((ref) {
  final securityContext = ref.watch(syncProvider.select((s) => s.securityContext));
  return HttpUploadService(
    (fingerprint) => PinnedIoHttpClient(fingerprint, securityContext, _uploadTimeout),
  );
});

// ponytail: effectively-unbounded timeout matches the prior rhttp longLiving
// client (Duration(days: 30)) so large file uploads never time out on slow
// links. Tighten if a dead-peer detection requirement appears.
const Duration _uploadTimeout = Duration(days: 30);

class HttpUploadService {
  HttpUploadService(this._clientFor);

  final PinnedClientFactory _clientFor;

  Future<void> upload({
    required Stream<List<int>> stream,
    required int contentLength,
    required String contentType,
    required Device target,
    required String? remoteSessionId,
    required String fileId,
    required String token,
    required void Function(double) onSendProgress,
    required CustomCancelToken cancelToken,
  }) async {
    // C1-sec-file: pin the TLS handshake to the peer's certificate fingerprint
    // so a MITM cannot passively read the uploaded file bytes. One pinned
    // client per upload; the client closes itself on completion/cancel.
    final client = _clientFor(target.fingerprint);
    await client.postStream(
      uri: ApiRoute.upload.target(target),
      query: {
        if (remoteSessionId != null) 'sessionId': remoteSessionId,
        'fileId': fileId,
        'token': token,
      },
      headers: {
        'Content-Length': contentLength.toString(),
        'Content-Type': contentType,
      },
      stream: stream,
      onSendProgress: onSendProgress,
      cancelToken: cancelToken,
    );
  }
}
