@Tags(['security'])
library;

import 'package:common/model/device.dart';
import 'package:common/src/isolate/child/http_provider.dart';
import 'package:common/src/task/upload/http_upload.dart';
import 'package:test/test.dart';

/// Regression guard for the upload-400 bug (2026-06):
/// send_provider once shadowed the local `sessionId`, so the remote session id
/// never reached the upload request and the receiver answered 400.
///
/// This contract test pins the lower-level invariant that the upload request
/// MUST carry `sessionId` in its query when a remoteSessionId is present.
class _RecordingClient implements CustomHttpClient {
  Map<String, String>? lastQuery;

  @override
  Future<String> get({required String uri, required Map<String, String> query}) async {
    throw UnimplementedError();
  }

  @override
  Future<String> post({
    required String uri,
    Map<String, String> query = const {},
    required Map<String, dynamic> json,
  }) async {
    throw UnimplementedError();
  }

  @override
  Future<void> postStream({
    required String uri,
    required Map<String, String> query,
    required Map<String, String> headers,
    required Stream<List<int>> stream,
    required void Function(double) onSendProgress,
    required CustomCancelToken cancelToken,
  }) async {
    lastQuery = Map<String, String>.from(query);
  }
}

Device _target() => const Device(
      signalingId: null,
      ip: '192.168.0.147',
      version: '2.1',
      port: 53317,
      https: true,
      fingerprint: 'fp',
      alias: 'peer',
      deviceModel: null,
      deviceType: DeviceType.desktop,
      download: false,
      discoveryMethods: {},
    );

void main() {
  late _RecordingClient client;
  late HttpUploadService service;

  setUp(() {
    client = _RecordingClient();
    service = HttpUploadService(client);
  });

  test('upload query carries sessionId when remoteSessionId is present', () async {
    await service.upload(
      stream: const Stream.empty(),
      contentLength: 0,
      contentType: 'application/octet-stream',
      target: _target(),
      remoteSessionId: 'remote-session-abc',
      fileId: 'file-1',
      token: 'token-1',
      onSendProgress: (_) {},
      cancelToken: CustomCancelToken(),
    );

    expect(client.lastQuery, isNotNull);
    expect(client.lastQuery!['sessionId'], 'remote-session-abc');
    expect(client.lastQuery!['fileId'], 'file-1');
    expect(client.lastQuery!['token'], 'token-1');
  });

  test('upload query omits sessionId when remoteSessionId is null', () async {
    await service.upload(
      stream: const Stream.empty(),
      contentLength: 0,
      contentType: 'application/octet-stream',
      target: _target(),
      remoteSessionId: null,
      fileId: 'file-1',
      token: 'token-1',
      onSendProgress: (_) {},
      cancelToken: CustomCancelToken(),
    );

    expect(client.lastQuery, isNotNull);
    expect(client.lastQuery!.containsKey('sessionId'), isFalse);
    expect(client.lastQuery!['fileId'], 'file-1');
    expect(client.lastQuery!['token'], 'token-1');
  });
}
