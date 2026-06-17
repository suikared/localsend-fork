import 'package:common/isolate.dart';
import 'package:common/model/stored_security_context.dart';
import 'package:rhttp/rhttp.dart';

class RhttpWrapper implements CustomHttpClient {
  final RhttpClient _client;

  RhttpWrapper._(this._client);

  factory RhttpWrapper.create(Duration timeout, StoredSecurityContext securityContext) {
    final client = createRhttpClient(timeout, securityContext);
    return RhttpWrapper._(client);
  }

  @override
  Future<String> get({
    required String uri,
    required Map<String, String> query,
  }) async {
    final response = await _client.get(
      uri,
      query: query,
    );
    return response.body;
  }

  @override
  Future<String> post({
    required String uri,
    Map<String, String> query = const {},
    required Map<String, dynamic> json,
  }) async {
    final response = await _client.post(
      uri,
      query: query,
      body: HttpBody.json(json),
    );
    return response.body;
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
    final token = CancelToken();
    cancelToken.setCancel(token.cancel);
    await _client.request(
      method: HttpMethod.post,
      expectBody: HttpExpectBody.bytes,
      url: uri,
      query: query,
      headers: HttpHeaders.rawMap(headers),
      body: HttpBody.stream(
        stream,
        length: int.parse(headers['Content-Length']!),
      ),
      onSendProgress: (curr, total) {
        onSendProgress(safeProgress(curr, total));
      },
      cancelToken: token,
    );
  }
}

/// Upload progress as a fraction in [0, 1]. Zero-length streams report 1.0
/// instead of dividing by zero (empty-file uploads).
double safeProgress(int curr, int total) => total == 0 ? 1.0 : curr / total;

RhttpClient createRhttpClient(Duration timeout, StoredSecurityContext securityContext, {Interceptor? interceptor}) {
  return RhttpClient.createSync(
    settings: ClientSettings(
      timeoutSettings: TimeoutSettings(
        timeout: timeout,
      ),
      tlsSettings: TlsSettings(
        verifyCertificates: false,
        clientCertificate: ClientCertificate(
          certificate: securityContext.certificate,
          privateKey: securityContext.privateKey,
        ),
      ),
    ),
    interceptors: interceptor != null ? [interceptor] : [],
  );
}
