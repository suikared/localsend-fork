@Tags(['security'])
library;

import 'dart:convert';

import 'package:common/src/task/upload/pinned_upload_client.dart';
import 'package:test/test.dart';

/// The self-signed LocalSend test certificate used by
/// `app/test/unit/util/security_helper_test.dart`, whose SHA-256(DER) is the
/// canonical fingerprint `247E5F...`.
const _pem = '''-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMRcwFQYDVQQDEw5Mb2Nh
bFNlbmQgVXNlcjEJMAcGA1UEChMAMQkwBwYDVQQLEwAxCTAHBgNVBAcTADEJMAcG
A1UECBMAMQkwBwYDVQQGEwAwHhcNMjMwNDIxMjM0NTM3WhcNMzMwNDE4MjM0NTM3
WjBQMRcwFQYDVQQDEw5Mb2NhbFNlbmQgVXNlcjEJMAcGA1UEChMAMQkwBwYDVQQL
EwAxCTAHBgNVBAcTADEJMAcGA1UECBMAMQkwBwYDVQQGEwAwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCL24MxhGfrdJm0Q8ZGiBkZ27ldcEChB4w7rSbJ
yiKeosoNbJl2kyj5dZjfBhWGgDLGDMM5w+Mh/5SrWgTL/QrhbB+lsrxILLznWqBi
R8wJP0P2YW9fBahQskJQcUXt/3jsCsMTWea4rWc3HZGh03bAkJfLM+PDSOfTpvAZ
6DQSp9QLzC9bgVNnq3W0SvOZGpF0xRa4InCyTUgxsNsV4+GIrmN5w4EbRFVVYu7D
5OS5fxNSCukiS0fb6oQzUp0vIAycvvWHHbAy8T6UMoUor2nfvNcryiaOX5WBMLyh
yMZ5gMOyXjdm1bT1XSlvtXPYUzxvsGAzTqS8mXjw8h7mm5htAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBAIs+T8Nkbl0gecT22CKW9/jMvUS1PGAyMqlwP8fNTsyv2xE9
hLsyUrxsscuv+HGJu6Cz1R3hLI8YY5jEShmaelI0stlLahH9Fbm43EZuadGXOVKZ
gMrNzQqLY5lec55rmS17GJlkm5opidkq4OlsCHfrBJitX6071atb0B1cdAjysWwV
x40mnwq0TmYgBLDhWaM4/ZfZQRJQpPCtBJO06Nk7gTPiqJGJU5iEaz1PLvARq69o
bJobSekf9tx3uwOIfioaoQvX0khkZ3ljFuNUpW3IE87OfPnYJQhu5xsTx00wi+Ce
x64ghD4CzRa7wYsOjeb8cUUDMSj030NO9fBGVtA=
-----END CERTIFICATE-----''';

/// DER bytes of [_pem] (PEM body base64-decoded), matching how
/// `calculateHashOfCertificate` derives the fingerprint.
List<int> get _der {
  final body = _pem
      .replaceAll('\r\n', '\n')
      .split('\n')
      .where((l) => l.isNotEmpty && !l.startsWith('---'))
      .join();
  return base64.decode(body);
}

const _expectedFingerprint = '247E5F7CF21DE14438EAE733E07AC5440593D0612570C7413674130608DF69A9';

void main() {
  group('fingerprintOfCertDer', () {
    test('produces the canonical uppercase SHA-256(DER) hex', () {
      expect(fingerprintOfCertDer(_der), _expectedFingerprint);
    });
  });

  group('fingerprintMatches', () {
    test('accepts an exact uppercase fingerprint', () {
      expect(fingerprintMatches(_der, _expectedFingerprint), isTrue);
    });

    test('accepts a lowercase fingerprint', () {
      expect(fingerprintMatches(_der, _expectedFingerprint.toLowerCase()), isTrue);
    });

    test('accepts a colon-separated fingerprint (normalized away)', () {
      final colonized = _expectedFingerprint.replaceAllMapped(
        RegExp(r'(.{2})(?!$)'),
        (m) => '${m[1]}:',
      );
      expect(fingerprintMatches(_der, colonized), isTrue);
    });

    test('rejects a mismatching fingerprint', () {
      expect(
        fingerprintMatches(_der, '0000000000000000000000000000000000000000000000000000000000000000'),
        isFalse,
      );
    });

    test('rejects an empty expected fingerprint', () {
      expect(fingerprintMatches(_der, ''), isFalse);
    });
  });
}
