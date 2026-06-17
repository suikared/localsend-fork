//! Handshake-time server certificate verifier that pins the peer to an expected
//! certificate fingerprint.
//!
//! Unlike the post-hoc check in [`crate::http::client`] (`verify_cert_from_res`),
//! which runs *after* the request (and therefore after request-side secrets like
//! the PIN have already been transmitted), this verifier runs during the TLS
//! handshake. A MITM that presents its own certificate is rejected before any
//! application data is sent.
//!
//! The pin anchor is the LocalSend device **fingerprint** — the lowercase SHA-256
//! hex of the peer's DER-encoded leaf certificate. This is the same value devices
//! advertise over multicast discovery and that `Device.fingerprint` carries, so it
//! is always available at `prepare_upload` time without an extra round-trip.
//!
//! Validation reuses [`crate::crypto::cert::verify_cert_from_der`]:
//! - time validity + self-signature always checked;
//! - when an expected fingerprint is supplied, `SHA-256(end_entity DER)` must match
//!   it (this is the pin);
//! - `expected_fingerprint = None` is the TOFU / first-contact mode (validate but
//!   do not pin). Used for discovery, which carries no secrets.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

/// A [ServerCertVerifier] that optionally pins the peer's leaf certificate to an
/// expected fingerprint (lowercase SHA-256 hex of the DER cert), matching the
/// LocalSend device `fingerprint`.
#[derive(Debug)]
pub struct PinnedServerCertVerifier {
    expected_fingerprint: Option<String>,
    supported: WebPkiSupportedAlgorithms,
}

impl PinnedServerCertVerifier {
    /// Create a verifier. `expected_fingerprint = None` disables pinning but still
    /// validates time validity and the certificate signature (TOFU mode).
    pub fn new(expected_fingerprint: Option<String>) -> Self {
        Self {
            // Normalize: lowercase, drop any ':' / whitespace separators so the
            // comparison is robust against formatting differences.
            expected_fingerprint: expected_fingerprint.map(normalize_fingerprint),
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

/// Lowercase hex SHA-256 of the DER-encoded certificate, matching the LocalSend
/// fingerprint format (`security_helper.calculateHashOfCertificate`).
pub fn fingerprint_of_der(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn normalize_fingerprint(fp: String) -> String {
    fp.chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let der = end_entity.as_ref();

        // Always validate time validity + self-signature (reuses tested logic).
        crate::crypto::cert::verify_cert_from_der(der, None).map_err(|e| {
            tracing::warn!("Server certificate validation failed: {e:#}");
            Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        })?;

        // Pin to fingerprint when provided. Timing side-channel on a SHA-256
        // preimage is not a realistic concern (no secret is being leaked), so a
        // plain equality on normalized hex is sufficient here.
        if let Some(expected) = &self.expected_fingerprint {
            let actual = fingerprint_of_der(der);
            if &actual != expected {
                tracing::warn!(
                    "Server certificate fingerprint mismatch: expected {expected}, got {actual}"
                );
                return Err(Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ));
            }
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    const GOOD_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMRcwFQYDVQQDEw5Mb2Nh
bFNlbmQgVXNlcjEJMAcGA1UEChMAMQkwBwYDVQQLEwAxCTAHBgNVBAcTADEJMAcG
A1UECBMAMQkwBwYDVQQGEwAwHhcNMjUwMjA5MDAwMzE0WhcNMzUwMjA3MDAwMzE0
WjBQMRcwFQYDVQQDEw5Mb2NhbFNlbmQgVXNlcjEJMAcGA1UEChMAMQkwBwYDVQQL
EwAxCTAHBgNVBAcTADEJMAcGA1UECBMAMQkwBwYDVQQGEwAwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCL24MxhGfrdJm0Q8ZGiBkZ27ldcEChB4w7rSbJ
yiKeosoNbJl2kyj5dZjfBhWGgDLGDMM5w+Mh/5SrWgTL/QrhbB+lsrxILLznWqBi
R8wJP0P2YW9fBahQskJQcUXt/3jsCsMTWea4rWc3HZGh03bAkJfLM+PDSOfTpvAZ
6DQSp9QLzC9bgVNnq3W0SvOZGpF0xRa4InCyTUgxsNsV4+GIrmN5w4EbRFVVYu7D
5OS5fxNSCukiS0fb6oQzUp0vIAycvvWHHbAy8T6UMoUor2nfvNcryiaOX5WBMLyh
yMZ5gMOyXjdm1bT1XSlvtXPYUzxvsGAzTqS8mXjw8h7mm5htAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBABZ+I7D6wkeSrsi1NBLP2zoZ5oGh+INNcGTravfOQHs4Fbas
/CysaUYjsD3fmaDh4MxgWEqAmWnnBiojfpGX2SGuFqRBKyT9DgitBt0L7Ezg1k3h
bfSiFW4hXWp75grVO8xfML7ZcWMlhKrOsOMUGiy1qs3qsyJ3w7B2Tz78HhXGO5dd
jyPmZarhixKO92UpEvKGxjO0E/3UUNUzxKTAAgFfhKpuwHUgIijM/EppZtA8OcSh
fEztiV0xKfcPVx4d6dqRt/NMElK1Ivw2vUuxTymphZkkFOzht9m73/kyKaeFp8Ij
VRus1zGVD8IVpIdPMyz01WJyS7M0fWaHXKWo+Bo=
-----END CERTIFICATE-----";

    // A different, validly self-signed cert with a different key/fingerprint.
    const MISMATCH_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMRcwFQYDVQQDEw5Mb2Nh
bFNlbmQgVXNlcjEJMAcGA1UEChMAMQkwBwYDVQQLEwAxCTAHBgNVBAcTADEJMAcG
A1UECBMAMQkwBwYDVQQGEwAwHhcNMjUwMjA5MDI1ODQxWhcNMzUwMjA3MDI1ODQx
WjBQMRcwFQYDVQQDEw5Mb2NhbFNlbmQgVXNlcjEJMAcGA1UEChMAMQkwBwYDVQQL
EwAxCTAHBgNVBAcTADEJMAcGA1UECBMAMQkwBwYDVQQGEwAwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCnrVjQQ0mAfBaucJd5rbZX9usLROwHDuXdczFq
XJhb8pPjEF18FoDHzobjz5JWq+GDkBmcg0k6+AeETGQEaJisZDBWH7NOjJahGGnQ
0okw1iVUoEpQ26ZSFkr3H5NNtGAa6EkS4xb0bsEDb3vs69zRvFyrVd6OEqmdsRy3
aU2AvAMoLthgY8bUZ/XyWpbA8euV3VjkRSHsju+DOQH4oj46ZITJ3M2/x5o/3jqJ
ILBhoLcu7UJJTHYqeBsPSTkMIGKLkYSUPOd/mSgwQB854wks4nf+hO4VWvKQFx9X
4gIjS7vJ6e9rQOn2NFfluPbRiijmWIiwUDUWz3UW2RS0b6gDAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBAAO3rG2YcQqH8Z7jDX82q0nn/bglOWvTySv4EP3FNrVPZKfN
aR+oLo8WdAWulbxXDIOK7XLk1V9SxEJvVxOTp2EIgcoWqJANoWjp+5nNInE02eNX
G8euvPvh+p/1cTbHxhrZqtsSpkAx1AbbbcvT+5hUUDXSU7cMN+vFjUqkEVrBlj7S
vFbLDHP82ywisZrkOfNapxV67U4ENaEwJ4P4OERnqOOieJr0elv598cSDu+OSKmt
rFNYYHERELX36g4+KcWGN223Pg4Xl0bFYqV0xwRUThh0657t8cioXaOsjjpKnGAm
eVVihnrJ3sdk7nnreAYMse/OipyufRyZ9t3WU8A=
-----END CERTIFICATE-----";

    // Self-signed cert whose not_before == not_after == 2025-02-09 (already expired
    // by the real system clock in 2026). Same key as GOOD_CERT.
    const EXPIRED_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMRcwFQYDVQQDEw5Mb2Nh
bFNlbmQgVXNlcjEJMAcGA1UEChMAMQkwBwYDVQQLEwAxCTAHBgNVBAcTADEJMAcG
A1UECBMAMQkwBwYDVQQGEwAwHhcNMjUwMjA5MjEwOTQ0WhcNMjUwMjA5MjEwOTQ0
WjBQMRcwFQYDVQQDEw5Mb2NhbFNlbmQgVXNlcjEJMAcGA1UEChMAMQkwBwYDVQQL
EwAxCTAHBgNVBAcTADEJMAcGA1UECBMAMQkwBwYDVQQGEwAwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCL24MxhGfrdJm0Q8ZGiBkZ27ldcEChB4w7rSbJ
yiKeosoNbJl2kyj5dZjfBhWGgDLGDMM5w+Mh/5SrWgTL/QrhbB+lsrxILLznWqBi
R8wJP0P2YW9fBahQskJQcUXt/3jsCsMTWea4rWc3HZGh03bAkJfLM+PDSOfTpvAZ
6DQSp9QLzC9bgVNnq3W0SvOZGpF0xRa4InCyTUgxsNsV4+GIrmN5w4EbRFVVYu7D
5OS5fxNSCukiS0fb6oQzUp0vIAycvvWHHbAy8T6UMoUor2nfvNcryiaOX5WBMLyh
yMZ5gMOyXjdm1bT1XSlvtXPYUzxvsGAzTqS8mXjw8h7mm5htAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBAH2/F6iEH8W5gIHcKJ6/EbrG2BY5Uhg5U8X6yPk6z9ctmY6w
n7fDT749PMVDJq+qhIcnoBlUgVJdJ2qFa5h3VaSF+tUFu/CImr+S8TYHCdQGYXA5
6b/pnHmbrWqZdNdxs6Y80A9Mu+iNeLDcrTo60/zGfJsiD9Cnlj0Q6c8nn+Obzeqq
iIwUmPFw0krH+ku/DlSenKnyL8jaktf48neufu0jObUvCuj62I2WlFZwzXd8CnDR
X2/mKq6FWHCDR6RTh1yMLfD+NoVNcswxwMFq8ILCfBuTjNVaSFm3eUqKeEOAaDes
nidU/qXQvBJ7NPUkXXgbcgqxK735iijOqQHmKts=
-----END CERTIFICATE-----";

    fn cert_der(pem_str: &str) -> CertificateDer<'static> {
        let contents = pem::parse(pem_str).expect("valid PEM fixture").into_contents();
        CertificateDer::from(contents)
    }

    #[test]
    fn fingerprint_of_der_matches_for_same_cert() {
        let der = cert_der(GOOD_CERT_PEM);
        let fp = fingerprint_of_der(der.as_ref());
        // Idempotent and deterministic.
        assert_eq!(fp, fingerprint_of_der(der.as_ref()));
        assert_eq!(fp.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn accepts_cert_with_matching_fingerprint() {
        let expected = fingerprint_of_der(cert_der(GOOD_CERT_PEM).as_ref());
        let verifier = PinnedServerCertVerifier::new(Some(expected));
        let cert = cert_der(GOOD_CERT_PEM);
        let result = verifier.verify_server_cert(&cert, &[], &ServerName::try_from("x").unwrap(), &[], UnixTime::now());
        assert!(result.is_ok(), "matching fingerprint must be accepted");
    }

    #[test]
    fn rejects_cert_with_mismatching_fingerprint() {
        // Pin to GOOD_CERT's fingerprint, present MISMATCH_CERT.
        let good_fp = fingerprint_of_der(cert_der(GOOD_CERT_PEM).as_ref());
        let verifier = PinnedServerCertVerifier::new(Some(good_fp));
        let cert = cert_der(MISMATCH_CERT_PEM);
        let result = verifier.verify_server_cert(&cert, &[], &ServerName::try_from("x").unwrap(), &[], UnixTime::now());
        assert!(
            matches!(result, Err(Error::InvalidCertificate(_))),
            "mismatching fingerprint must be rejected at handshake time, got: {result:?}"
        );
    }

    #[test]
    fn accepts_fingerprint_with_uppercase_and_colons() {
        // The advertised fingerprint may carry colons / uppercase; normalization
        // must still match.
        let good_fp = fingerprint_of_der(cert_der(GOOD_CERT_PEM).as_ref());
        let decorated = format_colons_upper(&good_fp);
        let verifier = PinnedServerCertVerifier::new(Some(decorated));
        let cert = cert_der(GOOD_CERT_PEM);
        let result = verifier.verify_server_cert(&cert, &[], &ServerName::try_from("x").unwrap(), &[], UnixTime::now());
        assert!(result.is_ok(), "normalized fingerprint must match, got: {result:?}");
    }

    #[test]
    fn tofu_mode_accepts_any_validly_signed_cert() {
        let verifier = PinnedServerCertVerifier::new(None);
        let cert = cert_der(GOOD_CERT_PEM);
        let result = verifier.verify_server_cert(&cert, &[], &ServerName::try_from("x").unwrap(), &[], UnixTime::now());
        assert!(result.is_ok(), "TOFU mode must accept a valid self-signed cert");
    }

    #[test]
    fn rejects_expired_cert_even_in_tofu_mode() {
        let verifier = PinnedServerCertVerifier::new(None);
        let cert = cert_der(EXPIRED_CERT_PEM);
        let result = verifier.verify_server_cert(&cert, &[], &ServerName::try_from("x").unwrap(), &[], UnixTime::now());
        assert!(
            matches!(result, Err(Error::InvalidCertificate(_))),
            "expired cert must be rejected even in TOFU mode, got: {result:?}"
        );
    }

    fn format_colons_upper(hex: &str) -> String {
        hex.chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>().to_uppercase())
            .collect::<Vec<_>>()
            .join(":")
    }
}
