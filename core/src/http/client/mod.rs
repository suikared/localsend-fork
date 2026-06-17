mod url;
pub mod v2;
pub mod v3;

pub use v2::LsHttpClientV2;
pub use v3::LsHttpClientV3;

use crate::http::StatusCodeError;
use crate::{crypto, http};
use reqwest::Response;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub enum LsHttpClient {
    V2(LsHttpClientV2),
    V3(LsHttpClientV3),
}

pub enum LsHttpClientVersion {
    V2,
    V3,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error(transparent)]
    StatusCode(StatusCodeError),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl LsHttpClient {
    pub fn new(
        private_key: &str,
        cert: &str,
        version: LsHttpClientVersion,
    ) -> Result<LsHttpClient, ClientError> {
        let client = match version {
            LsHttpClientVersion::V2 => {
                LsHttpClient::V2(LsHttpClientV2::try_new(&private_key, &cert)?)
            }
            LsHttpClientVersion::V3 => {
                LsHttpClient::V3(LsHttpClientV3::try_new(&private_key, &cert)?)
            }
        };

        Ok(client)
    }

    pub async fn register(
        &self,
        protocol: http::dto::ProtocolType,
        ip: &str,
        port: u16,
        payload: http::dto::RegisterDto,
    ) -> Result<ResultWithPublicKey<http::dto::RegisterResponseDto>, ClientError> {
        match self {
            LsHttpClient::V2(client) => {
                let result = client.register(protocol, ip, port, payload.into()).await?;
                Ok(ResultWithPublicKey {
                    public_key: result.public_key,
                    body: result.body.into(),
                })
            }
            LsHttpClient::V3(client) => client.register(protocol, ip, port, payload).await,
        }
    }

    pub async fn prepare_upload(
        &self,
        protocol: http::dto::ProtocolType,
        ip: &str,
        port: u16,
        fingerprint: Option<String>,
        payload: http::dto::PrepareUploadRequestDto,
        pin: Option<&str>,
    ) -> Result<http::dto::PrepareUploadResult, ClientError> {
        match self {
            LsHttpClient::V2(client) => {
                let result = client
                    .prepare_upload(protocol, ip, port, fingerprint, payload.into(), pin)
                    .await?;
                Ok(result.into())
            }
            LsHttpClient::V3(client) => {
                client
                    .prepare_upload(protocol, ip, port, fingerprint, payload)
                    .await
            }
        }
    }

    pub async fn upload(
        &self,
        protocol: http::dto::ProtocolType,
        ip: &str,
        port: u16,
        fingerprint: Option<String>,
        session_id: &str,
        file_id: &str,
        token: &str,
        binary: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), ClientError> {
        match self {
            LsHttpClient::V2(client) => {
                client
                    .upload(
                        protocol, ip, port, fingerprint, session_id, file_id, token, binary,
                    )
                    .await
            }
            LsHttpClient::V3(client) => {
                client
                    .upload(
                        protocol, ip, port, fingerprint, session_id, file_id, token, binary,
                    )
                    .await
            }
        }
    }

    pub async fn cancel(
        &self,
        protocol: http::dto::ProtocolType,
        ip: &str,
        port: u16,
        session_id: &str,
    ) -> Result<(), ClientError> {
        match self {
            LsHttpClient::V2(client) => client.cancel(protocol, ip, port, session_id).await,
            LsHttpClient::V3(client) => client.cancel(protocol, ip, port, session_id).await,
        }
    }
}

pub(super) fn create_reqwest_client(
    private_key: &str,
    cert: &str,
) -> Result<reqwest::Client, ClientError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let identity = {
        let pem = &[cert.as_bytes(), "\n".as_bytes(), private_key.as_bytes()].concat();
        reqwest::Identity::from_pem(pem)?
    };

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .identity(identity)
        .build()?;

    Ok(client)
}

/// Builds a reqwest client whose TLS handshake pins the peer to [expected_fingerprint]
/// (lowercase SHA-256 hex of the peer's DER leaf cert — the LocalSend device
/// `fingerprint`, advertised over multicast and carried by `Device.fingerprint`).
///
/// Unlike the TOFU client above, a MITM presenting a different certificate is rejected
/// *during the handshake*, before any request body (PIN, file bytes) is transmitted.
/// This is the core mitigation for C1-sec: request-side secrets are never sent to an
/// unverified peer.
///
/// The LocalSend receiver does not request a client certificate, so none is configured
/// here; the sender is authorized by IP binding and session token, not mTLS.
pub(super) fn build_pinned_reqwest_client(
    expected_fingerprint: &str,
) -> Result<reqwest::Client, ClientError> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let verifier: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier> =
        std::sync::Arc::new(
            crate::crypto::pinned_server_cert_verifier::PinnedServerCertVerifier::new(Some(
                expected_fingerprint.to_string(),
            )),
        );

    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(anyhow::Error::from)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let client = reqwest::Client::builder()
        // Pass the BARE ClientConfig, not Some(config): reqwest wraps it internally
        // (`let tls = Some(tls)`) and downcasts to Option<ClientConfig>. Wrapping
        // here too makes it Option<Option<_>> and yields "Unknown TLS backend".
        .use_preconfigured_tls(client_config)
        .tls_info(true)
        .build()?;

    Ok(client)
}

#[cfg(test)]
mod pinned_client_tests {
    use super::*;

    #[test]
    fn build_pinned_reqwest_client_succeeds() {
        let res = build_pinned_reqwest_client(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        match &res {
            Ok(_) => {}
            Err(e) => panic!("build_pinned_reqwest_client failed: {e:?}"),
        }
    }
}

/// Verifies the certificate from the response.
/// Returns the public key extracted from the certificate.
pub(super) fn verify_cert_from_res(
    response: &Response,
    public_key: Option<String>,
) -> anyhow::Result<String> {
    let tls_info_ext = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .ok_or_else(|| anyhow::anyhow!("TLS info not found"))?;
    let cert = tls_info_ext
        .peer_certificate()
        .ok_or_else(|| anyhow::anyhow!("Certificate not found"))?;
    crypto::cert::verify_cert_from_der(cert, public_key.as_deref())?;
    let public_key = match public_key {
        Some(public_key) => public_key,
        None => crypto::cert::public_key_from_cert_der(cert)?,
    };
    Ok(public_key)
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    message: String,
}

pub struct ResultWithPublicKey<T> {
    /// The public key extracted from the certificate.
    /// Encoded in PEM format.
    /// Only available in HTTPS mode.
    pub public_key: Option<String>,

    /// The response body.
    pub body: T,
}

pub(super) trait ResponseExt {
    async fn into_error<T>(self) -> Result<T, ClientError>;
}

impl ResponseExt for Response {
    async fn into_error<T>(self) -> Result<T, ClientError> {
        let status = self.status().as_u16();
        let body = self.text().await.unwrap_or_default();
        let message = match serde_json::from_str::<ErrorResponse>(&body) {
            Ok(error) => error.message,
            Err(_) => body,
        };
        Err(ClientError::StatusCode(StatusCodeError {
            status,
            message: if message.is_empty() {
                None
            } else {
                Some(message)
            },
        }))
    }
}
