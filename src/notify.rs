//! Notifications: what lanlord tells the notification plugins, and the HTTP client they share.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;

/// One notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Short subject.
    pub title: String,
    /// What happened.
    pub text: String,
}

impl Notification {
    /// The notification the "Send test notification" button sends.
    #[must_use]
    pub fn test() -> Self {
        Self {
            title: "lanlord test".to_owned(),
            text: "Test notification from lanlord: this plugin works.".to_owned(),
        }
    }
}

/// TLS settings that trust the usual public certificate authorities.
///
/// # Errors
///
/// If the TLS configuration cannot be built.
pub fn public_tls() -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// An HTTP client that trusts the usual public certificate authorities (built in, the image has no CA files).
///
/// # Errors
///
/// If the TLS configuration cannot be built.
pub fn public_client() -> Result<Client, String> {
    Client::builder()
        .use_preconfigured_tls(public_tls()?)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| error.to_string())
}
