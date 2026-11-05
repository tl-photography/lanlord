//! Plugin `webhook`: sends notifications as JSON to a URL, optionally with a bearer token from a file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use reqwest::{Client, RequestBuilder, Url};
use serde::Deserialize;
use serde_json::json;

use super::openwrt::read_password;
use super::{BoxFuture, Field, FieldKind, Plugin, PluginType, settings};
use crate::devices::Error;
use crate::notify::{Notification, public_client};

/// The type description for `lanlord.toml` and the web interface.
pub(super) const TYPE: PluginType = PluginType {
    kind: "webhook",
    title: "Webhook",
    description: "Sends notifications as JSON (title, text) with POST to a URL.",
    fields: &[
        Field {
            key: "url",
            label: "URL",
            kind: FieldKind::Url,
            placeholder: "https://example.org/hooks/lanlord",
            optional: false,
        },
        Field {
            key: "token_file",
            label: "Bearer token file (optional)",
            kind: FieldKind::DataFile,
            placeholder: "webhook.token",
            optional: true,
        },
    ],
    build: |name, table, data_dir| Ok(Arc::new(Webhook::new(name, table, data_dir)?)),
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    url: String,
    #[serde(default)]
    token_file: String,
}

/// Checks a notification address. A token must not travel unencrypted: with one, plain `http` is only allowed to
/// the own host.
pub(super) fn notification_url(name: &str, url: &str, has_token: bool) -> Result<Url, Error> {
    let invalid = |message: &str| Error::Invalid(format!("{name}: {message}"));
    let url = Url::parse(url).map_err(|_| invalid("invalid address"))?;
    let local = matches!(url.host_str(), Some("127.0.0.1" | "localhost"));
    match url.scheme() {
        "https" => Ok(url),
        "http" if !has_token || local => Ok(url),
        "http" => Err(invalid("with a token, the address must use https://")),
        _ => Err(invalid("the address must use http:// or https://")),
    }
}

/// Adds the bearer token, if there is a token file.
pub(super) async fn with_token(
    request: RequestBuilder,
    token_file: Option<&Path>,
) -> Result<RequestBuilder, String> {
    match token_file {
        Some(path) => Ok(request.bearer_auth(read_password(path).await?)),
        None => Ok(request),
    }
}

/// Sends the request and turns an error status into text.
pub(super) async fn send(name: &str, request: RequestBuilder) -> Result<(), String> {
    let response = request.send().await.map_err(|error| format!("{name}: {error}"))?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("{name}: HTTP {}", status.as_u16()))
    }
}

/// One webhook.
pub struct Webhook {
    name: String,
    url: Url,
    token_file: Option<PathBuf>,
    client: Client,
}

impl Webhook {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let Settings { url, token_file } = settings(&name, table)?;
        let url = notification_url(&name, &url, !token_file.is_empty())?;
        let client = public_client().map_err(|error| Error::Invalid(format!("{name}: {error}")))?;
        Ok(Self {
            name,
            url,
            token_file: (!token_file.is_empty()).then(|| data_dir.join(token_file)),
            client,
        })
    }

    async fn post(&self, notification: Notification) -> Result<(), String> {
        let body = json!({ "title": notification.title, "text": notification.text, "source": "lanlord" });
        let request = self.client.post(self.url.clone()).json(&body);
        send(&self.name, with_token(request, self.token_file.as_deref()).await?).await
    }
}

impl Plugin for Webhook {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "webhook"
    }

    fn observe(&self) -> BoxFuture<'_, Result<crate::compare::Observation, String>> {
        Box::pin(async { Ok(crate::compare::Observation::default()) })
    }

    fn notifies(&self) -> bool {
        true
    }

    fn notify(&self, notification: Notification) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(self.post(notification))
    }
}

#[cfg(test)]
pub(crate) mod tests;
