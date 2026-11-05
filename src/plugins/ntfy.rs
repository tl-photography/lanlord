//! Plugin `ntfy`: sends notifications to a topic on an ntfy server, optionally with an access token from a file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use reqwest::{Client, Url};
use serde::Deserialize;

use super::webhook::{notification_url, send, with_token};
use super::{BoxFuture, Field, FieldKind, Plugin, PluginType, settings};
use crate::compare::Observation;
use crate::devices::Error;
use crate::notify::{Notification, public_client};

/// The type description for `lanlord.toml` and the web interface.
pub(super) const TYPE: PluginType = PluginType {
    kind: "ntfy",
    title: "ntfy",
    description: "Sends notifications to a topic on an ntfy server, for example ntfy.sh or your own.",
    fields: &[
        Field {
            key: "server",
            label: "Server",
            kind: FieldKind::Url,
            placeholder: "https://ntfy.sh",
            optional: false,
        },
        Field {
            key: "topic",
            label: "Topic",
            kind: FieldKind::Word,
            placeholder: "lanlord-home",
            optional: false,
        },
        Field {
            key: "token_file",
            label: "Access token file (optional)",
            kind: FieldKind::DataFile,
            placeholder: "ntfy.token",
            optional: true,
        },
    ],
    build: |name, table, data_dir| Ok(Arc::new(Ntfy::new(name, table, data_dir)?)),
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    server: String,
    topic: String,
    #[serde(default)]
    token_file: String,
}

/// One ntfy topic.
pub struct Ntfy {
    name: String,
    url: Url,
    token_file: Option<PathBuf>,
    client: Client,
}

impl Ntfy {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let Settings {
            server,
            topic,
            token_file,
        } = settings(&name, table)?;
        let invalid = |message: &str| Error::Invalid(format!("{name}: {message}"));
        if topic.is_empty()
            || !topic
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(invalid("the topic may only have letters, digits, - and _"));
        }
        let mut url = notification_url(&name, &server, !token_file.is_empty())?;
        url.path_segments_mut()
            .map_err(|()| invalid("invalid server address"))?
            .pop_if_empty()
            .push(&topic);
        let client = public_client().map_err(|error| invalid(&error))?;
        Ok(Self {
            name,
            url,
            token_file: (!token_file.is_empty()).then(|| data_dir.join(token_file)),
            client,
        })
    }

    async fn post(&self, notification: Notification) -> Result<(), String> {
        let request = self
            .client
            .post(self.url.clone())
            .header("Title", notification.title)
            .header("Tags", "lanlord")
            .body(notification.text);
        send(&self.name, with_token(request, self.token_file.as_deref()).await?).await
    }
}

impl Plugin for Ntfy {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "ntfy"
    }

    fn observe(&self) -> BoxFuture<'_, Result<Observation, String>> {
        Box::pin(async { Ok(Observation::default()) })
    }

    fn notifies(&self) -> bool {
        true
    }

    fn notify(&self, notification: Notification) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(self.post(notification))
    }
}

#[cfg(test)]
mod tests;
