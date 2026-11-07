//! Plugin `email`: sends notifications by mail through an SMTP server.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Deserialize;

use super::openwrt::read_password;
use super::{BoxFuture, Field, FieldKind, Plugin, PluginType, settings};
use crate::compare::Observation;
use crate::devices::Error;
use crate::notify::Notification;

/// Longest time for one step of the conversation with the server.
const SMTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The type description for `lanlord.toml` and the web interface.
pub(super) const TYPE: PluginType = PluginType {
    kind: "email",
    title: "Email",
    description: "Sends notifications by mail through an SMTP server.",
    fields: &[
        Field {
            key: "server",
            label: "SMTP server",
            kind: FieldKind::Word,
            placeholder: "mail.example.org",
            optional: false,
        },
        Field {
            key: "port",
            label: "Port",
            kind: FieldKind::Port,
            placeholder: "587",
            optional: false,
        },
        Field {
            key: "security",
            label: "Security: starttls, tls or none",
            kind: FieldKind::Word,
            placeholder: "starttls",
            optional: false,
        },
        Field {
            key: "from",
            label: "From",
            kind: FieldKind::Word,
            placeholder: "lanlord@example.org",
            optional: false,
        },
        Field {
            key: "to",
            label: "To",
            kind: FieldKind::Word,
            placeholder: "me@example.org",
            optional: false,
        },
        Field {
            key: "user",
            label: "User (optional)",
            kind: FieldKind::Word,
            placeholder: "lanlord@example.org",
            optional: true,
        },
        Field {
            key: "password_file",
            label: "Password file (optional)",
            kind: FieldKind::DataFile,
            placeholder: "mail.password",
            optional: true,
        },
    ],
    build: |name, table, data_dir| Ok(Arc::new(Email::new(name, table, data_dir)?)),
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    server: String,
    port: u16,
    security: String,
    from: String,
    to: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password_file: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Security {
    StartTls,
    Tls,
    None,
}

/// One server and recipient.
pub struct Email {
    name: String,
    server: String,
    port: u16,
    security: Security,
    from: Mailbox,
    to: Mailbox,
    user: String,
    password_file: Option<PathBuf>,
}

impl Email {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let settings: Settings = settings(&name, table)?;
        let invalid = |message: String| Error::Invalid(format!("{name}: {message}"));
        let security = match settings.security.as_str() {
            "starttls" => Security::StartTls,
            "tls" => Security::Tls,
            "none" => Security::None,
            other => {
                return Err(invalid(format!(
                    "security must be starttls, tls or none, not {other}"
                )));
            }
        };
        if settings.user.is_empty() != settings.password_file.is_empty() {
            return Err(invalid("user and password file go together".to_owned()));
        }
        if security == Security::None && !settings.password_file.is_empty() {
            return Err(invalid("a password needs starttls or tls".to_owned()));
        }
        let address = |text: &str| {
            text.parse::<Mailbox>()
                .map_err(|_| invalid(format!("invalid mail address {text}")))
        };
        let (from, to) = (address(&settings.from)?, address(&settings.to)?);
        Ok(Self {
            password_file: (!settings.password_file.is_empty())
                .then(|| data_dir.join(&settings.password_file)),
            name,
            server: settings.server,
            port: settings.port,
            security,
            from,
            to,
            user: settings.user,
        })
    }

    async fn send(&self, notification: Notification) -> Result<(), String> {
        let fail = |error: &dyn std::fmt::Display| format!("{}: {error}", self.name);
        let tls = || TlsParameters::new(self.server.clone()).map_err(|error| fail(&error));
        let mut mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.server)
            .port(self.port)
            .timeout(Some(SMTP_TIMEOUT))
            .tls(match self.security {
                Security::StartTls => Tls::Required(tls()?),
                Security::Tls => Tls::Wrapper(tls()?),
                Security::None => Tls::None,
            });
        if let Some(path) = &self.password_file {
            mailer = mailer.credentials(Credentials::new(self.user.clone(), read_password(path).await?));
        }
        let message = Message::builder()
            .from(self.from.clone())
            .to(self.to.clone())
            .subject(notification.title)
            .header(ContentType::TEXT_PLAIN)
            .body(notification.text)
            .map_err(|error| fail(&error))?;
        mailer.build().send(message).await.map_err(|error| fail(&error))?;
        Ok(())
    }
}

impl Plugin for Email {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "email"
    }

    fn observe(&self) -> BoxFuture<'_, Result<Observation, String>> {
        Box::pin(async { Ok(Observation::default()) })
    }

    fn notifies(&self) -> bool {
        true
    }

    fn notify(&self, notification: Notification) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(self.send(notification))
    }
}

#[cfg(test)]
mod tests;
