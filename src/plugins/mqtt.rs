//! Plugin `mqtt`: publishes notifications as JSON to a topic on an MQTT broker, for example for openHAB or Home
//! Assistant to turn into a push message.
//!
//! lanlord only publishes, so the few MQTT 3.1.1 packets this needs are written here: `CONNECT`, one `PUBLISH` with
//! `QoS` 1, its `PUBACK`, `DISCONNECT`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::openwrt::{parse_fingerprint, pinned_tls, read_password};
use super::{BoxFuture, Field, FieldKind, Plugin, PluginType, settings};
use crate::compare::Observation;
use crate::devices::Error;
use crate::notify::{Notification, public_tls};

/// Longest time for connecting, publishing and the broker's acknowledgement.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// The type description for `lanlord.toml` and the web interface.
pub(super) const TYPE: PluginType = PluginType {
    kind: "mqtt",
    title: "MQTT",
    description: "Publishes notifications as JSON (title, text) to a topic on an MQTT broker.",
    fields: &[
        Field {
            key: "host",
            label: "Broker",
            kind: FieldKind::Word,
            placeholder: "mosquitto",
            optional: false,
        },
        Field {
            key: "port",
            label: "Port",
            kind: FieldKind::Port,
            placeholder: "1883",
            optional: false,
        },
        Field {
            key: "topic",
            label: "Topic",
            kind: FieldKind::Word,
            placeholder: "lanlord/notification",
            optional: false,
        },
        Field {
            key: "user",
            label: "User (optional)",
            kind: FieldKind::Word,
            placeholder: "lanlord",
            optional: true,
        },
        Field {
            key: "password_file",
            label: "Password file (optional)",
            kind: FieldKind::DataFile,
            placeholder: "mqtt.password",
            optional: true,
        },
        Field {
            key: "certificate",
            label: "Certificate fingerprint (optional, for a self-signed broker)",
            kind: FieldKind::Fingerprint,
            placeholder: "AB:CD:...",
            optional: true,
        },
        Field {
            key: "tls",
            label: "TLS (usually port 8883)",
            kind: FieldKind::Switch,
            placeholder: "",
            optional: true,
        },
    ],
    build: |name, table, data_dir| Ok(Arc::new(Mqtt::new(name, table, data_dir)?)),
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    host: String,
    port: u16,
    topic: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password_file: String,
    #[serde(default)]
    certificate: String,
    #[serde(default)]
    tls: bool,
}

/// How the connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Security {
    Plain,
    PublicCertificate,
    Pinned([u8; 32]),
}

/// One broker and topic.
pub struct Mqtt {
    name: String,
    host: String,
    port: u16,
    topic: String,
    user: String,
    password_file: Option<PathBuf>,
    security: Security,
}

impl Mqtt {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let settings: Settings = settings(&name, table)?;
        let invalid = |message: &str| Error::Invalid(format!("{name}: {message}"));
        if settings.topic.is_empty() || settings.topic.contains(['#', '+']) {
            return Err(invalid(
                "the topic must not be empty or contain the wildcards # and +",
            ));
        }
        if settings.user.is_empty() != settings.password_file.is_empty() {
            return Err(invalid("user and password file go together"));
        }
        let security = match (settings.tls, settings.certificate.is_empty()) {
            (false, true) => Security::Plain,
            (false, false) => return Err(invalid("a certificate fingerprint needs TLS")),
            (true, true) => Security::PublicCertificate,
            (true, false) => Security::Pinned(
                parse_fingerprint(&settings.certificate)
                    .ok_or_else(|| invalid("invalid certificate fingerprint"))?,
            ),
        };
        Ok(Self {
            password_file: (!settings.password_file.is_empty())
                .then(|| data_dir.join(&settings.password_file)),
            name,
            host: settings.host,
            port: settings.port,
            topic: settings.topic,
            user: settings.user,
            security,
        })
    }

    /// Connects, publishes with `QoS` 1, waits for the broker's acknowledgement and disconnects.
    async fn publish(&self, notification: Notification) -> Result<(), String> {
        let payload = json!({ "title": notification.title, "text": notification.text, "source": "lanlord" })
            .to_string();
        let password = match &self.password_file {
            Some(path) => Some(read_password(path).await?),
            None => None,
        };
        let credentials = password.as_deref().map(|password| (self.user.as_str(), password));
        let connect = connect_packet(&format!("lanlord-{}", self.name), credentials);
        let publish = publish_packet(&self.topic, payload.as_bytes());
        let tls = match self.security {
            Security::Plain => None,
            Security::PublicCertificate => Some(public_tls()?),
            Security::Pinned(fingerprint) => Some(pinned_tls(fingerprint)?),
        };
        let fail = |error: String| format!("{}: {error}", self.name);
        let session = async {
            let tcp = TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|error| error.to_string())?;
            match tls {
                None => exchange(tcp, &connect, &publish).await,
                Some(tls) => {
                    let server =
                        ServerName::try_from(self.host.clone()).map_err(|error| error.to_string())?;
                    let stream = TlsConnector::from(Arc::new(tls))
                        .connect(server, tcp)
                        .await
                        .map_err(|error| error.to_string())?;
                    exchange(stream, &connect, &publish).await
                }
            }
        };
        tokio::time::timeout(PUBLISH_TIMEOUT, session)
            .await
            .map_err(|_| fail(format!("no answer within {} s", PUBLISH_TIMEOUT.as_secs())))?
            .map_err(fail)
    }
}

/// The packet id of the one `PUBLISH` of a connection.
const PACKET_ID: u16 = 1;

/// A string or binary field: two bytes of length, then the bytes.
fn put_field(packet: &mut Vec<u8>, bytes: &[u8]) {
    let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&bytes[..usize::from(length)]);
}

/// The fixed header: packet type and the remaining length, seven bits per byte.
fn framed(first: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![first];
    let mut length = body.len();
    loop {
        let byte = u8::try_from(length % 128).unwrap_or(0);
        length /= 128;
        packet.push(if length > 0 { byte | 0x80 } else { byte });
        if length == 0 {
            break;
        }
    }
    packet.extend_from_slice(body);
    packet
}

/// `CONNECT` for MQTT 3.1.1 with a clean session, 30 s keep alive and optional user and password.
fn connect_packet(client_id: &str, credentials: Option<(&str, &str)>) -> Vec<u8> {
    let mut body = Vec::new();
    put_field(&mut body, b"MQTT");
    body.push(4);
    body.push(if credentials.is_some() { 0xc2 } else { 0x02 });
    body.extend_from_slice(&30u16.to_be_bytes());
    put_field(&mut body, client_id.as_bytes());
    if let Some((user, password)) = credentials {
        put_field(&mut body, user.as_bytes());
        put_field(&mut body, password.as_bytes());
    }
    framed(0x10, &body)
}

/// `PUBLISH` with `QoS` 1, not retained.
fn publish_packet(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    put_field(&mut body, topic.as_bytes());
    body.extend_from_slice(&PACKET_ID.to_be_bytes());
    body.extend_from_slice(payload);
    framed(0x32, &body)
}

/// Sends `CONNECT`, checks `CONNACK`, sends `PUBLISH`, waits for its `PUBACK` and disconnects.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    connect: &[u8],
    publish: &[u8],
) -> Result<(), String> {
    let failed = |error: std::io::Error| format!("connection failed: {error}");
    stream.write_all(connect).await.map_err(failed)?;
    let mut answer = [0u8; 4];
    stream.read_exact(&mut answer).await.map_err(failed)?;
    if answer[0] != 0x20 {
        return Err("the broker did not answer with CONNACK".to_owned());
    }
    match answer[3] {
        0 => {}
        4 | 5 => return Err("the broker refused the user or password".to_owned()),
        code => return Err(format!("the broker refused the connection, code {code}")),
    }
    stream.write_all(publish).await.map_err(failed)?;
    stream.read_exact(&mut answer).await.map_err(failed)?;
    if answer[0] != 0x40 || answer[2..4] != PACKET_ID.to_be_bytes() {
        return Err("the broker did not acknowledge the message".to_owned());
    }
    // The message is delivered; a failed goodbye changes nothing.
    let _ = stream.write_all(&[0xe0, 0]).await;
    let _ = stream.shutdown().await;
    Ok(())
}

impl Plugin for Mqtt {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "mqtt"
    }

    fn observe(&self) -> BoxFuture<'_, Result<Observation, String>> {
        Box::pin(async { Ok(Observation::default()) })
    }

    fn notifies(&self) -> bool {
        true
    }

    fn notify(&self, notification: Notification) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(self.publish(notification))
    }
}

#[cfg(test)]
mod tests;
