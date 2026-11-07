//! Unit tests of `plugins/mqtt`.

#![allow(clippy::unwrap_used)]

use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// Reads one MQTT packet: first byte, remaining length, body.
async fn read_packet(stream: &mut tokio::net::TcpStream) -> Option<(u8, Vec<u8>)> {
    let first = stream.read_u8().await.ok()?;
    let (mut length, mut shift) = (0usize, 0);
    loop {
        let byte = stream.read_u8().await.ok()?;
        length |= usize::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.ok()?;
    Some((first, body))
}

/// A small MQTT 3.1.1 broker: answers `CONNECT` with `connack` and acknowledges one `QoS` 1 `PUBLISH`.
async fn fake_broker(connack: u8) -> (u16, Arc<Mutex<Vec<(String, String)>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let published: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let log = published.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        while let Some((first, body)) = read_packet(&mut stream).await {
            match first >> 4 {
                1 => stream.write_all(&[0x20, 2, 0, connack]).await.unwrap(),
                3 => {
                    let topic_length = usize::from(u16::from_be_bytes([body[0], body[1]]));
                    let topic = String::from_utf8(body[2..2 + topic_length].to_vec()).unwrap();
                    let id = [body[2 + topic_length], body[3 + topic_length]];
                    let payload = String::from_utf8(body[4 + topic_length..].to_vec()).unwrap();
                    log.lock().unwrap().push((topic, payload));
                    stream.write_all(&[0x40, 2, id[0], id[1]]).await.unwrap();
                }
                _ => {}
            }
        }
    });
    (port, published)
}

fn mqtt(port: u16, extra: &str, data: &Path) -> Result<Mqtt, Error> {
    let table: toml::Table = toml::from_str(&format!(
        "host = \"127.0.0.1\"\nport = {port}\ntopic = \"lanlord/notification\"\n{extra}"
    ))
    .unwrap();
    Mqtt::new("broker".to_owned(), table, data)
}

#[tokio::test]
async fn notifications_are_published_as_json() {
    let data = tempfile::tempdir().unwrap();
    let (port, published) = fake_broker(0).await;
    let broker = mqtt(port, "", data.path()).unwrap();
    assert!(broker.notifies());
    assert_eq!(broker.kind(), "mqtt");
    assert_eq!(broker.observe().await.unwrap(), Observation::default());
    broker.notify(Notification::test()).await.unwrap();
    let published = published.lock().unwrap();
    assert_eq!(published[0].0, "lanlord/notification");
    let body: serde_json::Value = serde_json::from_str(&published[0].1).unwrap();
    assert_eq!(body["title"], "lanlord test");
    assert_eq!(body["source"], "lanlord");
}

#[tokio::test]
async fn a_refused_connection_is_reported() {
    let data = tempfile::tempdir().unwrap();
    let (port, _) = fake_broker(5).await;
    let error = mqtt(port, "", data.path())
        .unwrap()
        .notify(Notification::test())
        .await
        .unwrap_err();
    assert_eq!(error, "broker: the broker refused the user or password");
}

#[test]
fn packets_follow_mqtt_3_1_1() {
    assert_eq!(
        framed(0x10, &[0; 200])[..3],
        [0x10, 0xc8, 0x01],
        "long lengths use two bytes"
    );
    let connect = connect_packet("id", Some(("me", "pw")));
    assert_eq!(
        connect[8..10],
        [4, 0xc2],
        "protocol level and flags with user and password"
    );
    assert!(connect.ends_with(b"\0\x02me\0\x02pw"));
    assert_eq!(connect_packet("id", None)[9], 0x02, "clean session only");
    let publish = publish_packet("a/b", b"x");
    assert_eq!(publish, [0x32, 8, 0, 3, b'a', b'/', b'b', 0, 1, b'x']);
}

#[tokio::test]
async fn a_user_and_password_are_sent() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("mqtt.password");
    std::fs::write(&path, format!("{:x}\n", std::process::id())).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let (port, published) = fake_broker(0).await;
    let broker = mqtt(
        port,
        "user = \"me\"\npassword_file = \"mqtt.password\"\n",
        data.path(),
    )
    .unwrap();
    broker.notify(Notification::test()).await.unwrap();
    assert_eq!(published.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_missing_broker_is_reported() {
    let data = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let error = mqtt(port, "", data.path())
        .unwrap()
        .notify(Notification::test())
        .await
        .unwrap_err();
    assert!(error.starts_with("broker: "), "{error}");
}

#[test]
fn settings_are_checked() {
    let data = tempfile::tempdir().unwrap();
    let fingerprint = format!("certificate = \"{}\"\n", "00".repeat(32));
    assert_eq!(mqtt(1883, "", data.path()).unwrap().security, Security::Plain);
    assert_eq!(
        mqtt(8883, "tls = true\n", data.path()).unwrap().security,
        Security::PublicCertificate
    );
    let pinned = mqtt(8883, &format!("tls = true\n{fingerprint}"), data.path()).unwrap();
    assert_eq!(pinned.security, Security::Pinned([0; 32]));
    let error = |extra: &str| mqtt(1883, extra, data.path()).err().unwrap().to_string();
    assert!(error(&fingerprint).contains("needs TLS"));
    assert!(error("user = \"me\"\n").contains("go together"));
    assert!(error("tls = true\ncertificate = \"12\"\n").contains("invalid certificate"));
    let table: toml::Table = toml::from_str("host = \"a\"\nport = 1883\ntopic = \"home/#\"\n").unwrap();
    assert!(Mqtt::new("broker".to_owned(), table, data.path()).is_err());
}
