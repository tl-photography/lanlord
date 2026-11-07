//! Unit tests of `plugins/email`.

#![allow(clippy::unwrap_used)]

use std::sync::Mutex;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::*;

/// A small SMTP server without TLS: accepts one mail and records the conversation.
async fn fake_server(refuse_recipient: bool) -> (u16, Arc<Mutex<String>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received: Arc<Mutex<String>> = Arc::default();
    let log = received.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        writer.write_all(b"220 fake ESMTP\r\n").await.unwrap();
        let mut in_data = false;
        while let Ok(Some(line)) = lines.next_line().await {
            {
                let mut log = log.lock().unwrap();
                log.push_str(&line);
                log.push('\n');
            }
            let answer: &[u8] = if in_data {
                if line != "." {
                    continue;
                }
                in_data = false;
                b"250 queued\r\n"
            } else {
                match line
                    .split([' ', ':'])
                    .next()
                    .unwrap_or_default()
                    .to_ascii_uppercase()
                    .as_str()
                {
                    "RCPT" if refuse_recipient => b"550 no such user\r\n",
                    "EHLO" | "HELO" | "MAIL" | "RCPT" => b"250 ok\r\n",
                    "DATA" => {
                        in_data = true;
                        b"354 go on\r\n"
                    }
                    "QUIT" => {
                        writer.write_all(b"221 bye\r\n").await.unwrap();
                        break;
                    }
                    _ => b"500 what\r\n",
                }
            };
            writer.write_all(answer).await.unwrap();
        }
    });
    (port, received)
}

fn email(port: u16, security: &str, extra: &str, data: &Path) -> Result<Email, Error> {
    let table: toml::Table = toml::from_str(&format!(
        "server = \"127.0.0.1\"\nport = {port}\nsecurity = \"{security}\"\nfrom = \"lanlord@example.org\"\n\
         to = \"me@example.org\"\n{extra}"
    ))
    .unwrap();
    Email::new("mail".to_owned(), table, data)
}

#[tokio::test]
async fn notifications_are_sent_as_mail() {
    let data = tempfile::tempdir().unwrap();
    let (port, received) = fake_server(false).await;
    let mail = email(port, "none", "", data.path()).unwrap();
    assert!(mail.notifies());
    assert_eq!(mail.kind(), "email");
    assert_eq!(mail.observe().await.unwrap(), Observation::default());
    mail.notify(Notification::test()).await.unwrap();
    let received = received.lock().unwrap();
    assert!(received.contains("RCPT TO:<me@example.org>"), "{received}");
    assert!(received.contains("Subject: lanlord test"), "{received}");
    assert!(received.contains("Test notification from lanlord"), "{received}");
}

#[tokio::test]
async fn a_refused_mail_is_reported() {
    let data = tempfile::tempdir().unwrap();
    let (port, _) = fake_server(true).await;
    let mail = email(port, "none", "", data.path()).unwrap();
    let error = mail.notify(Notification::test()).await.unwrap_err();
    assert!(error.starts_with("mail: "), "{error}");
    assert!(error.contains("no such user"), "{error}");
}

#[test]
fn settings_are_checked() {
    let data = tempfile::tempdir().unwrap();
    let password = "user = \"me\"\npassword_file = \"mail.password\"\n";
    assert!(email(25, "starttls", password, data.path()).is_ok());
    assert!(email(465, "tls", "", data.path()).is_ok());
    let error =
        |security: &str, extra: &str| email(25, security, extra, data.path()).err().unwrap().to_string();
    assert!(error("plain", "").contains("must be starttls, tls or none"));
    assert!(error("none", password).contains("a password needs starttls or tls"));
    assert!(error("tls", "user = \"me\"\n").contains("go together"));
    let table: toml::Table = toml::from_str(
        "server = \"a\"\nport = 25\nsecurity = \"none\"\nfrom = \"not a mail\"\nto = \"me@example.org\"\n",
    )
    .unwrap();
    assert!(Email::new("mail".to_owned(), table, data.path()).is_err());
}
