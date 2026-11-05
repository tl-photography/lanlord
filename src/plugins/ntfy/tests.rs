//! Unit tests of `plugins/ntfy`.

#![allow(clippy::unwrap_used)]

use axum::http::StatusCode;

use super::*;
use crate::plugins::webhook::tests::fake_server;

fn ntfy(server: &str, topic: &str, token_file: &str, data: &Path) -> Result<Ntfy, Error> {
    let table: toml::Table = toml::from_str(&format!(
        "server = \"{server}\"\ntopic = \"{topic}\"\ntoken_file = \"{token_file}\"\n"
    ))
    .unwrap();
    Ntfy::new("phone".to_owned(), table, data)
}

#[tokio::test]
async fn notifications_go_to_the_topic_with_a_title() {
    let data = tempfile::tempdir().unwrap();
    let (server, received) = fake_server(StatusCode::OK).await;
    let topic = ntfy(&format!("{server}/"), "lanlord-home", "", data.path()).unwrap();
    assert_eq!(topic.url.path(), "/lanlord-home");
    assert!(topic.notifies());
    assert_eq!(topic.kind(), "ntfy");
    assert_eq!(topic.observe().await.unwrap(), Observation::default());
    topic.notify(Notification::test()).await.unwrap();
    let received = received.lock().unwrap();
    assert!(
        received[0].1.starts_with("lanlord test|Test notification"),
        "{:?}",
        received[0]
    );
}

#[test]
fn topics_and_addresses_are_checked() {
    let data = tempfile::tempdir().unwrap();
    assert!(ntfy("https://ntfy.sh", "a b", "", data.path()).is_err());
    assert!(ntfy("https://ntfy.sh", "a/b", "", data.path()).is_err());
    assert!(ntfy("http://ntfy.lan", "home", "ntfy.token", data.path()).is_err());
    assert!(ntfy("https://ntfy.sh", "home_1", "ntfy.token", data.path()).is_ok());
}
