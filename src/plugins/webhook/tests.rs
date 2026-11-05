//! Unit tests of `plugins/webhook`.

#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;

use super::*;

/// What the fake server received: authorization header and body.
type Received = Arc<Mutex<Vec<(Option<String>, String)>>>;

/// A server that records every request and answers with `status`.
pub(crate) async fn fake_server(status: StatusCode) -> (String, Received) {
    use axum::{Router, routing::post};
    let received: Received = Arc::default();
    let shared = received.clone();
    let handler = move |headers: HeaderMap, body: String| {
        let shared = shared.clone();
        async move {
            let authorization = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let title = headers
                .get("title")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = title.map_or(body.clone(), |title| format!("{title}|{body}"));
            shared.lock().unwrap().push((authorization, body));
            status
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, Router::new().fallback(post(handler))).await });
    (format!("http://127.0.0.1:{}", address.port()), received)
}

fn token_file(data: &Path, token: &str) {
    let path = data.join("hook.token");
    std::fs::write(&path, token).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn webhook(url: &str, token_file: &str, data: &Path) -> Result<Webhook, Error> {
    let table: toml::Table =
        toml::from_str(&format!("url = \"{url}\"\ntoken_file = \"{token_file}\"\n")).unwrap();
    Webhook::new("hook".to_owned(), table, data)
}

#[tokio::test]
async fn notifications_are_posted_as_json_with_the_token() {
    let data = tempfile::tempdir().unwrap();
    let token = format!("{:x}", std::process::id());
    token_file(data.path(), &format!("{token}\n"));
    let (url, received) = fake_server(StatusCode::NO_CONTENT).await;
    let hook = webhook(&format!("{url}/hooks/lanlord"), "hook.token", data.path()).unwrap();
    assert!(hook.notifies());
    assert_eq!(
        hook.observe().await.unwrap(),
        crate::compare::Observation::default()
    );
    hook.notify(Notification::test()).await.unwrap();

    let received = received.lock().unwrap();
    assert_eq!(received[0].0.as_deref(), Some(format!("Bearer {token}").as_str()));
    let body: Value = serde_json::from_str(&received[0].1).unwrap();
    assert_eq!(body["title"], "lanlord test");
    assert_eq!(body["source"], "lanlord");
}

#[tokio::test]
async fn errors_and_unsafe_addresses_are_reported() {
    let data = tempfile::tempdir().unwrap();
    let (url, received) = fake_server(StatusCode::FORBIDDEN).await;
    let hook = webhook(&url, "", data.path()).unwrap();
    assert_eq!(
        hook.notify(Notification::test()).await.unwrap_err(),
        "hook: HTTP 403"
    );
    assert_eq!(received.lock().unwrap()[0].0, None, "no token, no header");

    assert!(
        webhook("http://hooks.lan/x", "", data.path()).is_ok(),
        "plain http without a token"
    );
    assert!(
        webhook("http://hooks.lan/x", "hook.token", data.path()).is_err(),
        "a token needs https"
    );
    assert!(webhook("ftp://hooks.lan/x", "", data.path()).is_err());
    assert!(webhook("not a url", "", data.path()).is_err());

    let missing = webhook(&url, "missing.token", data.path()).unwrap();
    assert!(
        missing
            .notify(Notification::test())
            .await
            .unwrap_err()
            .contains("missing.token")
    );
}
