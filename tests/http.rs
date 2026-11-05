//! Requests against the router without a network socket.

#![allow(clippy::unwrap_used)]

use std::path::Path;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

const DEVICES: &str = r#"
[[device]]
name = "zeta"
mac = "00:00:00:00:00:02"
group = "iot"
ip = "192.0.2.20"
note = "<script>alert(1)</script>"

[[device]]
name = "alpha"
mac = "00:00:00:00:00:01"
group = "iot"
"#;

/// A data directory with the example settings and two devices; kept alive as long as the router.
fn app() -> (TempDir, Router) {
    let data = tempfile::tempdir().unwrap();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/groups.toml");
    std::fs::copy(example, data.path().join("groups.toml")).unwrap();
    std::fs::write(data.path().join("devices.toml"), DEVICES).unwrap();
    let state = lanlord::AppState::load_without_login(data.path()).unwrap();
    (data, lanlord::app(state))
}

async fn send(path: &str) -> axum::response::Response {
    let (_data, app) = app();
    app.oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn get(path: &str) -> (StatusCode, String) {
    let response = send(path).await;
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn healthz_answers_ok() {
    assert_eq!(get("/healthz").await, (StatusCode::OK, "ok".to_owned()));
}

#[tokio::test]
async fn index_lists_the_devices_by_group() {
    let (status, body) = get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"<span class="title" title="IoT">IoT</span> <span class="badge">VLAN 20</span> <span class="count">2 devices</span>"#));
    assert!(body.contains(r#"<span class="title" title="LAN">LAN</span> <span class="badge">VLAN 1</span> <span class="count">0 devices</span>"#));
    let alpha = body.find("alpha").unwrap();
    let zeta = body.find("zeta").unwrap();
    assert!(alpha < zeta, "devices are sorted by name");
    assert!(body.contains("192.0.2.20"));
}

#[tokio::test]
async fn page_is_made_for_phones_too() {
    let (_, body) = get("/").await;
    assert!(body.contains(r#"name="viewport" content="width=device-width, initial-scale=1""#));
    assert!(
        body.contains(r#"class="card" href="/devices/alpha""#),
        "one card per device"
    );
    assert!(body.contains(r#"class="move-menu""#));
    assert!(body.contains(r#"data-move-group="lan""#));
    assert!(body.contains(r#"<script src="/app.js" defer></script>"#));
    assert!(body.contains(r#"<link rel="icon" href="/favicon.svg" type="image/svg+xml">"#));
}

#[tokio::test]
async fn without_targets_the_page_says_nothing_is_applied() {
    let (_, body) = get("/").await;
    assert!(body.contains("nothing is applied to the network"));
}

#[tokio::test]
async fn notes_are_escaped() {
    let (_, body) = get("/").await;
    assert!(!body.contains("<script>"));
    assert!(body.contains("&#60;script&#62;") || body.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn style_sheet_is_served_as_css() {
    let response = send("/style.css").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/css; charset=utf-8");
    let css = response.into_body().collect().await.unwrap().to_bytes();
    let css = String::from_utf8(css.to_vec()).unwrap();
    assert!(css.contains(".move-menu { position: relative; display: none; }"));
    assert!(css.contains(".move-menu[open] { display: block; }"));
    assert!(css.contains("a:focus-visible"));
    assert!(css.contains(".topbar nav a:hover { opacity: 1; border-color: var(--accent);"));
    assert!(!css.contains("transform: translateY(-1px)"));
}

#[tokio::test]
async fn favicon_is_only_the_house_mark() {
    let response = send("/favicon.svg").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "image/svg+xml");
    let svg = response.into_body().collect().await.unwrap().to_bytes();
    let svg = String::from_utf8(svg.to_vec()).unwrap();
    assert!(svg.contains("M 12 56 L 54 18 L 96 56"));
    assert!(!svg.contains("LANlord"));
}

#[tokio::test]
async fn unknown_path_is_not_found() {
    assert_eq!(get("/nope").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn devices_in_unknown_groups_stop_the_start() {
    let data = tempfile::tempdir().unwrap();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/groups.toml");
    std::fs::copy(example, data.path().join("groups.toml")).unwrap();
    std::fs::write(
        data.path().join("devices.toml"),
        DEVICES.replace("\"iot\"", "\"office\""),
    )
    .unwrap();
    assert!(lanlord::AppState::load_without_login(data.path()).is_err());
}

#[tokio::test]
async fn starts_without_groups_and_devices() {
    let data = tempfile::tempdir().unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let response = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let page = String::from_utf8(body.to_vec()).unwrap();
    assert!(page.contains("No groups yet"), "{page}");
    assert!(page.contains(r#"href="/groups""#));
}

#[tokio::test]
async fn every_response_has_the_security_headers() {
    for path in ["/", "/healthz", "/style.css", "/app.js", "/favicon.svg", "/nope"] {
        let response = send(path).await;
        let headers = response.headers();
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'self'"), "{path}: {csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{path}: {csp}");
        assert_eq!(headers["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(headers["x-frame-options"], "DENY", "{path}");
        assert_eq!(headers["referrer-policy"], "no-referrer", "{path}");
        assert_eq!(headers["cache-control"], "no-store", "{path}");
        assert_eq!(headers["cross-origin-embedder-policy"], "require-corp", "{path}");
    }
}
