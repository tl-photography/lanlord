//! The settings page and what the overview and the plugin page show.

#![allow(clippy::unwrap_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn get(path: &str) -> Request<Body> {
    Request::get(path).body(Body::empty()).unwrap()
}

fn post(path: &str, form: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(form.to_owned()))
        .unwrap()
}

fn data() -> TempDir {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("groups.toml"),
        "default_group = \"lan\"\n[[group]]\nname = \"lan\"\nvlan = 1\nlabel = \"LAN\"\n",
    )
    .unwrap();
    std::fs::write(
        data.path().join("devices.toml"),
        "[[device]]\nname = \"tv\"\nmac = \"00:00:00:00:00:09\"\nip = \"192.0.2.9\"\ngroup = \"lan\"\n\n[[device]]\nname = \"lamp\"\nmac = \"00:00:00:00:00:0a\"\ngroup = \"lan\"\n",
    )
    .unwrap();
    data
}

#[tokio::test]
async fn addresses_are_shown_until_switched_off() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (_, page) = send(&app, get("/")).await;
    assert!(
        page.contains("192.0.2.9 · <code>00:00:00:00:00:09</code>"),
        "{page}"
    );
    let (_, page) = send(&app, get("/settings")).await;
    assert_eq!(page.matches(" checked").count(), 2, "{page}");

    let (status, _) = send(&app, post("/settings", "show_ip=true")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = send(&app, get("/")).await;
    assert!(page.contains("192.0.2.9"), "{page}");
    assert!(!page.contains("<code>"), "{page}");
    assert!(!page.contains(" · "), "{page}");

    let (status, _) = send(&app, post("/settings", "show_mac=true")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = send(&app, get("/")).await;
    assert!(!page.contains("192.0.2.9"), "{page}");
    assert!(page.contains("<code>00:00:00:00:00:09</code>"), "{page}");

    let (status, _) = send(&app, post("/settings", "")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = send(&app, get("/")).await;
    assert!(!page.contains("class=\"meta\""), "{page}");
    assert!(page.contains("<strong>tv</strong>"), "{page}");

    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(log.contains("Overview changed: MAC hidden, IP shown"), "{log}");
}

#[tokio::test]
async fn saving_the_settings_keeps_the_other_settings() {
    let data = data();
    std::fs::write(
        data.path().join("lanlord.toml"),
        "[scan]\ninterval_minutes = 5\nrestore = false\n",
    )
    .unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    send(&app, post("/settings", "show_mac=true")).await;
    let saved = std::fs::read_to_string(data.path().join("lanlord.toml")).unwrap();
    assert!(saved.contains("interval_minutes = 5"), "{saved}");
    assert!(saved.contains("show_ip = false"), "{saved}");

    let (_, page) = send(&app, get("/settings")).await;
    assert_eq!(page.matches(" checked").count(), 1, "{page}");
}

#[tokio::test]
async fn a_plugin_shows_its_device_as_a_plain_badge() {
    let data = data();
    std::fs::write(
        data.path().join("lanlord.toml"),
        "[[plugin]]\nname = \"hook\"\ntype = \"webhook\"\nenabled = false\nurl = \"https://192.0.2.1/x\"\n\n[[plugin]]\nname = \"leases\"\ntype = \"leases-file\"\nenabled = false\npath = \"dhcp.leases\"\n",
    )
    .unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/plugins")).await;
    assert!(!page.contains("badge linked"), "{page}");

    let router = "[[plugin]]\nname = \"router\"\ntype = \"openwrt\"\nenabled = false\ndevice = \"tv\"\nuser = \"lanlord\"\npassword_file = \"router.password\"\ncertificate_sha256 = \"00\"\n";
    std::fs::write(data.path().join("lanlord.toml"), router).unwrap();
    let (_, page) = send(&app, get("/plugins")).await;
    assert!(page.contains("class=\"badge linked\""), "{page}");
    assert!(page.contains(">tv</span>"), "{page}");
    assert!(!page.contains("<a href=\"/devices/tv\""), "{page}");
}

#[tokio::test]
async fn interface_badges_sit_side_by_side_without_addresses() {
    let data = data();
    let path = data.path().join("devices.toml");
    let list = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        list.replace("name = \"lamp\"", "name = \"lamp\"\nmachine = \"desk\""),
    )
    .unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (_, page) = send(&app, get("/")).await;
    assert!(!page.contains("connections compact"), "{page}");
    send(&app, post("/settings", "")).await;
    let (_, page) = send(&app, get("/")).await;
    assert!(page.contains("connections compact"), "{page}");
}
