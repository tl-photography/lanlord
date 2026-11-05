//! Plugins linked to devices: the dropdown, the badge on the device card and renames.

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
        "default_group = \"lan\"\n[[group]]\nname = \"lan\"\nvlan = 1\n",
    )
    .unwrap();
    std::fs::write(
        data.path().join("devices.toml"),
        "[[device]]\nname = \"LivingRoomAP\"\nmac = \"00:00:00:00:00:01\"\ngroup = \"lan\"\nip = \"192.0.2.5\"\n",
    )
    .unwrap();
    data
}

#[tokio::test]
async fn a_plugin_linked_to_a_device_follows_its_rename() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (_, page) = send(&app, get("/plugins")).await;
    assert!(page.contains(r#"<select name="device">"#), "{page}");
    assert!(page.contains(r#"<option value="LivingRoomAP">LivingRoomAP</option>"#));

    let form = format!(
        "type=openwrt&name=ap&url=&user=lanlord&password_file=ap.password&certificate={}&device=LivingRoomAP",
        "00".repeat(32)
    );
    assert_eq!(send(&app, post("/plugins", &form)).await.0, StatusCode::SEE_OTHER);
    assert_eq!(
        lanlord::plugins::load(&data.path().join("lanlord.toml")).all_problems(),
        Vec::<String>::new()
    );

    let (_, page) = send(&app, get("/")).await;
    assert!(
        page.contains(r#"title="Plugin ap talks to this device">ap</span>"#),
        "{page}"
    );

    let rename = "name=Devolo&mac=00:00:00:00:00:01&group=lan&ip=192.0.2.5&note=";
    assert_eq!(
        send(&app, post("/devices/LivingRoomAP", rename)).await.0,
        StatusCode::SEE_OTHER
    );
    let settings = lanlord::plugins::read_settings(&data.path().join("lanlord.toml")).unwrap();
    assert_eq!(settings.plugins[0]["device"].as_str(), Some("Devolo"));
    let (_, page) = send(&app, get("/history")).await;
    assert!(
        page.contains("Plugin ap changed: device LivingRoomAP → Devolo"),
        "{page}"
    );
    let (_, page) = send(&app, get("/")).await;
    assert!(page.contains(">ap</span>"), "the badge moved with the name");
}
