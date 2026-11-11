//! Adding and changing devices through the forms.

#![allow(clippy::unwrap_used)]

mod common;

use common::app;
use std::path::Path;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

const DEVICES: &str = r#"
[[device]]
name = "alpha"
mac = "00:00:00:00:00:01"
group = "iot"
note = "say \"hi\""

[[device]]
name = "beta"
mac = "00:00:00:00:00:02"
group = "lan"
"#;

fn data() -> TempDir {
    let data = tempfile::tempdir().unwrap();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/groups.toml");
    std::fs::copy(example, data.path().join("groups.toml")).unwrap();
    std::fs::write(data.path().join("devices.toml"), DEVICES).unwrap();
    data
}

fn devices(data: &TempDir) -> String {
    std::fs::read_to_string(data.path().join("devices.toml")).unwrap()
}

async fn body(response: axum::response::Response) -> String {
    String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

/// A form post like a browser sends it from lanlord's own page.
async fn post(data: &TempDir, path: &str, form: &str) -> axum::response::Response {
    let request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(form.to_owned()))
        .unwrap();
    app(data).oneshot(request).await.unwrap()
}

async fn get(data: &TempDir, path: &str) -> axum::response::Response {
    app(data)
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn new_device_is_added() {
    let data = data();
    let response = post(
        &data,
        "/devices",
        "name=gamma&mac=AA-BB-CC-00-11-22&group=guest&ip=192.0.2.30&note=new",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/");
    let file = devices(&data);
    assert!(file.contains("name = \"gamma\""));
    assert!(file.contains("mac = \"aa:bb:cc:00:11:22\""), "MAC is normalized");
    assert!(file.contains("ip = \"192.0.2.30\""));
}

#[tokio::test]
async fn device_can_move_and_be_renamed() {
    let data = data();
    let response = post(
        &data,
        "/devices/alpha",
        "name=alpha2&mac=00:00:00:00:00:01&group=lan",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let file = devices(&data);
    assert!(file.contains("name = \"alpha2\""));
    assert!(!file.contains("name = \"alpha\""));
    assert_eq!(file.matches("group = \"lan\"").count(), 2);
}

#[tokio::test]
async fn move_menu_changes_only_the_device_group() {
    let data = data();
    let response = post(&data, "/devices/alpha/move", "group=guest").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let list: lanlord::devices::DeviceList = toml::from_str(&devices(&data)).unwrap();
    let moved = list
        .interfaces
        .iter()
        .find(|device| device.name == "alpha")
        .unwrap();
    assert_eq!(moved.group, "guest");
    assert_eq!(moved.mac, "00:00:00:00:00:01");
    assert_eq!(moved.note, "say \"hi\"");
}

#[tokio::test]
async fn move_menu_rejects_unknown_groups_without_writing() {
    let data = data();
    let response = post(&data, "/devices/alpha/move", "group=unknown").await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(devices(&data), DEVICES);
}

#[tokio::test]
async fn invalid_input_shows_the_form_again_and_changes_nothing() {
    for (form, message) in [
        ("name=gamma&mac=nope&group=lan", "Invalid MAC address"),
        (
            "name=gamma&mac=00:00:00:00:00:03&group=lan&ip=300.1.1.1",
            "Invalid IP address",
        ),
        ("name=beta&mac=00:00:00:00:00:03&group=lan", "duplicate name"),
        (
            "name=gamma&mac=00:00:00:00:00:02&group=lan",
            "duplicate MAC address",
        ),
        ("name=gam_ma&mac=00:00:00:00:00:03&group=lan", "invalid name"),
        ("name=gamma&mac=00:00:00:00:00:03&group=office", "unknown group"),
    ] {
        let data = data();
        let response = post(&data, "/devices", form).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{form}");
        let page = body(response).await;
        assert!(page.contains(message), "{form}: {page}");
        assert_eq!(devices(&data), DEVICES, "{form}");
    }
}

#[tokio::test]
async fn cross_site_posts_are_rejected() {
    let data = data();
    let request = Request::post("/devices/alpha")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "cross-site")
        .body(Body::from("name=alpha&mac=00:00:00:00:00:01&group=guest"))
        .unwrap();
    let response = app(&data).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(devices(&data), DEVICES);
}

#[tokio::test]
async fn edit_form_shows_the_device_escaped() {
    let data = data();
    let response = get(&data, "/devices/alpha").await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body(response).await;
    assert!(page.contains(r#"value="alpha""#));
    assert!(!page.contains(r#"say "hi""#), "quotes in values are escaped");
    assert!(page.contains(r#"<option value="iot" selected>"#));
}

#[tokio::test]
async fn unknown_devices_are_not_found() {
    let data = data();
    assert_eq!(get(&data, "/devices/nope").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        post(&data, "/devices/nope/move", "group=guest").await.status(),
        StatusCode::NOT_FOUND
    );
    let response = post(
        &data,
        "/devices/nope",
        "name=nope&mac=00:00:00:00:00:09&group=lan",
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(devices(&data), DEVICES);
}

#[tokio::test]
async fn new_form_uses_the_default_group() {
    let data = data();
    let page = body(get(&data, "/devices/new").await).await;
    assert!(page.contains(r#"<option value="guest" selected>"#));
}
