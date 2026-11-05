//! Setting up the groups through the interface, starting from an empty data directory.

#![allow(clippy::unwrap_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

fn app(data: &TempDir) -> Router {
    lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap())
}

fn groups_file(data: &TempDir) -> String {
    std::fs::read_to_string(data.path().join("groups.toml")).unwrap_or_default()
}

async fn post(data: &TempDir, path: &str, form: &str) -> (StatusCode, String) {
    let request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(form.to_owned()))
        .unwrap();
    let response = app(data).oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

async fn setup() -> TempDir {
    let data = tempfile::tempdir().unwrap();
    assert_eq!(
        post(&data, "/groups", "name=lan&vlan=1&label=LAN").await.0,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        post(&data, "/groups", "name=guest&vlan=30").await.0,
        StatusCode::SEE_OTHER
    );
    data
}

#[tokio::test]
async fn first_group_becomes_the_default() {
    let data = setup().await;
    let file = groups_file(&data);
    assert!(file.contains("default_group = \"lan\""), "{file}");
    assert!(file.contains("name = \"guest\""));
    assert!(file.contains("vlan = 30"));
}

#[tokio::test]
async fn default_group_can_be_changed() {
    let data = setup().await;
    assert_eq!(
        post(&data, "/groups/default", "group=guest").await.0,
        StatusCode::SEE_OTHER
    );
    assert!(groups_file(&data).contains("default_group = \"guest\""));
    let (status, page) = post(&data, "/groups/default", "group=office").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("unknown default group"));
}

#[tokio::test]
async fn invalid_groups_are_rejected() {
    let data = setup().await;
    let before = groups_file(&data);
    for (form, message) in [
        ("name=iot&vlan=1", "duplicate VLAN"),
        ("name=lan&vlan=20", "duplicate group"),
        ("name=iot&vlan=5000", "VLAN must be 1 to 4094"),
        ("name=iot&vlan=abc", "The VLAN must be a number"),
        ("name=i_ot&vlan=20", "invalid group name"),
    ] {
        let (status, page) = post(&data, "/groups", form).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{form}");
        assert!(page.contains(message), "{form}: {page}");
        assert_eq!(groups_file(&data), before, "{form}");
    }
}

#[tokio::test]
async fn groups_with_devices_and_the_default_cannot_be_deleted() {
    let data = setup().await;
    let device = "name=tv&mac=00:00:00:00:00:01&group=guest";
    assert_eq!(post(&data, "/devices", device).await.0, StatusCode::SEE_OTHER);

    let (status, page) = post(&data, "/groups/guest/delete", "").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("still has devices"));

    let (status, page) = post(&data, "/groups/lan/delete", "").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("is the default group"));
}

#[tokio::test]
async fn unused_groups_can_be_deleted_down_to_none() {
    let data = setup().await;
    assert_eq!(
        post(&data, "/groups/guest/delete", "").await.0,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        post(&data, "/groups/lan/delete", "").await.0,
        StatusCode::SEE_OTHER
    );
    let file = groups_file(&data);
    assert!(!file.contains("[[group]]"), "{file}");
    assert!(file.contains("default_group = \"\""), "{file}");
}
