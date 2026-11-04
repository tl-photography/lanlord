//! Managing plugin configuration through the web interface.

#![allow(clippy::unwrap_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

fn app(data: &TempDir) -> Router {
    lanlord::app(lanlord::AppState::load(data.path()).unwrap())
}

async fn post(data: &TempDir, path: &str, form: &str) -> axum::response::Response {
    let request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(form.to_owned()))
        .unwrap();
    app(data).oneshot(request).await.unwrap()
}

async fn get(data: &TempDir, path: &str) -> (StatusCode, String) {
    let response = app(data)
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn plugins_can_be_added_configured_and_toggled() {
    let data = tempfile::tempdir().unwrap();
    let response = post(
        &data,
        "/plugins",
        "kind=leases-file&name=router&path=%2Fdata%2Fdhcp.leases",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let settings_path = data.path().join("lanlord.toml");
    let active = lanlord::plugins::load(&settings_path).unwrap();
    assert_eq!(active.len(), 1);

    let response = post(&data, "/plugins/router/enabled", "").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(lanlord::plugins::load(&settings_path).unwrap().is_empty());

    let response = post(&data, "/plugins/router", "path=%2Fdata%2Frouter.leases").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let settings = lanlord::plugins::read_settings(&settings_path).unwrap();
    assert_eq!(settings.plugins[0]["path"].as_str(), Some("/data/router.leases"));
    assert_eq!(settings.plugins[0]["enabled"].as_bool(), Some(false));

    let page = get(&data, "/plugins").await;
    assert_eq!(page.0, StatusCode::OK);
    assert!(page.1.contains("router"));
    assert!(page.1.contains("/data/router.leases"));
}

#[tokio::test]
async fn plugin_search_input_and_tab_are_rendered() {
    let data = tempfile::tempdir().unwrap();
    let page = get(&data, "/plugins").await;
    assert_eq!(page.0, StatusCode::OK);
    assert!(page.1.contains(r#"id="plugin-search""#));
    assert!(page.1.contains(r#"aria-current="page">Plugins</a>"#));
}
