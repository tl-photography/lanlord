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
    assert!(page.1.contains("<details open>"));
}

#[tokio::test]
async fn openwrt_plugin_can_be_added_and_configured() {
    let data = tempfile::tempdir().unwrap();
    let response = post(
        &data,
        "/plugins",
        "kind=openwrt&name=router&host=router.lan&user=root&port=22&key_file=%2Fdata%2Fssh%2Frouter&host_key_file=%2Fdata%2Fssh%2Frouter.pub",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let settings_path = data.path().join("lanlord.toml");
    let active = lanlord::plugins::load(&settings_path).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].kind(), "openwrt");

    let response = post(
        &data,
        "/plugins/router",
        "host=router2.lan&user=root&port=2222&key_file=%2Fdata%2Fssh%2Frouter&host_key_file=%2Fdata%2Fssh%2Frouter.pub",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let settings = lanlord::plugins::read_settings(&settings_path).unwrap();
    assert_eq!(settings.plugins[0]["host"].as_str(), Some("router2.lan"));
    assert_eq!(settings.plugins[0]["port"].as_integer(), Some(2222));

    let page = get(&data, "/plugins").await;
    assert_eq!(page.0, StatusCode::OK);
    assert!(page.1.contains("router2.lan"));
    assert!(page.1.contains("/data/ssh/router.pub"));
}

#[tokio::test]
async fn pihole_plugin_can_be_configured_without_storing_a_password() {
    let data = tempfile::tempdir().unwrap();
    let response = post(
        &data,
        "/plugins",
        "kind=pihole&name=pihole&url=http%3A%2F%2Fpihole&password_file=%2Fdata%2Fssh%2Fpihole-password",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let settings_path = data.path().join("lanlord.toml");
    let active = lanlord::plugins::load(&settings_path).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].kind(), "pihole");
    let saved = std::fs::read_to_string(settings_path).unwrap();
    assert!(saved.contains("/data/ssh/pihole-password"));
    assert!(!saved.contains("password ="));
    let page = get(&data, "/plugins").await;
    assert!(page.1.contains(r#"<details class="plugin-config" open>"#));
}

#[tokio::test]
async fn pihole_plugin_stores_only_the_password_file_path() {
    let data = tempfile::tempdir().unwrap();
    let response = post(
        &data,
        "/plugins",
        "kind=pihole&name=pihole&url=http%3A%2F%2Fpihole&password_file=%2Fdata%2Fssh%2Fpihole-password",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let settings = lanlord::plugins::read_settings(&data.path().join("lanlord.toml")).unwrap();
    assert_eq!(settings.plugins[0]["url"].as_str(), Some("http://pihole"));
    assert_eq!(
        settings.plugins[0]["password_file"].as_str(),
        Some("/data/ssh/pihole-password")
    );
    assert!(!settings.plugins[0].contains_key("password"));
}

#[tokio::test]
async fn scan_reports_unknown_devices_from_active_sources() {
    let data = tempfile::tempdir().unwrap();
    let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/groups.toml");
    std::fs::copy(example, data.path().join("groups.toml")).unwrap();
    let lease_path = data.path().join("dhcp.leases");
    std::fs::write(
        &lease_path,
        "1793900000 00:11:22:33:44:55 192.0.2.45 new-device *\n",
    )
    .unwrap();
    let mut plugin = toml::Table::new();
    plugin.insert("type".to_owned(), toml::Value::String("leases-file".to_owned()));
    plugin.insert("name".to_owned(), toml::Value::String("router".to_owned()));
    plugin.insert("enabled".to_owned(), toml::Value::Boolean(true));
    plugin.insert(
        "path".to_owned(),
        toml::Value::String(lease_path.display().to_string()),
    );
    lanlord::plugins::save_settings(
        &data.path().join("lanlord.toml"),
        &lanlord::plugins::Settings {
            plugins: vec![plugin],
        },
    )
    .unwrap();

    let response = post(&data, "/plugins/scan", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let page = String::from_utf8(body.to_vec()).unwrap();
    assert!(page.contains("Scan results"));
    assert!(page.contains("Unknown device new-device"));
    assert!(page.contains("00:11:22:33:44:55"));
    assert!(page.contains(r#"action="/devices/discovered""#));
    assert!(page.contains(r#"value="new-device""#));
}
