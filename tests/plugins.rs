//! Managing plugin configuration through the web interface.

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
    let response = post(&data, "/plugins", "type=leases-file&name=router&path=dhcp.leases").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let settings_path = data.path().join("lanlord.toml");
    assert_eq!(lanlord::plugins::load(&settings_path).plugins.len(), 1);

    let response = post(&data, "/plugins/router/enabled", "").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(lanlord::plugins::load(&settings_path).plugins.is_empty());

    let response = post(&data, "/plugins/router", "path=router.leases").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let settings = lanlord::plugins::read_settings(&settings_path).unwrap();
    assert_eq!(settings.plugins[0]["path"].as_str(), Some("router.leases"));
    assert_eq!(settings.plugins[0]["enabled"].as_bool(), Some(false));

    let (status, page) = get(&data, "/plugins").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("router.leases"));
    assert!(page.contains(r#"id="plugin-search""#));
}

#[tokio::test]
async fn page_offers_the_built_in_types() {
    let data = tempfile::tempdir().unwrap();
    let (status, page) = get(&data, "/plugins").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(r#"aria-current="page">Plugins</a>"#));
    assert!(page.contains(r#"name="type" value="leases-file""#));
    assert!(page.contains(r#"name="type" value="openwrt""#));
    assert!(page.contains(r#"name="type" value="pihole""#));
    assert!(page.contains(r#"placeholder="pihole.password""#));
    assert!(!page.contains("telepathy"));
}

#[tokio::test]
async fn openwrt_plugin_can_be_added_and_configured() {
    let data = tempfile::tempdir().unwrap();
    let response = post(
        &data,
        "/plugins",
        "type=openwrt&name=router&url=https%3A%2F%2Frouter.lan&user=lanlord&password_file=router.password&certificate=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let settings_path = data.path().join("lanlord.toml");
    let active = lanlord::plugins::load(&settings_path).plugins;
    assert_eq!(active[0].kind(), "openwrt");

    let response = post(
        &data,
        "/plugins/router",
        "url=https%3A%2F%2Frouter2.lan&user=lanlord&password_file=router.password&certificate=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let settings = lanlord::plugins::read_settings(&settings_path).unwrap();
    assert_eq!(settings.plugins[0]["url"].as_str(), Some("https://router2.lan"));
    assert!(
        !settings.plugins[0].contains_key("password"),
        "only the file name is stored"
    );
}

#[tokio::test]
async fn invalid_settings_are_rejected_with_a_message() {
    let data = tempfile::tempdir().unwrap();
    for (form, message) in [
        (
            "type=leases-file&name=a&path=%2Fetc%2Fpasswd",
            "file name in the data directory",
        ),
        (
            "type=leases-file&name=a&path=..%2Flanlord.toml",
            "file name in the data directory",
        ),
        ("type=leases-file&name=a&path=", "Lease file is required"),
        (
            "type=openwrt&name=a&url=http%3A%2F%2Frouter.lan&user=lanlord&password_file=p&certificate=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
            "the address must use https://",
        ),
        (
            "type=openwrt&name=a&url=https%3A%2F%2Frouter.lan&user=lanlord&password_file=p&certificate=1234",
            "must be 64 hex digits",
        ),
        ("type=telepathy&name=a", "Choose a supported plugin type"),
        (
            "type=leases-file&name=a%20b&path=dhcp.leases",
            "invalid plugin name",
        ),
    ] {
        let response = post(&data, "/plugins", form).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{form}");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let page = String::from_utf8(body.to_vec()).unwrap();
        assert!(page.contains(message), "{form}: {page}");
    }
    assert!(!data.path().join("lanlord.toml").exists());
}

#[tokio::test]
async fn scan_reports_unknown_devices_that_can_be_added() {
    let data = tempfile::tempdir().unwrap();
    let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/groups.toml");
    std::fs::copy(example, data.path().join("groups.toml")).unwrap();
    std::fs::write(
        data.path().join("devices.toml"),
        "[[device]]\nname = \"known\"\nmac = \"00:00:00:00:00:01\"\ngroup = \"lan\"\n",
    )
    .unwrap();
    std::fs::write(
        data.path().join("dhcp.leases"),
        "1793900000 00:11:22:33:44:55 192.0.2.45 new-device *\n1793900000 00:00:00:00:00:01 192.0.2.2 known *\n",
    )
    .unwrap();
    assert_eq!(
        post(&data, "/plugins", "type=leases-file&name=router&path=dhcp.leases")
            .await
            .status(),
        StatusCode::SEE_OTHER
    );

    let response = post(&data, "/plugins/scan", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let page = String::from_utf8(body.to_vec()).unwrap();
    assert!(page.contains("1 discrepancy"), "{page}");
    assert!(page.contains("Unknown device new-device (00:11:22:33:44:55, 192.0.2.45)"));
    assert!(
        page.contains(r#"action="/devices/discovered""#),
        "unknown devices can be added to a filled list"
    );

    let response = post(
        &data,
        "/devices/discovered",
        "name=new-device&mac=00:11:22:33:44:55",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let devices = std::fs::read_to_string(data.path().join("devices.toml")).unwrap();
    assert!(devices.contains("name = \"new-device\""), "{devices}");
}

#[tokio::test]
async fn failing_plugins_are_reported_without_stopping_the_scan() {
    let data = tempfile::tempdir().unwrap();
    assert_eq!(
        post(
            &data,
            "/plugins",
            "type=leases-file&name=missing&path=nope.leases"
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    let response = post(&data, "/plugins/scan", "").await;
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let page = String::from_utf8(body.to_vec()).unwrap();
    assert!(page.contains("Scan failed"), "{page}");
    assert!(page.contains("nope.leases"));
}

/// The `router` entry of an older lanlord version, with SSH settings the current OpenWrt plugin does not know.
const OLD_ENTRY: &str = "[[plugin]]\ntype = \"openwrt\"\nname = \"router\"\nenabled = true\nhost = \"router.lan\"\nport = 22\nuser = \"root\"\nkey_file = \"router.key\"\nhost_key_file = \"router.pub\"\n";
const LEASES_ENTRY: &str =
    "[[plugin]]\ntype = \"leases-file\"\nname = \"leases\"\nenabled = true\npath = \"dhcp.leases\"\n";

#[tokio::test]
async fn broken_entries_are_left_out_without_stopping_lanlord() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("lanlord.toml"),
        format!("{OLD_ENTRY}{LEASES_ENTRY}"),
    )
    .unwrap();

    let loaded = lanlord::plugins::load(&data.path().join("lanlord.toml"));
    assert_eq!(loaded.plugins.len(), 1, "the working plugin is still loaded");
    assert_eq!(loaded.plugins[0].name(), "leases");
    assert!(loaded.problems[0].as_deref().unwrap().contains("router"));

    let (status, page) = get(&data, "/plugins").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Left out: router: Address is required"), "{page}");
    assert!(page.contains(r#"action="/plugins/router/delete""#));
}

#[tokio::test]
async fn new_settings_replace_the_old_fields() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(data.path().join("lanlord.toml"), OLD_ENTRY).unwrap();
    let response = post(
        &data,
        "/plugins/router",
        "url=https%3A%2F%2Frouter.lan&user=lanlord&password_file=router.password&certificate=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let saved = std::fs::read_to_string(data.path().join("lanlord.toml")).unwrap();
    assert!(!saved.contains("key_file"), "{saved}");
    assert_eq!(
        lanlord::plugins::load(&data.path().join("lanlord.toml")).all_problems(),
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn broken_entries_can_be_deleted() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("lanlord.toml"),
        format!("{OLD_ENTRY}{LEASES_ENTRY}"),
    )
    .unwrap();
    assert_eq!(
        post(&data, "/plugins/router/delete", "").await.status(),
        StatusCode::SEE_OTHER
    );
    let saved = std::fs::read_to_string(data.path().join("lanlord.toml")).unwrap();
    assert!(!saved.contains("router"), "{saved}");
    assert!(saved.contains("leases"));
    let response = post(&data, "/plugins/nope/delete", "").await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_broken_settings_file_is_shown_not_fatal() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(data.path().join("lanlord.toml"), "this is = not [valid").unwrap();
    let loaded = lanlord::plugins::load(&data.path().join("lanlord.toml"));
    assert!(loaded.plugins.is_empty());
    assert!(loaded.file_problem.is_some());
    let (status, page) = get(&data, "/plugins").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("lanlord.toml"), "{page}");
}
