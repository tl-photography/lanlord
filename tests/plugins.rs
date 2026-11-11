//! Managing plugin configuration through the web interface.

#![allow(clippy::unwrap_used)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::app;
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

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
async fn enabled_plugins_come_first_and_are_sorted() {
    let data = tempfile::tempdir().unwrap();
    for name in ["aaa", "ccc", "bbb"] {
        post(
            &data,
            "/plugins",
            &format!("type=leases-file&name={name}&path=dhcp.leases"),
        )
        .await;
    }
    post(&data, "/plugins/aaa/enabled", "").await;

    let (_, page) = get(&data, "/plugins").await;
    let position = |text: &str| page.find(text).unwrap();
    assert!(position(r#"plugin-group">Enabled"#) < position("<h2>bbb</h2>"));
    assert!(position("<h2>bbb</h2>") < position("<h2>ccc</h2>"));
    assert!(position("<h2>ccc</h2>") < position(r#"plugin-group">Disabled"#));
    assert!(position(r#"plugin-group">Disabled"#) < position("<h2>aaa</h2>"));
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
    assert!(page.contains(r#"<input type="checkbox" name="report_devices" value="true">"#));
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
    assert!(
        page.contains("New device new-device (00:11:22:33:44:55) added to"),
        "{page}"
    );
    assert!(
        page.contains("No discrepancies"),
        "the new device is in the list now: {page}"
    );
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
    assert!(
        page.contains("Left out: router: Password file is required"),
        "{page}"
    );
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

#[tokio::test]
async fn switches_are_saved_as_yes_or_no() {
    let data = tempfile::tempdir().unwrap();
    let fingerprint = "00".repeat(32);
    let form = format!(
        "type=pihole&name=dns&url=https%3A%2F%2Fpi.hole&password_file=pihole.password&certificate={fingerprint}"
    );
    assert_eq!(
        post(&data, "/plugins", &form).await.status(),
        StatusCode::SEE_OTHER
    );
    let path = data.path().join("lanlord.toml");
    let saved = |path: &std::path::Path| {
        lanlord::plugins::read_settings(path).unwrap().plugins[0]["report_devices"].as_bool()
    };
    assert_eq!(saved(&path), Some(false), "an unchecked box sends nothing");

    let form = format!(
        "url=https%3A%2F%2Fpi.hole&password_file=pihole.password&certificate={fingerprint}&report_devices=true"
    );
    assert_eq!(
        post(&data, "/plugins/dns", &form).await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(saved(&path), Some(true));
    let (_, page) = get(&data, "/plugins").await;
    assert!(page.contains(r#"name="report_devices" value="true" checked"#));
}

#[tokio::test]
async fn notification_plugins_send_a_test_on_request() {
    use std::sync::{Arc, Mutex};
    let received: Arc<Mutex<Vec<String>>> = Arc::default();
    let shared = received.clone();
    let handler = move |body: String| {
        let shared = shared.clone();
        async move {
            shared.lock().unwrap().push(body);
            StatusCode::NO_CONTENT
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new().route("/hook", axum::routing::post(handler)),
        )
        .await
    });

    let data = tempfile::tempdir().unwrap();
    let form = format!("type=webhook&name=hook&url=http%3A%2F%2F127.0.0.1%3A{port}%2Fhook&token_file=");
    assert_eq!(
        post(&data, "/plugins", &form).await.status(),
        StatusCode::SEE_OTHER,
        "the token file is optional"
    );
    let (_, page) = get(&data, "/plugins").await;
    assert!(page.contains("Send test notification"));

    let response = post(&data, "/plugins/hook/test", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8(body.to_vec())
            .unwrap()
            .contains("hook: test notification sent")
    );
    assert!(received.lock().unwrap()[0].contains("lanlord test"));

    let response = post(&data, "/plugins/nothing/test", "").await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn an_older_entry_without_a_switch_still_loads() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("lanlord.toml");
    std::fs::write(
        &path,
        format!(
            "[[plugin]]\ntype = \"pihole\"\nname = \"dns\"\nenabled = true\nurl = \"https://pi.hole\"\n\
             password_file = \"pihole.password\"\ncertificate = \"{}\"\n",
            "00".repeat(32)
        ),
    )
    .unwrap();
    let loaded = lanlord::plugins::load(&path);
    assert_eq!(loaded.all_problems(), Vec::<String>::new());
    assert_eq!(loaded.plugins.len(), 1);
}

#[tokio::test]
async fn plugins_can_be_renamed() {
    let data = tempfile::tempdir().unwrap();
    assert_eq!(
        post(&data, "/plugins", "type=leases-file&name=one&path=a.leases")
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        post(&data, "/plugins", "type=leases-file&name=two&path=b.leases")
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    let (_, page) = get(&data, "/plugins").await;
    assert!(page.contains(r#"name="new_name" value="one""#), "{page}");

    let response = post(&data, "/plugins/one", "path=a.leases&new_name=first").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let settings = lanlord::plugins::read_settings(&data.path().join("lanlord.toml")).unwrap();
    assert_eq!(settings.plugins[0]["name"].as_str(), Some("first"));
    let (_, history) = get(&data, "/history").await;
    assert!(history.contains("Plugin one renamed to first"), "{history}");
    assert!(!history.contains("Plugin one deleted"));

    let response = post(&data, "/plugins/first", "path=a.leases&new_name=two").await;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "the name is taken"
    );
    let response = post(&data, "/plugins/first", "path=a.leases&new_name=a%20b").await;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid name"
    );
}
