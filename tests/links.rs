//! Plugins linked to devices: the dropdown, the badge on the device card and renames.

#![allow(clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::{get, post, send};
use tempfile::TempDir;

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

#[tokio::test]
async fn a_rename_reaches_plugin_addresses_with_the_old_name() {
    let data = data();
    std::fs::write(
        data.path().join("lanlord.toml"),
        format!(
            "[[plugin]]\ntype = \"openwrt\"\nname = \"ap\"\nenabled = true\nurl = \"https://livingroomap.lan:8443\"\n\
             user = \"lanlord\"\npassword_file = \"ap.password\"\ncertificate = \"{}\"\n\n\
             [[plugin]]\ntype = \"openwrt\"\nname = \"other\"\nenabled = true\nurl = \"https://router.lan\"\n\
             user = \"lanlord\"\npassword_file = \"ap.password\"\ncertificate = \"{}\"\n",
            "00".repeat(32),
            "00".repeat(32)
        ),
    )
    .unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let rename = "name=Devolo&mac=00:00:00:00:00:01&group=lan&ip=192.0.2.5&note=";
    assert_eq!(
        send(&app, post("/devices/LivingRoomAP", rename)).await.0,
        StatusCode::SEE_OTHER
    );

    let settings = lanlord::plugins::read_settings(&data.path().join("lanlord.toml")).unwrap();
    assert_eq!(
        settings.plugins[0]["url"].as_str(),
        Some("https://devolo.lan:8443")
    );
    assert_eq!(
        settings.plugins[1]["url"].as_str(),
        Some("https://router.lan"),
        "other hosts stay"
    );
    let (_, page) = send(&app, get("/history")).await;
    assert!(
        page.contains("Plugin ap changed: url https://livingroomap.lan:8443 → https://devolo.lan:8443"),
        "{page}"
    );
}

#[tokio::test]
async fn a_plugin_named_like_its_device_shows_its_type() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("devices.toml"),
        "[[device]]\nname = \"router\"\nmac = \"00:00:00:00:00:01\"\ngroup = \"lan\"\nip = \"192.0.2.1\"\n",
    )
    .unwrap();
    std::fs::write(
        data.path().join("groups.toml"),
        "default_group = \"lan\"\n[[group]]\nname = \"lan\"\nvlan = 1\n",
    )
    .unwrap();
    std::fs::write(
        data.path().join("lanlord.toml"),
        format!(
            "[[plugin]]\ntype = \"openwrt\"\nname = \"router\"\nenabled = true\nurl = \"\"\nuser = \"lanlord\"\n\
             password_file = \"router.password\"\ncertificate = \"{}\"\ndevice = \"router\"\n",
            "00".repeat(32)
        ),
    )
    .unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/")).await;
    assert!(
        page.contains(r#"title="Plugin router talks to this device">OpenWrt</span>"#),
        "{page}"
    );
}
