//! The settings page and what the overview and the plugin page show.

#![allow(clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::{get, post, send};
use tempfile::TempDir;

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
        page.contains("<span>192.0.2.9</span><code>00:00:00:00:00:09</code>"),
        "{page}"
    );
    let (_, page) = send(&app, get("/settings")).await;
    assert_eq!(page.matches(" checked").count(), 2, "{page}");

    let (status, _) = send(&app, post("/settings", "show_ip=true")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = send(&app, get("/")).await;
    assert!(page.contains("192.0.2.9"), "{page}");
    assert!(!page.contains("<code>"), "{page}");

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

#[tokio::test]
async fn a_linked_plugin_shows_on_the_device() {
    let data = data();
    std::fs::write(
        data.path().join("lanlord.toml"),
        "[[plugin]]\nname = \"router\"\ntype = \"openwrt\"\nenabled = false\ndevice = \"tv\"\nuser = \"lanlord\"\npassword_file = \"router.password\"\ncertificate_sha256 = \"00\"\n",
    )
    .unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/")).await;
    assert!(page.contains("Plugin router talks to this device"), "{page}");
}

#[tokio::test]
async fn a_device_found_by_a_scan_is_new_until_someone_looks_at_it() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let path = data.path().join("devices.toml");
    let list = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!("{list}\n[[device]]\nname = \"stranger\"\nmac = \"00:00:00:00:00:0b\"\ngroup = \"lan\"\nunreviewed = true\n"),
    )
    .unwrap();
    let (_, page) = send(&app, get("/")).await;
    assert!(page.contains(r#"class="badge new""#), "{page}");
    assert_eq!(
        page.matches("Found by a scan, not reviewed yet").count(),
        1,
        "{page}"
    );
    let (_, page) = send(&app, get("/devices/stranger")).await;
    assert!(page.contains("A scan found this device"), "{page}");

    let form = "name=stranger&mac=00%3A00%3A00%3A00%3A00%3A0b&group=lan";
    assert_eq!(
        send(&app, post("/devices/stranger", form)).await.0,
        StatusCode::SEE_OTHER
    );
    let (_, page) = send(&app, get("/")).await;
    assert_eq!(
        page.matches("Found by a scan, not reviewed yet").count(),
        0,
        "{page}"
    );
    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(log.contains("reviewed"), "{log}");
}

#[tokio::test]
async fn the_switch_for_a_self_assigned_address_is_saved() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let form = "name=tv&mac=00%3A00%3A00%3A00%3A00%3A09&group=lan&ip=192.0.2.9&self_assigned=true";
    assert_eq!(
        send(&app, post("/devices/tv", form)).await.0,
        StatusCode::SEE_OTHER
    );
    let saved = std::fs::read_to_string(data.path().join("devices.toml")).unwrap();
    assert!(saved.contains("self_assigned = true"), "{saved}");
    let (_, page) = send(&app, get("/devices/tv")).await;
    assert!(page.contains(r#"value="true" selected"#), "{page}");
    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(log.contains("address set on the device"), "{log}");
}

#[tokio::test]
async fn a_bad_scan_interval_stays_on_the_settings_page() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (status, page) = send(&app, post("/settings/background", "interval=soon")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        page.contains("The interval must be a number of minutes"),
        "{page}"
    );
}

#[tokio::test]
async fn an_address_outside_the_subnet_gets_a_warning() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/")).await;
    assert!(!page.contains("note warning"), "{page}");

    let inside = send(&app, post("/groups/lan/network", "subnet=192.0.2.0%2F24")).await;
    assert_eq!(inside.0, StatusCode::SEE_OTHER);
    let (_, page) = send(&app, get("/")).await;
    assert!(!page.contains("note warning"), "{page}");

    let outside = send(&app, post("/groups/lan/network", "subnet=198.51.100.0%2F24")).await;
    assert_eq!(outside.0, StatusCode::SEE_OTHER);
    let (_, page) = send(&app, get("/")).await;
    assert!(
        page.contains("192.0.2.9 is outside LAN (198.51.100.0/24)"),
        "{page}"
    );
    let (_, page) = send(&app, get("/devices/tv")).await;
    assert!(page.contains("is outside LAN"), "{page}");
    let (_, page) = send(&app, get("/devices/lamp")).await;
    assert!(!page.contains("is outside LAN"), "no fixed address: {page}");

    let (status, page) = send(&app, post("/groups/lan/network", "subnet=nonsense")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("the subnet must look like"), "{page}");
    let (status, page) = send(&app, post("/groups/none/network", "subnet=")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("No such group"), "{page}");

    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(log.contains("subnet none → 192.0.2.0/24"), "{log}");
}

#[tokio::test]
async fn subnets_of_two_groups_cannot_overlap() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let form = "name=iot&vlan=20&subnet=192.0.2.128%2F25";
    send(&app, post("/groups/lan/network", "subnet=192.0.2.0%2F24")).await;
    let (status, page) = send(&app, post("/groups", form)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("overlap"), "{page}");
}
