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
async fn a_linked_device_moves_to_the_network_column_and_keeps_its_group() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/")).await;
    assert!(!page.contains("group network"), "{page}");

    std::fs::write(
        data.path().join("lanlord.toml"),
        "[[plugin]]\nname = \"router\"\ntype = \"openwrt\"\nenabled = false\ndevice = \"tv\"\nuser = \"lanlord\"\npassword_file = \"router.password\"\ncertificate_sha256 = \"00\"\n",
    )
    .unwrap();
    let (_, page) = send(&app, get("/")).await;
    let (network, groups) = page.split_once(r#"data-group="lan""#).unwrap();
    assert!(network.contains("group network"), "{page}");
    assert!(network.contains("<strong>tv</strong>"), "{page}");
    assert!(network.contains(r#"<span class="badge vlan""#), "{page}");
    assert!(network.contains(r#"aria-label="Move tv""#), "{page}");
    assert!(!groups.contains("<strong>tv</strong>"), "{page}");
    assert!(groups.contains("2 devices, 1 in Network<"), "{page}");
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
    assert!(page.contains(r#"value="true" checked"#), "{page}");
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
