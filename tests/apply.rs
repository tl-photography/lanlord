//! The apply page against a small fake `OpenWrt` router.

#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::{Json, Router, routing};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const FINGERPRINT: &str =
    "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

/// Static leases of the fake router; `apply` commits the staged changes at once.
#[derive(Default)]
struct Uci {
    hosts: Map<String, Value>,
    staged: Vec<Value>,
}

async fn fake_router() -> String {
    let uci = Arc::new(Mutex::new(Uci::default()));
    let handler = move |Json(request): Json<Value>| {
        let uci = uci.clone();
        async move {
            let params = request["params"].as_array().cloned().unwrap_or_default();
            let mut uci = uci.lock().unwrap();
            let result = match (params[1].as_str().unwrap(), params[2].as_str().unwrap()) {
                ("session", "login") => json!([0, { "ubus_rpc_session": "s" }]),
                ("network.interface", "dump") => json!([0, { "interface": [
                    { "interface": "lan", "ipv4-address": [{ "address": "192.0.2.1", "mask": 24 }] }
                ] }]),
                ("uci", "get") => {
                    let mut values = uci.hosts.clone();
                    values.insert("lan".to_owned(), json!({ ".type": "dhcp", "interface": "lan" }));
                    json!([0, { "values": values }])
                }
                ("uci", "add") => {
                    uci.staged.push(params[3].clone());
                    json!([0])
                }
                ("uci", "apply") => {
                    for added in std::mem::take(&mut uci.staged) {
                        let mut section = added["values"].as_object().unwrap().clone();
                        section.insert(".type".to_owned(), json!("host"));
                        section.insert(".name".to_owned(), added["name"].clone());
                        uci.hosts
                            .insert(added["name"].as_str().unwrap().to_owned(), Value::Object(section));
                    }
                    json!([0])
                }
                ("uci", "confirm") => json!([0]),
                ("luci-rpc", "getDHCPLeases") => json!([0, { "dhcp_leases": [] }]),
                ("iwinfo", "devices") => json!([0, { "devices": ["phy0-ap0"] }]),
                ("iwinfo", "info") => json!([0, { "ssid": "Home", "frequency": 5180 }]),
                ("iwinfo", "assoclist") => {
                    json!([0, { "results": [{ "mac": "00:00:00:00:00:01", "signal": -43 }] }])
                }
                _ => json!([3]),
            };
            Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(
        async move { axum::serve(listener, Router::new().route("/ubus", routing::post(handler))).await },
    );
    format!("http://127.0.0.1:{}", address.port())
}

async fn data_with_router() -> TempDir {
    let data = tempfile::tempdir().unwrap();
    let path = data.path();
    std::fs::write(
        path.join("groups.toml"),
        "default_group = \"lan\"\n[[group]]\nname = \"lan\"\nvlan = 1\n",
    )
    .unwrap();
    std::fs::write(
        path.join("devices.toml"),
        "[[device]]\nname = \"OMV\"\nmac = \"00:00:00:00:00:01\"\ngroup = \"lan\"\nip = \"192.0.2.2\"\n",
    )
    .unwrap();
    std::fs::write(path.join("router.password"), "secret").unwrap();
    std::fs::set_permissions(
        path.join("router.password"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(
        path.join("lanlord.toml"),
        format!(
            "[[plugin]]\ntype = \"openwrt\"\nname = \"router\"\nurl = \"{}\"\nuser = \"lanlord\"\n\
             password_file = \"router.password\"\ncertificate = \"{FINGERPRINT}\"\n",
            fake_router().await
        ),
    )
    .unwrap();
    data
}

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

fn digest(page: &str) -> String {
    let start = page.find(r#"name="digest" value=""#).unwrap() + 21;
    page[start..start + 32].to_owned()
}

#[tokio::test]
async fn changes_are_shown_and_applied_with_the_button_only() {
    let data = data_with_router().await;
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (status, page) = send(&app, get("/apply")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("OMV: static lease 192.0.2.2"), "{page}");
    assert!(
        page.contains("uci set dhcp.lanlord_omv.ip=&#39;192.0.2.2&#39;"),
        "{page}"
    );
    assert!(page.contains("Apply 1 change"));

    let (status, page) = send(&app, post("/apply/router", "digest=0000")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("changed since the preview"));

    let form = format!("digest={}", digest(&page));
    let (status, page) = send(&app, post("/apply/router", &form)).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("router: 1 change applied"));
    assert!(page.contains("Up to date."));
}

#[tokio::test]
async fn without_targets_nothing_can_be_applied() {
    let data = tempfile::tempdir().unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/apply")).await;
    assert!(page.contains("No plugin applies changes"));
    let (status, page) = send(&app, post("/apply/router", "digest=x")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("No target named router"));
}

#[tokio::test]
async fn the_top_bar_counts_open_changes_and_the_form_leads_to_the_review() {
    let data = data_with_router().await;
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (status, count) = send(&app, get("/apply/count")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count, r#"{"changes":1}"#);

    let (_, page) = send(&app, get("/devices/OMV")).await;
    assert!(page.contains("Save and review changes"));
    let response = app
        .clone()
        .oneshot(post(
            "/devices/OMV",
            "name=OMV&mac=00:00:00:00:00:01&group=lan&ip=192.0.2.2&note=&then=review",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/apply");

    let (_, page) = send(&app, get("/apply")).await;
    let form = format!("digest={}", digest(&page));
    send(&app, post("/apply/router", &form)).await;
    assert_eq!(
        send(&app, get("/apply/count")).await.1,
        r#"{"changes":0}"#,
        "counted again after applying"
    );
}

#[tokio::test]
async fn without_targets_the_form_has_no_review_button() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("groups.toml"),
        "default_group = \"lan\"\n[[group]]\nname = \"lan\"\nvlan = 1\n",
    )
    .unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/devices/new")).await;
    assert!(!page.contains("Save and review changes"));
    assert_eq!(send(&app, get("/apply/count")).await.1, r#"{"changes":0}"#);
}

#[tokio::test]
async fn the_scan_shows_which_device_is_on_which_wifi() {
    let data = data_with_router().await;
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (status, page) = send(&app, post("/plugins/scan", "")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("On Wi-Fi"), "{page}");
    assert!(page.contains("OMV: router: Home (5 GHz), -43 dBm"), "{page}");
}

/// Adds a second router to the plugins of the data directory.
async fn add_router(data: &TempDir) {
    let path = data.path().join("lanlord.toml");
    let settings = format!(
        "{}\n[[plugin]]\ntype = \"openwrt\"\nname = \"second\"\nurl = \"{}\"\nuser = \"lanlord\"\n\
         password_file = \"router.password\"\ncertificate = \"{FINGERPRINT}\"\n",
        std::fs::read_to_string(&path).unwrap(),
        fake_router().await
    );
    std::fs::write(&path, settings).unwrap();
}

fn digest_of(page: &str, name: &str) -> String {
    let marker = format!(r#"name="digest-{name}" value=""#);
    let start = page.find(&marker).unwrap() + marker.len();
    page[start..start + 32].to_owned()
}

#[tokio::test]
async fn apply_all_handles_every_target_and_keeps_going_after_a_failure() {
    let data = data_with_router().await;
    add_router(&data).await;
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (_, page) = send(&app, get("/apply")).await;
    assert!(page.contains("Apply all (2 changes on 2 targets)"), "{page}");

    let form = format!("digest-router=0000&digest-second={}", digest_of(&page, "second"));
    let (status, page) = send(&app, post("/apply-all", &form)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the first target failed"
    );
    assert!(
        page.contains("router: the device or the list changed since the preview"),
        "{page}"
    );
    assert!(
        page.contains("second: 1 change applied"),
        "the second one still ran: {page}"
    );
    assert!(!page.contains("Apply all"), "only one target is left: {page}");

    let (_, history) = send(&app, get("/history")).await;
    assert!(history.contains("Apply to router failed"));
    assert!(history.contains("Applied to second: OMV: static lease 192.0.2.2"));
}
