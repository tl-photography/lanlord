//! Connections of one machine: one card, moved together.

#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{StatusCode, header};
use common::{get, post, send};
use tempfile::TempDir;
use tower::ServiceExt;

fn data() -> TempDir {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("groups.toml"),
        "default_group = \"lan\"\n[[group]]\nname = \"lan\"\nvlan = 1\nlabel = \"LAN\"\n\n[[group]]\nname = \"iot\"\nvlan = 20\nlabel = \"IoT\"\n",
    )
    .unwrap();
    let device = |name: &str, mac: u8, group: &str| {
        format!(
            "[[device]]\nname = \"{name}\"\nmac = \"00:00:00:00:00:{mac:02x}\"\ngroup = \"{group}\"\nmachine = \"ThinkPad\"\n\n"
        )
    };
    std::fs::write(
        data.path().join("devices.toml"),
        format!(
            "{}{}{}[[device]]\nname = \"tv\"\nmac = \"00:00:00:00:00:09\"\ngroup = \"lan\"\n",
            device("ThinkPadDock", 1, "lan"),
            device("ThinkPadWifi", 2, "lan"),
            device("ThinkPadCable", 3, "iot")
        ),
    )
    .unwrap();
    data
}

#[tokio::test]
async fn connections_of_a_machine_share_one_card_and_move_together() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (_, page) = send(&app, get("/")).await;
    assert_eq!(
        page.matches(r#"data-device="machine:ThinkPad""#).count(),
        2,
        "one card in LAN, one in IoT"
    );
    assert!(
        page.contains(r#"<a class="card machine" href="/machines/ThinkPad">"#),
        "{page}"
    );
    assert!(
        page.contains(r#"title="Interface of ThinkPad">ThinkPadDock</span>"#),
        "{page}"
    );
    assert!(!page.contains(r#"href="/devices/ThinkPadDock""#), "{page}");
    assert!(page.contains("Also in IoT"));
    assert!(page.contains("Also in LAN"));
    assert!(page.contains(r#"action="/machines/ThinkPad/move""#));
    assert!(
        page.contains("3 devices"),
        "the LAN header counts connections: {page}"
    );

    let (status, _) = send(&app, post("/machines/ThinkPad/move", "group=iot")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let groups = ["lan".to_owned(), "iot".to_owned()];
    let list = lanlord::devices::DeviceList::load(&data.path().join("devices.toml"), &groups).unwrap();
    let in_iot = list
        .interfaces
        .iter()
        .filter(|device| device.group == "iot")
        .count();
    assert_eq!(in_iot, 3, "{list:?}");
    let (_, page) = send(&app, get("/")).await;
    assert_eq!(page.matches(r#"data-device="machine:ThinkPad""#).count(), 1);
    assert!(!page.contains("Also in"));
    let (_, history) = send(&app, get("/history")).await;
    assert!(history.contains("Device ThinkPadDock changed: group lan → iot"));
    assert!(!history.contains("ThinkPadCable changed"), "already in IoT");

    assert_eq!(
        send(&app, post("/machines/Nothing/move", "group=iot")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn saving_an_interface_keeps_its_device() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/devices/ThinkPadWifi")).await;
    assert!(page.contains(r#"name="machine" value="ThinkPad""#), "{page}");
    assert!(!page.contains("Belongs to"), "{page}");

    let bad = "name=tv&mac=00:00:00:00:00:09&group=lan&ip=&note=&machine=Living%20Room";
    let (status, page) = send(&app, post("/devices/tv", bad)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("invalid device name"));
}

#[tokio::test]
async fn the_machine_page_shows_and_changes_its_interfaces() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (status, page) = send(&app, get("/machines/ThinkPad")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(r#"<a href="/devices/ThinkPadCable">ThinkPadCable</a>"#),
        "{page}"
    );
    assert!(page.contains("Add a new interface"));
    assert_eq!(
        send(&app, get("/machines/Nothing")).await.0,
        StatusCode::NOT_FOUND
    );

    let add = "name=ThinkPadUsb&mac=00:00:00:00:00:05&group=iot&ip=&machine=ThinkPad&then=machine";
    let response = app.clone().oneshot(post("/devices", add)).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/machines/ThinkPad");
    let (_, page) = send(&app, get("/machines/ThinkPad")).await;
    assert!(page.contains("ThinkPadUsb"));

    let (status, _) = send(&app, post("/machines/ThinkPad", "new_name=Laptop")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = send(&app, get("/machines/Laptop")).await;
    assert!(
        page.contains("ThinkPadDock"),
        "the interfaces keep their names: {page}"
    );
    let (status, page) = send(&app, post("/machines/Laptop", "new_name=a%20b")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("Invalid name"));

    let response = app
        .clone()
        .oneshot(post("/devices/ThinkPadUsb/delete", ""))
        .await
        .unwrap();
    assert_eq!(response.headers()[header::LOCATION], "/machines/Laptop");
    let (_, page) = send(&app, get("/machines/Laptop")).await;
    assert!(!page.contains("ThinkPadUsb"));
    assert_eq!(
        send(&app, post("/devices/ThinkPadUsb/delete", "")).await.0,
        StatusCode::NOT_FOUND
    );

    let (_, history) = send(&app, get("/history")).await;
    assert!(history.contains("Device ThinkPad renamed to Laptop"), "{history}");
    assert!(history.contains("Device ThinkPadUsb deleted"));
}

#[tokio::test]
async fn a_device_becomes_a_machine_and_a_deleted_one_goes_home() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (_, page) = send(&app, get("/devices/tv")).await;
    assert!(page.contains("Add more interfaces"), "{page}");
    let response = app
        .clone()
        .oneshot(post("/devices/tv/interfaces", ""))
        .await
        .unwrap();
    assert_eq!(response.headers()[header::LOCATION], "/machines/tv");
    let (_, page) = send(&app, get("/devices/tv")).await;
    assert!(page.contains("All interfaces of tv"), "{page}");

    let response = app.clone().oneshot(post("/devices/tv/delete", "")).await.unwrap();
    assert_eq!(
        response.headers()[header::LOCATION],
        "/",
        "the last interface of the machine"
    );
    assert_eq!(send(&app, get("/machines/tv")).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        send(&app, post("/devices/nothing/interfaces", "")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn an_existing_device_is_picked_as_an_interface() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (_, page) = send(&app, get("/machines/ThinkPad")).await;
    assert!(page.contains("<option value=\"tv\">tv</option>"), "{page}");
    assert!(!page.contains("<option value=\"ThinkPadWifi\">"), "{page}");

    let (status, _) = send(&app, post("/machines/ThinkPad/interfaces", "device=tv")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = send(&app, get("/machines/ThinkPad")).await;
    assert!(page.contains("href=\"/devices/tv\""), "{page}");
    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(log.contains("Interface tv added to ThinkPad"), "{log}");

    let (status, _) = send(&app, post("/machines/ThinkPad/interfaces", "device=gone")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&app, post("/machines/nothing/interfaces", "device=tv")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_device_of_another_machine_says_where_it_is_and_moves() {
    let data = data();
    let path = data.path().join("devices.toml");
    let list = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{list}\n[[device]]\nname = \"dock\"\nmac = \"00:00:00:00:00:0a\"\ngroup = \"lan\"\nmachine = \"desk\"\n")).unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (_, page) = send(&app, get("/machines/ThinkPad")).await;
    assert!(page.contains("dock (in desk)"), "{page}");

    let (status, _) = send(&app, post("/machines/ThinkPad/interfaces", "device=dock")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _) = send(&app, get("/machines/desk")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_interface_is_removed_from_its_machine_and_stays_a_device() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let remove = |device: &str| post(&format!("/machines/ThinkPad/interfaces/{device}/remove"), "");

    let (_, page) = send(&app, get("/machines/ThinkPad")).await;
    assert!(page.contains("Remove ThinkPadWifi from ThinkPad"), "{page}");
    assert!(!page.contains("/delete"), "{page}");

    let response = app.clone().oneshot(remove("ThinkPadWifi")).await.unwrap();
    assert_eq!(response.headers()[header::LOCATION], "/machines/ThinkPad");
    assert_eq!(send(&app, get("/devices/ThinkPadWifi")).await.0, StatusCode::OK);
    let (_, page) = send(&app, get("/machines/ThinkPad")).await;
    assert!(!page.contains("/devices/ThinkPadWifi"), "{page}");
    assert_eq!(send(&app, remove("ThinkPadWifi")).await.0, StatusCode::NOT_FOUND);

    let response = app.clone().oneshot(remove("ThinkPadDock")).await.unwrap();
    assert_eq!(response.headers()[header::LOCATION], "/machines/ThinkPad");
    let response = app.clone().oneshot(remove("ThinkPadCable")).await.unwrap();
    assert_eq!(response.headers()[header::LOCATION], "/devices/ThinkPadCable");
    assert_eq!(
        send(&app, get("/machines/ThinkPad")).await.0,
        StatusCode::NOT_FOUND
    );

    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(
        log.contains("Interface ThinkPadWifi removed from ThinkPad"),
        "{log}"
    );
}

#[tokio::test]
async fn deleting_asks_first() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/devices/tv")).await;
    assert!(page.contains(r#"data-confirm="Delete tv?""#), "{page}");
    let (_, script) = send(&app, get("/app.js")).await;
    assert!(script.contains("window.confirm"), "{script}");
}
