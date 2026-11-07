//! Connections of one machine: one card, moved together.

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
        page.contains(r#"<a href="/devices/ThinkPadDock">ThinkPadDock</a>"#),
        "{page}"
    );
    assert!(page.contains("Also in IoT"));
    assert!(page.contains("Also in LAN"));
    assert!(page.contains(r#"action="/machines/ThinkPad/move""#));
    assert!(
        page.contains("3 devices"),
        "the LAN header counts connections: {page}"
    );

    let (status, _) = send(&app, post("/machines/ThinkPad/move", "group=iot")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let list = std::fs::read_to_string(data.path().join("devices.toml")).unwrap();
    assert_eq!(list.matches("group = \"iot\"").count(), 3, "{list}");
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
async fn the_form_offers_machines_and_checks_the_name() {
    let data = data();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());
    let (_, page) = send(&app, get("/devices/tv")).await;
    assert!(page.contains(r#"<option value="ThinkPad">"#), "{page}");

    let ok = "name=tv&mac=00:00:00:00:00:09&group=lan&ip=&note=&machine=LivingRoom";
    assert_eq!(send(&app, post("/devices/tv", ok)).await.0, StatusCode::SEE_OTHER);
    let (_, history) = send(&app, get("/history")).await;
    assert!(
        history.contains("Device tv changed: machine none → LivingRoom"),
        "{history}"
    );

    let bad = "name=tv&mac=00:00:00:00:00:09&group=lan&ip=&note=&machine=Living%20Room";
    let (status, page) = send(&app, post("/devices/tv", bad)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("invalid machine name"));
}
