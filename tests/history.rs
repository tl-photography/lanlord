//! The change log through the web interface.

#![allow(clippy::unwrap_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn post(path: &str, form: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(form.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn changes_are_logged_and_shown_newest_first() {
    let data = tempfile::tempdir().unwrap();
    let app = lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap());

    let (_, page) = send(&app, Request::get("/history").body(Body::empty()).unwrap()).await;
    assert!(page.contains("No changes yet."));

    for (path, form) in [
        ("/groups", "name=lan&vlan=1"),
        ("/groups", "name=iot&vlan=20"),
        ("/devices", "name=tv&mac=00:00:00:00:00:01&group=lan&ip=&note="),
        ("/devices/tv/move", "group=iot"),
        ("/plugins", "type=leases-file&name=leases&path=dhcp.leases"),
        ("/plugins/leases/enabled", ""),
    ] {
        assert_eq!(
            send(&app, post(path, form)).await.0,
            StatusCode::SEE_OTHER,
            "{path}"
        );
    }
    let (status, _) = send(&app, post("/devices", "name=bad&mac=nope&group=lan")).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a refused change is not logged"
    );

    let (status, page) = send(&app, Request::get("/history").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let order = [
        "Plugin leases changed: enabled true → false",
        "Plugin leases added: type leases-file",
        "Device tv changed: group lan → iot",
        "Device tv added: group lan, MAC 00:00:00:00:00:01, IP none",
        "Group iot added: VLAN 20",
        "Default group none → lan",
        "Group lan added: VLAN 1",
    ];
    let positions: Vec<usize> = order.iter().map(|text| page.find(text).unwrap()).collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "newest first: {page}"
    );
    assert!(!page.contains("bad"));
}
