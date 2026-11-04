//! Requests against the router without a network socket.

#![allow(clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn get(path: &str) -> (StatusCode, String) {
    let response = lanlord::app()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn healthz_answers_ok() {
    assert_eq!(get("/healthz").await, (StatusCode::OK, "ok".to_owned()));
}

#[tokio::test]
async fn index_shows_the_name() {
    let (status, body) = get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<h1>lanlord</h1>"));
}

#[tokio::test]
async fn unknown_path_is_not_found() {
    assert_eq!(get("/nope").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_response_has_the_security_headers() {
    for path in ["/", "/healthz", "/nope"] {
        let response = lanlord::app()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let headers = response.headers();
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'self'"), "{path}: {csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{path}: {csp}");
        assert_eq!(headers["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(headers["x-frame-options"], "DENY", "{path}");
        assert_eq!(headers["referrer-policy"], "no-referrer", "{path}");
        assert_eq!(headers["cache-control"], "no-store", "{path}");
    }
}
