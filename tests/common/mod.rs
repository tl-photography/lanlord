//! Helpers shared by the integration tests: requests and the app over a data directory.

// Each test file uses only some of them.
#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

/// The app over the data directory, without a login.
pub fn app(data: &TempDir) -> Router {
    lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap())
}

/// Sends a request and returns the status and the body as text.
pub async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// A GET request.
pub fn get(path: &str) -> Request<Body> {
    Request::get(path).body(Body::empty()).unwrap()
}

/// A form POST from the app's own pages.
pub fn post(path: &str, form: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(form.to_owned()))
        .unwrap()
}
