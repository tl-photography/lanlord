//! The login in front of every page.

#![allow(clippy::unwrap_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

const PASSWORD: &str = "a long enough password";

fn app(data: &TempDir) -> Router {
    lanlord::app(lanlord::AppState::load(data.path()).unwrap())
}

fn with_password() -> TempDir {
    let data = tempfile::tempdir().unwrap();
    lanlord::auth::save_password(&data.path().join("password.hash"), PASSWORD).unwrap();
    data
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::get(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::empty()).unwrap()
}

fn post(path: &str, form: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::from(form.to_owned())).unwrap()
}

/// Logs in and returns the cookie for the next requests.
async fn log_in(app: &Router) -> String {
    let (status, headers, _) = send(app, post("/login", &format!("password={PASSWORD}"), None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cookie = headers[header::SET_COOKIE].to_str().unwrap();
    for attribute in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(attribute), "{cookie}");
    }
    cookie.split(';').next().unwrap().to_owned()
}

#[tokio::test]
async fn pages_need_a_login() {
    let data = with_password();
    let app = app(&data);
    for path in ["/", "/groups", "/plugins", "/devices/new", "/app.js"] {
        let (status, headers, _) = send(&app, get(path, None)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(headers[header::LOCATION], "/login", "{path}");
        assert!(
            headers.contains_key("content-security-policy"),
            "{path}: headers on redirects too"
        );
    }
    let (status, ..) = send(&app, post("/groups", "name=lan&vlan=1", None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        !data.path().join("groups.toml").exists(),
        "nothing changes without a login"
    );
}

#[tokio::test]
async fn the_login_page_and_health_check_are_public() {
    let data = with_password();
    let app = app(&data);
    for path in ["/login", "/healthz", "/style.css", "/favicon.svg", "/logo.svg"] {
        assert_eq!(send(&app, get(path, None)).await.0, StatusCode::OK, "{path}");
    }
    let (_, _, page) = send(&app, get("/login", None)).await;
    assert!(page.contains(r#"type="password""#));
}

#[tokio::test]
async fn a_session_opens_the_pages_until_logout() {
    let data = with_password();
    let app = app(&data);
    let cookie = log_in(&app).await;
    assert_eq!(send(&app, get("/", Some(&cookie))).await.0, StatusCode::OK);
    assert_eq!(send(&app, get("/groups", Some(&cookie))).await.0, StatusCode::OK);

    let (status, headers, _) = send(&app, post("/logout", "", Some(&cookie))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(send(&app, get("/", Some(&cookie))).await.0, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn wrong_passwords_and_guessed_sessions_are_rejected() {
    let data = with_password();
    let app = app(&data);
    let (status, headers, page) = send(&app, post("/login", "password=wrong", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert!(page.contains("Wrong password"));
    let guessed = "lanlord_session=0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(send(&app, get("/", Some(guessed))).await.0, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn without_a_password_nothing_opens() {
    let data = tempfile::tempdir().unwrap();
    let app = app(&data);
    let (_, _, page) = send(&app, get("/login", None)).await;
    assert!(page.contains("No password is set yet"));
    assert!(page.contains("set-password"));
    let (status, ..) = send(&app, post("/login", "password=anything", None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, get("/", None)).await.0, StatusCode::SEE_OTHER);
}
