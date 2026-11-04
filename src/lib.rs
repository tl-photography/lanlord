//! lanlord: device list for a small OpenWrt network.

pub mod config;
pub mod devices;

use axum::http::{HeaderName, HeaderValue, header};
use axum::{Router, response::Html, routing::get};
use tower_http::set_header::SetResponseHeaderLayer;

/// Headers on every response: no external content, no frames, no caching of device data.
const SECURITY_HEADERS: [(HeaderName, &str); 9] = [
    (
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ),
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::X_FRAME_OPTIONS, "DENY"),
    (header::REFERRER_POLICY, "no-referrer"),
    (header::CACHE_CONTROL, "no-store"),
    (
        HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=()",
    ),
    (
        HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    ),
    (
        HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    ),
    (
        HeaderName::from_static("cross-origin-embedder-policy"),
        "require-corp",
    ),
];

/// Routes of the web interface.
pub fn app() -> Router {
    let mut router = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz));
    for (name, value) in SECURITY_HEADERS {
        router = router.layer(SetResponseHeaderLayer::overriding(
            name,
            HeaderValue::from_static(value),
        ));
    }
    router
}

async fn index() -> Html<&'static str> {
    Html("<!doctype html><title>lanlord</title><h1>lanlord</h1>")
}

async fn healthz() -> &'static str {
    "ok"
}
