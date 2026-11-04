//! lanlord: device list for a small OpenWrt network.

use axum::{Router, response::Html, routing::get};

/// Routes of the web interface.
pub fn app() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
}

async fn index() -> Html<&'static str> {
    Html("<!doctype html><title>lanlord</title><h1>lanlord</h1>")
}

async fn healthz() -> &'static str {
    "ok"
}
