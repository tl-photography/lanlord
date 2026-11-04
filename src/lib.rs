//! lanlord: device list for a small OpenWrt network.

pub mod config;
pub mod devices;
pub mod origin;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::{Router, routing::get};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::config::Config;
use crate::devices::{DeviceList, Error};

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

/// Styles as a file, the Content Security Policy does not allow inline styles.
const STYLE: &str = include_str!("../static/style.css");

/// Settings and data files, shared by all requests.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: Config,
    devices_path: PathBuf,
}

impl AppState {
    /// Reads `lanlord.toml` and checks `devices.toml` in the data directory.
    ///
    /// # Errors
    ///
    /// If the settings are missing or invalid, or the device list is invalid.
    pub fn load(data_dir: &Path) -> Result<Self, Error> {
        let config = Config::load(&data_dir.join("lanlord.toml"))?;
        let devices_path = data_dir.join("devices.toml");
        DeviceList::load(&devices_path, &config.group_names())?;
        Ok(Self {
            inner: Arc::new(Inner { config, devices_path }),
        })
    }

    fn devices(&self) -> Result<DeviceList, Error> {
        DeviceList::load(&self.inner.devices_path, &self.inner.config.group_names())
    }
}

/// Routes of the web interface.
pub fn app(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/", get(index))
        .route("/style.css", get(style))
        .route("/healthz", get(healthz))
        .layer(axum::middleware::from_fn(origin::same_origin_only))
        .with_state(state);
    for (name, value) in SECURITY_HEADERS {
        router = router.layer(SetResponseHeaderLayer::overriding(
            name,
            HeaderValue::from_static(value),
        ));
    }
    router
}

struct DeviceRow {
    name: String,
    mac: String,
    ip: String,
    note: String,
}

struct GroupView {
    label: String,
    vlan: u16,
    devices: Vec<DeviceRow>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    groups: Vec<GroupView>,
}

fn server_error(error: &impl std::fmt::Display) -> Response {
    tracing::error!("{error}");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal error, see the log").into_response()
}

async fn index(State(state): State<AppState>) -> Response {
    let list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    let groups = state
        .inner
        .config
        .groups
        .iter()
        .map(|group| {
            let mut devices: Vec<DeviceRow> = list
                .devices
                .iter()
                .filter(|device| device.group == group.name)
                .map(|device| DeviceRow {
                    name: device.name.clone(),
                    mac: device.mac.clone(),
                    ip: device.ip.map(|ip| ip.to_string()).unwrap_or_default(),
                    note: device.note.clone(),
                })
                .collect();
            devices.sort_by_key(|device| device.name.to_ascii_lowercase());
            GroupView {
                label: if group.label.is_empty() {
                    group.name.clone()
                } else {
                    group.label.clone()
                },
                vlan: group.vlan,
                devices,
            }
        })
        .collect();
    match (IndexPage { groups }).render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn style() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLE)
}

async fn healthz() -> &'static str {
    "ok"
}
