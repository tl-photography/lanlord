//! lanlord: device list for a small `OpenWrt` network.

pub mod compare;
pub mod config;
pub mod devices;
mod edit;
mod groups;
pub mod origin;
mod plugin_ui;
pub mod plugins;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

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

/// Drag and drop and the long-press menu; everything also works without it.
const SCRIPT: &str = include_str!("../static/app.js");

/// The logo, also used as icon.
const LOGO: &str = include_str!("../assets/lanlord.svg");

/// House mark used for the browser icon.
const FAVICON: &str = include_str!("../assets/favicon.svg");

/// Settings and data files, shared by all requests.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    plugins: RwLock<Vec<Arc<dyn plugins::Plugin>>>,
    plugins_path: PathBuf,
    groups: RwLock<Config>,
    groups_path: PathBuf,
    devices_path: PathBuf,
    /// Held while the device list is read, changed and written.
    write_lock: Mutex<()>,
}

impl AppState {
    /// Reads `groups.toml`, `devices.toml` and the plugins in `lanlord.toml` from the data directory. All may be
    /// missing: lanlord then starts without groups, devices and plugins.
    ///
    /// # Errors
    ///
    /// If a file cannot be read or is invalid.
    pub fn load(data_dir: &Path) -> Result<Self, Error> {
        let groups_path = data_dir.join("groups.toml");
        let groups = Config::load(&groups_path)?;
        let devices_path = data_dir.join("devices.toml");
        DeviceList::load(&devices_path, &groups.group_names())?;
        let plugins_path = data_dir.join("lanlord.toml");
        let plugins = plugins::load(&plugins_path)?;
        Ok(Self {
            inner: Arc::new(Inner {
                plugins: RwLock::new(plugins),
                plugins_path,
                groups: RwLock::new(groups),
                groups_path,
                devices_path,
                write_lock: Mutex::new(()),
            }),
        })
    }

    /// The current groups.
    pub(crate) fn groups(&self) -> Config {
        self.inner
            .groups
            .read()
            .map_or_else(|poisoned| poisoned.into_inner().clone(), |groups| groups.clone())
    }

    fn devices(&self) -> Result<DeviceList, Error> {
        DeviceList::load(&self.inner.devices_path, &self.groups().group_names())
    }
}

/// Routes of the web interface.
pub fn app(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/", get(index))
        .route("/devices", axum::routing::post(edit::create))
        .route("/devices/new", get(edit::new_form))
        .route("/devices/{name}", get(edit::edit_form).post(edit::update))
        .route("/devices/{name}/move", axum::routing::post(edit::move_device))
        .route("/groups", get(groups::list).post(groups::create))
        .route("/groups/default", axum::routing::post(groups::set_default))
        .route("/groups/{name}/delete", axum::routing::post(groups::delete))
        .route("/plugins", get(plugin_ui::list).post(plugin_ui::create))
        .route("/plugins/{name}/enabled", axum::routing::post(plugin_ui::toggle))
        .route("/plugins/{name}", axum::routing::post(plugin_ui::update))
        .route("/style.css", get(style))
        .route("/logo.svg", get(logo))
        .route("/favicon.svg", get(favicon))
        .route("/app.js", get(script))
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
    initial: char,
    name: String,
    group: String,
    mac: String,
    ip: String,
    note: String,
    move_groups: Vec<MoveGroup>,
}

#[derive(Clone)]
struct MoveGroup {
    name: String,
    label: String,
}

struct GroupView {
    name: String,
    label: String,
    vlan: u16,
    devices: Vec<DeviceRow>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    nav: &'static str,
    groups: Vec<GroupView>,
    has_targets: bool,
}

impl IndexPage {
    fn has_groups(&self) -> bool {
        !self.groups.is_empty()
    }
}

pub(crate) fn server_error(error: &impl std::fmt::Display) -> Response {
    tracing::error!("{error}");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal error, see the log").into_response()
}

async fn index(State(state): State<AppState>) -> Response {
    let list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    let config = state.groups();
    let move_groups: Vec<MoveGroup> = config
        .groups
        .iter()
        .map(|group| MoveGroup {
            name: group.name.clone(),
            label: group.title().to_owned(),
        })
        .collect();
    let groups = state
        .groups()
        .groups
        .iter()
        .map(|group| {
            let mut devices: Vec<DeviceRow> = list
                .devices
                .iter()
                .filter(|device| device.group == group.name)
                .map(|device| DeviceRow {
                    initial: device.name.chars().next().unwrap_or('?').to_ascii_uppercase(),
                    name: device.name.clone(),
                    group: device.group.clone(),
                    mac: device.mac.clone(),
                    ip: device.ip.map(|ip| ip.to_string()).unwrap_or_default(),
                    note: device.note.clone(),
                    move_groups: move_groups.clone(),
                })
                .collect();
            devices.sort_by_key(|device| device.name.to_ascii_lowercase());
            GroupView {
                name: group.name.clone(),
                label: group.title().to_owned(),
                vlan: group.vlan,
                devices,
            }
        })
        .collect();
    let has_targets = state.inner.plugins.read().map_or_else(
        |poisoned| poisoned.into_inner().iter().any(|plugin| plugin.is_target()),
        |plugins| plugins.iter().any(|plugin| plugin.is_target()),
    );
    let page = IndexPage {
        nav: "devices",
        groups,
        has_targets,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => server_error(&error),
    }
}

async fn style() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLE)
}

async fn script() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], SCRIPT)
}

async fn logo() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/svg+xml")], LOGO)
}

async fn favicon() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/svg+xml")], FAVICON)
}

async fn healthz() -> &'static str {
    "ok"
}
