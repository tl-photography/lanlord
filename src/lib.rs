//! lanlord: device list for a small `OpenWrt` network.

mod apply;
pub mod auth;
pub mod compare;
pub mod config;
pub mod devices;
mod edit;
mod groups;
mod guests;
pub mod history;
mod history_ui;
pub mod leases;
mod machines;
pub mod notify;
pub mod origin;
pub mod plan;
mod plugin_ui;
pub mod plugins;
pub mod preview;
mod settings_ui;
pub mod watch;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::{Router, routing::get};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::config::Config;
use crate::devices::{DeviceList, Error};

/// Headers on every response: no external content, no frames, no caching of device data.
const SECURITY_HEADERS: [(HeaderName, &str); 8] = [
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
        HeaderName::from_static("cross-origin-embedder-policy"),
        "require-corp",
    ),
];

/// How long a counted number of open changes is shown before it is counted again.
const PENDING_LIFETIME: Duration = Duration::from_secs(30);

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
    /// Off only when another layer, like a proxy with its own login, protects lanlord.
    login_required: bool,
    password_path: PathBuf,
    sessions: auth::Sessions,
    /// The change log.
    history_path: PathBuf,
    /// Number of changes the targets would make, and when it was counted.
    pending: Mutex<Option<(Instant, usize)>>,
    /// What the background scan remembers.
    watch: Mutex<watch::WatchState>,
}

impl AppState {
    /// Reads `groups.toml`, `devices.toml` and the plugins in `lanlord.toml` from the data directory. All may be
    /// missing: lanlord then starts without groups, devices and plugins.
    ///
    /// # Errors
    ///
    /// If a file cannot be read or is invalid.
    pub fn load(data_dir: &Path) -> Result<Self, Error> {
        Self::open(data_dir, true)
    }

    /// Like [`AppState::load`], but without the login: for tests, and for running behind another layer that
    /// already authenticates every request.
    ///
    /// # Errors
    ///
    /// If a file cannot be read or is invalid.
    pub fn load_without_login(data_dir: &Path) -> Result<Self, Error> {
        Self::open(data_dir, false)
    }

    fn open(data_dir: &Path, login_required: bool) -> Result<Self, Error> {
        let groups_path = data_dir.join("groups.toml");
        let groups = Config::load(&groups_path)?;
        let devices_path = data_dir.join("devices.toml");
        DeviceList::load(&devices_path, &groups.group_names())?;
        let plugins_path = data_dir.join("lanlord.toml");
        let loaded = plugins::load(&plugins_path);
        for problem in loaded.all_problems() {
            tracing::warn!("plugin left out: {problem}");
        }
        let plugins = loaded.plugins;
        Ok(Self {
            inner: Arc::new(Inner {
                plugins: RwLock::new(plugins),
                plugins_path,
                groups: RwLock::new(groups),
                groups_path,
                devices_path,
                write_lock: Mutex::new(()),
                login_required,
                password_path: data_dir.join("password.hash"),
                sessions: auth::Sessions::default(),
                history_path: data_dir.join("history.log"),
                pending: Mutex::new(None),
                watch: Mutex::default(),
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

    /// Whether a plugin can apply changes.
    fn has_targets(&self) -> bool {
        self.inner.plugins.read().map_or_else(
            |poisoned| poisoned.into_inner().iter().any(|plugin| plugin.is_target()),
            |plugins| plugins.iter().any(|plugin| plugin.is_target()),
        )
    }

    /// The counted changes, if counted within [`PENDING_LIFETIME`].
    fn pending(&self) -> Option<usize> {
        let pending = self.inner.pending.lock().ok()?;
        pending
            .filter(|(counted, _)| counted.elapsed() < PENDING_LIFETIME)
            .map(|(_, changes)| changes)
    }

    fn remember_pending(&self, changes: usize) {
        if let Ok(mut pending) = self.inner.pending.lock() {
            *pending = Some((Instant::now(), changes));
        }
    }

    /// Builds the plugins again from `lanlord.toml`, for example after a linked device changed.
    pub(crate) fn reload_plugins(&self) {
        let loaded = plugins::load(&self.inner.plugins_path).plugins;
        if let Ok(mut plugins) = self.inner.plugins.write() {
            *plugins = loaded;
        }
    }

    /// Drops the count after a change, so the badge is counted again.
    pub(crate) fn forget_pending(&self) {
        if let Ok(mut pending) = self.inner.pending.lock() {
            *pending = None;
        }
    }

    /// The plan for the targets: devices and groups.
    pub(crate) fn plan(&self) -> Result<plan::Plan, Error> {
        let devices = self.devices()?;
        let config = self.groups();
        Ok(plan::Plan {
            services: self.services(&devices),
            devices,
            groups: config.groups,
            dns_service: config.dns_service,
        })
    }

    /// The services of the enabled plugins, at the fixed address of the device each is linked to.
    pub(crate) fn services(&self, devices: &DeviceList) -> Vec<plan::Service> {
        let settings = plugins::read_settings(&self.inner.plugins_path).unwrap_or_default();
        let Ok(active) = self.inner.plugins.read() else {
            return Vec::new();
        };
        let mut services = Vec::new();
        for (device, names) in plugins::linked_plugins(&settings) {
            let address = devices
                .interfaces
                .iter()
                .filter(|interface| interface.name == device || interface.device == device)
                .find_map(|interface| interface.ip);
            let Some(address) = address else { continue };
            for plugin in active
                .iter()
                .filter(|plugin| names.iter().any(|name| name == plugin.name()))
            {
                for kind in plugin.offers() {
                    services.push(plan::Service {
                        kind,
                        address,
                        source: plugin.name().to_owned(),
                    });
                }
            }
        }
        services.sort_by(|left, right| left.source.cmp(&right.source));
        services
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
        .route("/devices/{name}/delete", axum::routing::post(edit::delete))
        .route(
            "/devices/{name}/interfaces",
            axum::routing::post(edit::make_machine),
        )
        .route("/machines/{name}", get(machines::show).post(machines::rename))
        .route("/machines/{name}/move", axum::routing::post(edit::move_machine))
        .route(
            "/machines/{name}/interfaces",
            axum::routing::post(machines::add_interface),
        )
        .route(
            "/machines/{name}/interfaces/{device}/remove",
            axum::routing::post(machines::remove_interface),
        )
        .route("/groups", get(groups::list).post(groups::create))
        .route("/groups/default", axum::routing::post(groups::set_default))
        .route("/settings/dns", axum::routing::post(settings_ui::dns))
        .route("/groups/{name}/delete", axum::routing::post(groups::delete))
        .route("/groups/{name}/network", axum::routing::post(groups::set_network))
        .route("/settings", get(settings_ui::show).post(settings_ui::save))
        .route(
            "/settings/background",
            axum::routing::post(settings_ui::background),
        )
        .route("/plugins", get(plugin_ui::list).post(plugin_ui::create))
        .route("/plugins/scan", axum::routing::post(plugin_ui::scan))
        .route("/plugins/{name}/enabled", axum::routing::post(plugin_ui::toggle))
        .route("/plugins/{name}/delete", axum::routing::post(plugin_ui::delete))
        .route(
            "/plugins/{name}/test",
            axum::routing::post(plugin_ui::test_notification),
        )
        .route("/plugins/{name}", axum::routing::post(plugin_ui::update))
        .route("/history", get(history_ui::list))
        .route("/apply", get(apply::list))
        .route("/apply/count", get(apply::count))
        .route("/apply-all", axum::routing::post(apply::apply_all))
        .route("/apply/{name}", axum::routing::post(apply::apply))
        .route("/style.css", get(style))
        .route("/logo.svg", get(logo))
        .route("/favicon.svg", get(favicon))
        .route("/app.js", get(script))
        .route("/healthz", get(healthz))
        .route("/login", get(auth::form).post(auth::login))
        .route("/logout", axum::routing::post(auth::logout))
        .layer(axum::middleware::from_fn(origin::same_origin_only))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_login,
        ))
        .with_state(state);
    for (name, value) in SECURITY_HEADERS {
        router = router.layer(SetResponseHeaderLayer::overriding(
            name,
            HeaderValue::from_static(value),
        ));
    }
    // Only the logo and icon may be shown by other sites, for example a dashboard; everything else stays own.
    router.layer(SetResponseHeaderLayer::if_not_present(
        CROSS_ORIGIN_RESOURCE_POLICY,
        HeaderValue::from_static("same-origin"),
    ))
}

struct DeviceRow {
    name: String,
    /// Plugins that talk to this device.
    plugins: Vec<String>,
    mac: String,
    ip: String,
    note: String,
    /// The fixed address is outside the subnet of the group.
    warning: String,
    /// Found by a scan and not looked at yet.
    unreviewed: bool,
}

#[derive(Clone)]
struct MoveGroup {
    name: String,
    label: String,
}

/// One card on the devices page: a device, or a machine with its connections in this group.
struct CardView {
    /// Identifies the card for drag and drop.
    key: String,
    title: String,
    machine: bool,
    /// Where the move forms post to.
    move_action: String,
    group: String,
    rows: Vec<DeviceRow>,
    /// Plugins linked to the machine itself.
    plugins: Vec<String>,
    /// Other groups with connections of the same machine.
    also_in: String,
    move_groups: Vec<MoveGroup>,
}

struct GroupView {
    name: String,
    label: String,
    vlan: u16,
    count: usize,
    cards: Vec<CardView>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    nav: &'static str,
    groups: Vec<GroupView>,
    has_targets: bool,
    overview: plugins::OverviewSettings,
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

fn device_row(
    device: &devices::Interface,
    group: &config::Group,
    links: &HashMap<String, Vec<String>>,
) -> DeviceRow {
    DeviceRow {
        plugins: links.get(&device.name).cloned().unwrap_or_default(),
        name: device.name.clone(),
        mac: device.mac.clone(),
        ip: device.ip.map(|ip| ip.to_string()).unwrap_or_default(),
        note: device.note.clone(),
        unreviewed: device.unreviewed,
        warning: device
            .ip
            .and_then(|ip| group.address_warning(ip))
            .unwrap_or_default(),
    }
}

/// The name with a possible line break at each change to upper case, as HTML. Only letters, digits and `-` are kept,
/// which is all a valid name has, so the result is safe to show unescaped.
#[must_use]
pub fn break_name(name: &str) -> String {
    let mut html = String::new();
    let mut after_lower = false;
    for letter in name
        .chars()
        .filter(|letter| letter.is_ascii_alphanumeric() || *letter == '-')
    {
        if after_lower && letter.is_ascii_uppercase() {
            html.push_str("<wbr>");
        }
        after_lower = letter.is_ascii_lowercase() || letter.is_ascii_digit();
        html.push(letter);
    }
    html
}

/// The cards of one group: one per device, one per machine with its connections in this group.
fn group_cards(
    group: &config::Group,
    list: &DeviceList,
    config: &Config,
    links: &HashMap<String, Vec<String>>,
    move_groups: &[MoveGroup],
) -> Vec<CardView> {
    let members: Vec<&devices::Interface> = list
        .interfaces
        .iter()
        .filter(|device| device.group == group.name)
        .collect();
    let mut cards: Vec<CardView> = Vec::new();
    for device in &members {
        if device.device.is_empty() {
            cards.push(CardView {
                key: device.name.clone(),
                title: device.name.clone(),
                machine: false,
                move_action: format!("/devices/{}/move", device.name),
                group: group.name.clone(),
                rows: vec![device_row(device, group, links)],
                plugins: Vec::new(),
                also_in: String::new(),
                move_groups: move_groups.to_vec(),
            });
            continue;
        }
        if cards
            .iter()
            .any(|card| card.machine && card.title == device.device)
        {
            continue;
        }
        let mut rows: Vec<DeviceRow> = members
            .iter()
            .filter(|other| other.device == device.device)
            .map(|other| device_row(other, group, links))
            .collect();
        rows.sort_by_key(|row| row.name.to_ascii_lowercase());
        let elsewhere: Vec<String> = config
            .groups
            .iter()
            .filter(|other| {
                other.name != group.name
                    && list
                        .interfaces
                        .iter()
                        .any(|entry| entry.device == device.device && entry.group == other.name)
            })
            .map(|other| other.title().to_owned())
            .collect();
        cards.push(CardView {
            key: format!("machine:{}", device.device),
            title: device.device.clone(),
            machine: true,
            move_action: format!("/machines/{}/move", device.device),
            group: group.name.clone(),
            rows,
            plugins: links.get(&device.device).cloned().unwrap_or_default(),
            also_in: elsewhere.join(", "),
            move_groups: move_groups.to_vec(),
        });
    }
    cards.sort_by_key(|card| card.title.to_ascii_lowercase());
    cards
}

async fn index(State(state): State<AppState>) -> Response {
    let list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    let config = state.groups();
    let settings = plugins::read_settings(&state.inner.plugins_path).unwrap_or_default();
    let links = plugins::linked_plugins(&settings);
    let move_groups: Vec<MoveGroup> = config
        .groups
        .iter()
        .map(|group| MoveGroup {
            name: group.name.clone(),
            label: group.title().to_owned(),
        })
        .collect();
    let groups = config
        .groups
        .iter()
        .map(|group| {
            let cards = group_cards(group, &list, &config, &links, &move_groups);
            GroupView {
                name: group.name.clone(),
                label: group.title().to_owned(),
                vlan: group.vlan,
                count: cards.iter().map(|card| card.rows.len()).sum(),
                cards,
            }
        })
        .collect();
    let has_targets = state.has_targets();
    let page = IndexPage {
        nav: "devices",
        groups,
        has_targets,
        overview: settings.overview,
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

const CROSS_ORIGIN_RESOURCE_POLICY: HeaderName = HeaderName::from_static("cross-origin-resource-policy");

/// Public images: other sites may embed them.
fn public_image(svg: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/svg+xml")),
            (
                CROSS_ORIGIN_RESOURCE_POLICY,
                HeaderValue::from_static("cross-origin"),
            ),
        ],
        svg,
    )
}

async fn logo() -> impl IntoResponse {
    public_image(LOGO)
}

async fn favicon() -> impl IntoResponse {
    public_image(FAVICON)
}

async fn healthz() -> &'static str {
    "ok"
}
