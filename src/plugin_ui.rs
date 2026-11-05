//! Configuring built-in plugins.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::compare::{self, Finding};
use crate::devices::Error;
use crate::plugins::{self, Settings};
use crate::{AppState, server_error};

#[derive(Debug, Default, Deserialize)]
pub struct PluginForm {
    kind: String,
    name: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    key_file: String,
    #[serde(default)]
    host_key_file: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    password_file: String,
}

#[derive(Debug, Deserialize)]
pub struct PluginConfigForm {
    #[serde(default)]
    path: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    key_file: String,
    #[serde(default)]
    host_key_file: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    password_file: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct PluginToggleForm {
    enabled: Option<bool>,
}

struct PluginRow {
    name: String,
    kind: String,
    title: String,
    path: String,
    host: String,
    user: String,
    port: String,
    key_file: String,
    host_key_file: String,
    url: String,
    password_file: String,
    search: String,
    enabled: bool,
}

struct PluginScanRow {
    name: String,
    kind: String,
    status: String,
    error: String,
    findings: Vec<String>,
    discoveries: Vec<Discovery>,
}

struct Discovery {
    name: String,
    mac: String,
}

#[derive(Template)]
#[template(path = "plugins.html")]
struct PluginsPage {
    nav: &'static str,
    plugins: Vec<PluginRow>,
    scan_results: Vec<PluginScanRow>,
    has_scanned: bool,
    can_import: bool,
    form: PluginForm,
    error: String,
}

fn page(state: &AppState, form: PluginForm, error: String) -> Response {
    page_with_scan(state, form, error, Vec::new(), false)
}

fn page_with_scan(
    state: &AppState,
    form: PluginForm,
    error: String,
    scan_results: Vec<PluginScanRow>,
    has_scanned: bool,
) -> Response {
    let settings = match plugins::read_settings(&state.inner.plugins_path) {
        Ok(settings) => settings,
        Err(error) => return server_error(&error),
    };
    let rows = settings
        .plugins
        .iter()
        .map(|table| {
            let name = text(table, "name");
            let kind = text(table, "type");
            let path = text(table, "path");
            let host = text(table, "host");
            let user = text(table, "user");
            let key_file = text(table, "key_file");
            let host_key_file = text(table, "host_key_file");
            let url = text(table, "url");
            let password_file = text(table, "password_file");
            let port = table
                .get("port")
                .and_then(toml::Value::as_integer)
                .unwrap_or(22)
                .to_string();
            let title = match kind.as_str() {
                "leases-file" => "DHCP leases file".to_owned(),
                "openwrt" => "OpenWrt".to_owned(),
                _ => "Unknown plugin".to_owned(),
            };
            PluginRow {
                search: format!("{name} {kind} {path} {host} {user} {url}").to_ascii_lowercase(),
                name,
                kind,
                title,
                path,
                host,
                user,
                port,
                key_file,
                host_key_file,
                url,
                password_file,
                enabled: table
                    .get("enabled")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(true),
            }
        })
        .collect();
    let status = if error.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let page = PluginsPage {
        nav: "plugins",
        plugins: rows,
        scan_results,
        has_scanned,
        can_import: match state.devices() {
            Ok(devices) => devices.devices.is_empty() && !state.groups().default_group.is_empty(),
            Err(error) => return server_error(&error),
        },
        form,
        error,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Scans every enabled source plugin without applying changes.
pub async fn scan(State(state): State<AppState>) -> Response {
    let devices = match state.devices() {
        Ok(devices) => devices,
        Err(error) => return server_error(&error),
    };
    let groups = state.groups().groups;
    let active = match state.inner.plugins.read() {
        Ok(plugins) => plugins.clone(),
        Err(_) => return server_error(&"plugin lock poisoned"),
    };
    let mut scan_results = Vec::new();
    for plugin in active {
        let result = plugin.observe().await;
        let (status, error, findings, discoveries) = match result {
            Ok(observation) => {
                let discrepancies = compare::compare(&devices, &groups, &observation);
                let discoveries = discrepancies
                    .iter()
                    .filter_map(|finding| match finding {
                        Finding::Unknown { mac, hostname, .. } => Some(Discovery {
                            name: hostname.clone(),
                            mac: mac.clone(),
                        }),
                        _ => None,
                    })
                    .collect();
                let findings = discrepancies.iter().map(finding_text).collect::<Vec<_>>();
                let status = if findings.is_empty() {
                    "No discrepancies".to_owned()
                } else {
                    format!("{} discrepancies", findings.len())
                };
                (status, String::new(), findings, discoveries)
            }
            Err(error) => ("Scan failed".to_owned(), error, Vec::new(), Vec::new()),
        };
        scan_results.push(PluginScanRow {
            name: plugin.name().to_owned(),
            kind: plugin.kind().to_owned(),
            status,
            error,
            findings,
            discoveries,
        });
    }
    page_with_scan(&state, PluginForm::default(), String::new(), scan_results, true)
}

fn finding_text(finding: &Finding) -> String {
    match finding {
        Finding::Unknown { mac, ip, hostname } => format!(
            "Unknown device {} ({mac}, {})",
            if hostname.is_empty() {
                "without a hostname"
            } else {
                hostname
            },
            ip.map_or_else(|| "no IP address".to_owned(), |ip| ip.to_string())
        ),
        Finding::Missing { device } => format!("{device} has no matching entry"),
        Finding::WrongName { device, actual } => format!("{device} is named {actual}"),
        Finding::WrongIp {
            device,
            expected,
            actual,
        } => {
            format!("{device} has IP {actual:?}, expected {expected:?}")
        }
        Finding::WrongVlan {
            device,
            expected,
            actual,
        } => {
            format!("{device} is on VLAN {actual}, expected {expected}")
        }
        Finding::Foreign { mac, name } => format!("Unlisted entry {name} ({mac})"),
    }
}

fn text(table: &toml::Table, key: &str) -> String {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Lists and searches configured plugin instances.
pub async fn list(State(state): State<AppState>) -> Response {
    page(&state, PluginForm::default(), String::new())
}

/// Adds a built-in plugin instance.
pub async fn create(State(state): State<AppState>, Form(form): Form<PluginForm>) -> Response {
    let form = PluginForm {
        kind: form.kind.trim().to_owned(),
        name: form.name.trim().to_owned(),
        path: form.path.trim().to_owned(),
        host: form.host.trim().to_owned(),
        user: form.user.trim().to_owned(),
        port: form.port.trim().to_owned(),
        key_file: form.key_file.trim().to_owned(),
        host_key_file: form.host_key_file.trim().to_owned(),
        url: form.url.trim().to_owned(),
        password_file: form.password_file.trim().to_owned(),
    };
    change(&state, |settings| {
        let mut table = toml::Table::new();
        table.insert("type".to_owned(), toml::Value::String(form.kind.clone()));
        table.insert("name".to_owned(), toml::Value::String(form.name.clone()));
        table.insert("enabled".to_owned(), toml::Value::Boolean(true));
        match form.kind.as_str() {
            "leases-file" if !form.path.is_empty() => {
                table.insert("path".to_owned(), toml::Value::String(form.path.clone()));
            }
            "openwrt" => {
                let port = match form.port.parse::<u16>() {
                    Ok(port) if port != 0 => port,
                    _ => return Err("The SSH port must be from 1 to 65535".to_owned()),
                };
                table.insert("host".to_owned(), toml::Value::String(form.host.clone()));
                table.insert("user".to_owned(), toml::Value::String(form.user.clone()));
                table.insert("port".to_owned(), toml::Value::Integer(i64::from(port)));
                table.insert("key_file".to_owned(), toml::Value::String(form.key_file.clone()));
                table.insert(
                    "host_key_file".to_owned(),
                    toml::Value::String(form.host_key_file.clone()),
                );
            }
            "pihole" if !form.url.is_empty() && !form.password_file.is_empty() => {
                table.insert("url".to_owned(), toml::Value::String(form.url.clone()));
                table.insert(
                    "password_file".to_owned(),
                    toml::Value::String(form.password_file.clone()),
                );
            }
            "pihole" => return Err("The API URL and password file path are required".to_owned()),
            "leases-file" => return Err("The lease file path is required".to_owned()),
            _ => return Err("Choose a supported plugin type".to_owned()),
        }
        settings.plugins.push(table);
        Ok(())
    })
}

/// Changes the settings for an existing plugin.
pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<PluginConfigForm>,
) -> Response {
    let path = form.path.trim().to_owned();
    let host = form.host.trim().to_owned();
    let user = form.user.trim().to_owned();
    let key_file = form.key_file.trim().to_owned();
    let host_key_file = form.host_key_file.trim().to_owned();
    let url = form.url.trim().to_owned();
    let password_file = form.password_file.trim().to_owned();
    let port = form.port.trim().to_owned();
    change(&state, |settings| {
        let Some(plugin) = settings
            .plugins
            .iter_mut()
            .find(|table| text(table, "name") == name)
        else {
            return Err(format!("No plugin named {name}"));
        };
        match text(plugin, "type").as_str() {
            "leases-file" if !path.is_empty() => {
                plugin.insert("path".to_owned(), toml::Value::String(path));
            }
            "openwrt" => {
                let port = match port.parse::<u16>() {
                    Ok(port) if port != 0 => port,
                    _ => return Err("The SSH port must be from 1 to 65535".to_owned()),
                };
                plugin.insert("host".to_owned(), toml::Value::String(host));
                plugin.insert("user".to_owned(), toml::Value::String(user));
                plugin.insert("port".to_owned(), toml::Value::Integer(i64::from(port)));
                plugin.insert("key_file".to_owned(), toml::Value::String(key_file));
                plugin.insert("host_key_file".to_owned(), toml::Value::String(host_key_file));
            }
            "pihole" if !url.is_empty() && !password_file.is_empty() => {
                plugin.insert("url".to_owned(), toml::Value::String(url));
                plugin.insert("password_file".to_owned(), toml::Value::String(password_file));
            }
            "pihole" => return Err("The API URL and password file path are required".to_owned()),
            "leases-file" => return Err("The lease file path is required".to_owned()),
            _ => return Err("Unsupported plugin type".to_owned()),
        }
        Ok(())
    })
}

/// Enables or disables a plugin instance.
pub async fn toggle(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<PluginToggleForm>,
) -> Response {
    change(&state, |settings| {
        let Some(plugin) = settings
            .plugins
            .iter_mut()
            .find(|table| text(table, "name") == name)
        else {
            return Err(format!("No plugin named {name}"));
        };
        plugin.insert(
            "enabled".to_owned(),
            toml::Value::Boolean(form.enabled.unwrap_or(false)),
        );
        Ok(())
    })
}

fn change(state: &AppState, update: impl FnOnce(&mut Settings) -> Result<(), String>) -> Response {
    let Ok(_guard) = state.inner.write_lock.lock() else {
        return server_error(&"settings lock poisoned");
    };
    let mut settings = match plugins::read_settings(&state.inner.plugins_path) {
        Ok(settings) => settings,
        Err(error) => return server_error(&error),
    };
    if let Err(message) = update(&mut settings) {
        return page(state, PluginForm::default(), message);
    }
    match plugins::save_settings(&state.inner.plugins_path, &settings) {
        Ok(()) => {}
        Err(Error::Invalid(message)) => return page(state, PluginForm::default(), message),
        Err(error) => return server_error(&error),
    }
    let loaded = match plugins::load(&state.inner.plugins_path) {
        Ok(plugins) => plugins,
        Err(error) => return server_error(&error),
    };
    match state.inner.plugins.write() {
        Ok(mut plugins) => *plugins = loaded,
        Err(_) => return server_error(&"plugin lock poisoned"),
    }
    Redirect::to("/plugins").into_response()
}
