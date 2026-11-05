//! The plugins page: add, configure, enable and scan plugin instances. Fields and checks come from the type
//! descriptions in `plugins`, so a new type needs no code here.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::compare::{self, Finding};
use crate::devices::Error;
use crate::history;
use crate::plugins::{self, Field, FieldKind, Plugin, PluginType, Settings};
use crate::{AppState, server_error};

/// Longest time one plugin may take for a scan.
const SCAN_TIMEOUT: Duration = Duration::from_secs(20);

struct FieldView {
    key: &'static str,
    label: &'static str,
    value: String,
    input: &'static str,
    placeholder: &'static str,
}

struct PluginRow {
    name: String,
    problem: String,
    title: &'static str,
    enabled: bool,
    search: String,
    fields: Vec<FieldView>,
}

struct TypeView {
    kind: &'static str,
    title: &'static str,
    description: &'static str,
    fields: Vec<FieldView>,
}

struct ScanRow {
    name: String,
    title: &'static str,
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
    types: Vec<TypeView>,
    scan_results: Vec<ScanRow>,
    has_scanned: bool,
    can_import: bool,
    error: String,
}

fn input(field: &Field) -> &'static str {
    match field.kind {
        FieldKind::Url => "url",
        _ => "text",
    }
}

fn field_views(fields: &'static [Field], values: impl Fn(&str) -> String) -> Vec<FieldView> {
    fields
        .iter()
        .map(|field| FieldView {
            key: field.key,
            label: field.label,
            value: values(field.key),
            input: input(field),
            placeholder: field.placeholder,
        })
        .collect()
}

fn table_text(table: &toml::Table, key: &str) -> String {
    match table.get(key) {
        Some(toml::Value::String(text)) => text.clone(),
        Some(toml::Value::Integer(number)) => number.to_string(),
        _ => String::new(),
    }
}

fn page(state: &AppState, scan_results: Vec<ScanRow>, has_scanned: bool, error: String) -> Response {
    // A broken lanlord.toml is shown, not hidden behind an error page, so it can be fixed here.
    let (settings, file_problem) = match plugins::read_settings(&state.inner.plugins_path) {
        Ok(settings) => (settings, String::new()),
        Err(error) => (Settings::default(), error.to_string()),
    };
    let problems = plugins::check(
        settings.plugins.clone(),
        &plugins::data_dir(&state.inner.plugins_path),
    )
    .problems;
    let rows = settings
        .plugins
        .iter()
        .zip(problems)
        .map(|(table, problem)| {
            let name = table_text(table, "name");
            let kind = table_text(table, "type");
            let plugin_type = plugins::plugin_type(&kind);
            let fields = plugin_type.map_or_else(Vec::new, |plugin_type| {
                field_views(plugin_type.fields, |key| table_text(table, key))
            });
            PluginRow {
                search: format!("{name} {kind}").to_ascii_lowercase(),
                problem: problem.unwrap_or_default(),
                name,
                title: plugin_type.map_or("Unknown type", |plugin_type| plugin_type.title),
                enabled: table
                    .get("enabled")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(true),
                fields,
            }
        })
        .collect();
    let types = plugins::TYPES
        .iter()
        .map(|plugin_type| TypeView {
            kind: plugin_type.kind,
            title: plugin_type.title,
            description: plugin_type.description,
            fields: field_views(plugin_type.fields, |_| String::new()),
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
        types,
        scan_results,
        has_scanned,
        can_import: !state.groups().default_group.is_empty(),
        error: if error.is_empty() { file_problem } else { error },
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Lists the configured plugins and the types that can be added.
pub async fn list(State(state): State<AppState>) -> Response {
    page(&state, Vec::new(), false, String::new())
}

/// Checks the submitted values for every field of a type and turns them into settings.
fn settings_table(plugin_type: &PluginType, form: &HashMap<String, String>) -> Result<toml::Table, String> {
    let mut table = toml::Table::new();
    for field in plugin_type.fields {
        let value = form.get(field.key).map_or("", String::as_str);
        table.insert(field.key.to_owned(), plugins::field_value(field, value)?);
    }
    Ok(table)
}

/// Adds a plugin instance; the form has `type`, `name` and the fields of the type.
pub async fn create(State(state): State<AppState>, Form(form): Form<HashMap<String, String>>) -> Response {
    let kind = form.get("type").map_or("", |kind| kind.trim());
    let Some(plugin_type) = plugins::plugin_type(kind) else {
        return page(
            &state,
            Vec::new(),
            false,
            "Choose a supported plugin type".to_owned(),
        );
    };
    let name = form.get("name").map_or("", |name| name.trim()).to_owned();
    change(&state, |settings| {
        let mut table = settings_table(plugin_type, &form)?;
        table.insert(
            "type".to_owned(),
            toml::Value::String(plugin_type.kind.to_owned()),
        );
        table.insert("name".to_owned(), toml::Value::String(name));
        table.insert("enabled".to_owned(), toml::Value::Boolean(true));
        settings.plugins.push(table);
        Ok(())
    })
}

fn find<'a>(settings: &'a mut Settings, name: &str) -> Result<&'a mut toml::Table, String> {
    settings
        .plugins
        .iter_mut()
        .find(|table| table_text(table, "name") == name)
        .ok_or_else(|| format!("No plugin named {name}"))
}

/// Changes the settings of a plugin instance; its type and name stay.
pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    change(&state, |settings| {
        let plugin = find(settings, &name)?;
        let Some(plugin_type) = plugins::plugin_type(&table_text(plugin, "type")) else {
            return Err("Unknown plugin type".to_owned());
        };
        // New settings replace all old ones, so leftovers of an older version cannot keep the entry invalid.
        let fields = settings_table(plugin_type, &form)?;
        plugin.retain(|key, _| matches!(key, "type" | "name" | "enabled"));
        plugin.extend(fields);
        Ok(())
    })
}

/// Deletes a plugin instance, also a broken one.
pub async fn delete(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    change(&state, |settings| {
        let before = settings.plugins.len();
        settings.plugins.retain(|table| table_text(table, "name") != name);
        if settings.plugins.len() == before {
            return Err(format!("No plugin named {name}"));
        }
        Ok(())
    })
}

/// Enables or disables a plugin instance; an unchecked box sends no value.
pub async fn toggle(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let enabled = form.get("enabled").is_some_and(|value| value == "true");
    change(&state, |settings| {
        find(settings, &name)?.insert("enabled".to_owned(), toml::Value::Boolean(enabled));
        Ok(())
    })
}

fn change(state: &AppState, update: impl FnOnce(&mut Settings) -> Result<(), String>) -> Response {
    let Ok(guard) = state.inner.write_lock.lock() else {
        return server_error(&"settings lock poisoned");
    };
    let mut settings = match plugins::read_settings(&state.inner.plugins_path) {
        Ok(settings) => settings,
        Err(error) => return server_error(&error),
    };
    let before = settings.clone();
    if let Err(message) = update(&mut settings) {
        drop(guard);
        return page(state, Vec::new(), false, message);
    }
    match plugins::save_settings(&state.inner.plugins_path, &settings) {
        Ok(()) => history::record(&state.inner.history_path, &history::plugins(&before, &settings)),
        Err(Error::Invalid(message)) => {
            drop(guard);
            return page(state, Vec::new(), false, message);
        }
        Err(error) => return server_error(&error),
    }
    let loaded = plugins::load(&state.inner.plugins_path).plugins;
    match state.inner.plugins.write() {
        Ok(mut plugins) => *plugins = loaded,
        Err(_) => return server_error(&"plugin lock poisoned"),
    }
    Redirect::to("/plugins").into_response()
}

/// Scans every enabled plugin at the same time, each with a time limit, without changing anything.
pub async fn scan(State(state): State<AppState>) -> Response {
    let devices = match state.devices() {
        Ok(devices) => devices,
        Err(error) => return server_error(&error),
    };
    let groups = state.groups().groups;
    let active: Vec<Arc<dyn Plugin>> = match state.inner.plugins.read() {
        Ok(plugins) => plugins.clone(),
        Err(_) => return server_error(&"plugin lock poisoned"),
    };
    let mut tasks = tokio::task::JoinSet::new();
    for (index, plugin) in active.iter().cloned().enumerate() {
        tasks.spawn(async move { (index, tokio::time::timeout(SCAN_TIMEOUT, plugin.observe()).await) });
    }
    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(result) = joined {
            results.push(result);
        }
    }
    results.sort_by_key(|(index, _)| *index);
    let scan_results = results
        .into_iter()
        .map(|(index, result)| {
            let plugin = &active[index];
            let title =
                plugins::plugin_type(plugin.kind()).map_or("Unknown type", |plugin_type| plugin_type.title);
            let observation = match result {
                Ok(Ok(observation)) => observation,
                Ok(Err(error)) => return failed(plugin.name(), title, error),
                Err(_) => {
                    return failed(
                        plugin.name(),
                        title,
                        format!("No answer within {} s", SCAN_TIMEOUT.as_secs()),
                    );
                }
            };
            let findings = compare::compare(&devices, &groups, &observation);
            let discoveries = findings
                .iter()
                .filter_map(|finding| match finding {
                    Finding::Unknown { mac, hostname, .. } => Some(Discovery {
                        name: hostname.clone(),
                        mac: mac.clone(),
                    }),
                    _ => None,
                })
                .collect();
            ScanRow {
                name: plugin.name().to_owned(),
                title,
                status: match findings.len() {
                    0 => "No discrepancies".to_owned(),
                    1 => "1 discrepancy".to_owned(),
                    count => format!("{count} discrepancies"),
                },
                error: String::new(),
                findings: findings.iter().map(finding_text).collect(),
                discoveries,
            }
        })
        .collect();
    page(&state, scan_results, true, String::new())
}

fn failed(name: &str, title: &'static str, error: String) -> ScanRow {
    ScanRow {
        name: name.to_owned(),
        title,
        status: "Scan failed".to_owned(),
        error,
        findings: Vec::new(),
        discoveries: Vec::new(),
    }
}

fn address(ip: Option<std::net::Ipv4Addr>) -> String {
    ip.map_or_else(|| "no address".to_owned(), |ip| ip.to_string())
}

fn finding_text(finding: &Finding) -> String {
    match finding {
        Finding::Unknown { mac, ip, hostname } => {
            let name = if hostname.is_empty() {
                "without a host name"
            } else {
                hostname
            };
            format!("Unknown device {name} ({mac}, {})", address(*ip))
        }
        Finding::Missing { device } => format!("{device} has no entry"),
        Finding::WrongName { device, actual } => format!("{device} is named {actual}"),
        Finding::WrongIp {
            device,
            expected,
            actual,
        } => format!(
            "{device} has {}, expected {}",
            address(*actual),
            address(*expected)
        ),
        Finding::WrongVlan {
            device,
            expected,
            actual,
        } => format!("{device} is in VLAN {actual}, expected {expected}"),
        Finding::Foreign { mac, name } => format!("Entry {name} ({mac}) is not in the list"),
    }
}
