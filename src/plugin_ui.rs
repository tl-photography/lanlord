//! Configuring built-in plugins.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::devices::Error;
use crate::plugins::{self, Settings};
use crate::{AppState, server_error};

#[derive(Debug, Default, Deserialize)]
pub struct PluginForm {
    kind: String,
    name: String,
    path: String,
}

#[derive(Debug, Deserialize)]
pub struct PluginPathForm {
    path: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct PluginToggleForm {
    enabled: Option<bool>,
}

struct PluginRow {
    name: String,
    title: String,
    path: String,
    search: String,
    enabled: bool,
}

#[derive(Template)]
#[template(path = "plugins.html")]
struct PluginsPage {
    nav: &'static str,
    plugins: Vec<PluginRow>,
    form: PluginForm,
    error: String,
}

fn page(state: &AppState, form: PluginForm, error: String) -> Response {
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
            let title = match kind.as_str() {
                "leases-file" => "DHCP leases file".to_owned(),
                _ => kind.clone(),
            };
            PluginRow {
                search: format!("{name} {kind} {path}").to_ascii_lowercase(),
                name,
                title,
                path,
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
        form,
        error,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
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
    };
    if form.kind != "leases-file" {
        return page(&state, form, "Choose a supported plugin type".to_owned());
    }
    if form.path.is_empty() {
        return page(&state, form, "The lease file path is required".to_owned());
    }
    change(&state, |settings| {
        let mut table = toml::Table::new();
        table.insert("type".to_owned(), toml::Value::String(form.kind.clone()));
        table.insert("name".to_owned(), toml::Value::String(form.name.clone()));
        table.insert("enabled".to_owned(), toml::Value::Boolean(true));
        table.insert("path".to_owned(), toml::Value::String(form.path.clone()));
        settings.plugins.push(table);
        Ok(())
    })
}

/// Changes the path for an existing lease-file plugin.
pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<PluginPathForm>,
) -> Response {
    let path = form.path.trim().to_owned();
    if path.is_empty() {
        return page(
            &state,
            PluginForm::default(),
            "The lease file path is required".to_owned(),
        );
    }
    change(&state, |settings| {
        let Some(plugin) = settings
            .plugins
            .iter_mut()
            .find(|table| text(table, "name") == name)
        else {
            return Err(format!("No plugin named {name}"));
        };
        plugin.insert("path".to_owned(), toml::Value::String(path));
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
