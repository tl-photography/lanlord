//! The settings page: what the overview shows, the background scan and the DNS service of all networks.

use std::collections::HashMap;

use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::devices::Error;
use crate::plugins::{self, OverviewSettings, ScanSettings, Settings};
use crate::{AppState, history, server_error};

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    nav: &'static str,
    overview: OverviewSettings,
    scan: ScanSettings,
    /// One line about the last background scan.
    last_scan: String,
    dns_options: Vec<DnsOption>,
    dns_service: String,
    error: String,
}

/// A DNS service to choose.
struct DnsOption {
    source: String,
    label: String,
}

fn page(state: &AppState, status: StatusCode, error: String) -> Response {
    let (settings, error) = match plugins::read_settings(&state.inner.plugins_path) {
        Ok(settings) => (settings, error),
        Err(problem) => (Settings::default(), problem.to_string()),
    };
    let dns_options = state
        .devices()
        .map(|list| state.services(&list))
        .unwrap_or_default()
        .into_iter()
        .filter(|service| service.kind == "dns")
        .map(|service| DnsOption {
            label: format!("{} ({})", service.source, service.address),
            source: service.source,
        })
        .collect();
    let page = SettingsPage {
        nav: "settings",
        overview: settings.overview,
        scan: settings.scan,
        last_scan: state
            .inner
            .watch
            .lock()
            .map(|watch| watch.last.clone())
            .unwrap_or_default(),
        dns_options,
        dns_service: state.groups().dns_service,
        error,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Shows the settings.
pub async fn show(State(state): State<AppState>) -> Response {
    page(&state, StatusCode::OK, String::new())
}

/// Saves a change of the settings; `lines` says what goes into the history.
fn change(
    state: &AppState,
    update: impl FnOnce(&mut Settings),
    lines: impl FnOnce(&Settings, &Settings) -> Vec<String>,
) -> Response {
    let Ok(guard) = state.inner.write_lock.lock() else {
        return server_error(&"settings lock poisoned");
    };
    let mut settings = match plugins::read_settings(&state.inner.plugins_path) {
        Ok(settings) => settings,
        Err(error) => return server_error(&error),
    };
    let before = settings.clone();
    update(&mut settings);
    match plugins::save_settings(&state.inner.plugins_path, &settings) {
        Ok(()) => {
            history::record(&state.inner.history_path, &lines(&before, &settings));
            Redirect::to("/settings").into_response()
        }
        Err(Error::Invalid(message)) => {
            drop(guard);
            page(state, StatusCode::UNPROCESSABLE_ENTITY, message)
        }
        Err(error) => server_error(&error),
    }
}

/// The switches of the overview form; an unticked one is not sent.
#[derive(Debug, Deserialize)]
pub struct SettingsForm {
    #[serde(default)]
    show_mac: bool,
    #[serde(default)]
    show_ip: bool,
}

fn shown(show: bool) -> &'static str {
    if show { "shown" } else { "hidden" }
}

/// Saves what the overview shows.
pub async fn save(State(state): State<AppState>, Form(form): Form<SettingsForm>) -> Response {
    let overview = OverviewSettings {
        show_mac: form.show_mac,
        show_ip: form.show_ip,
    };
    change(
        &state,
        |settings| settings.overview = overview,
        |before, _| {
            if before.overview == overview {
                return Vec::new();
            }
            vec![format!(
                "Overview changed: MAC {}, IP {}",
                shown(overview.show_mac),
                shown(overview.show_ip)
            )]
        },
    )
}

/// Field of the form for the DNS service.
#[derive(Debug, Deserialize)]
pub struct DnsForm {
    service: String,
}

/// Chooses the DNS service of all networks; empty is the router.
pub async fn dns(State(state): State<AppState>, Form(form): Form<DnsForm>) -> Response {
    let Ok(guard) = state.inner.write_lock.lock() else {
        return server_error(&"settings lock poisoned");
    };
    let service = form.service.trim();
    let offered = state
        .devices()
        .map(|list| state.services(&list))
        .unwrap_or_default();
    if !service.is_empty()
        && !offered
            .iter()
            .any(|offer| offer.kind == "dns" && offer.source == service)
    {
        drop(guard);
        return page(
            &state,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{service} offers no DNS service"),
        );
    }
    let before = state.groups();
    let mut config = before.clone();
    service.clone_into(&mut config.dns_service);
    match config.save(&state.inner.groups_path) {
        Ok(()) => {
            history::record(&state.inner.history_path, &history::groups(&before, &config));
            if let Ok(mut groups) = state.inner.groups.write() {
                *groups = config;
            }
            Redirect::to("/settings").into_response()
        }
        Err(error) => server_error(&error),
    }
}

/// Sets the interval and the restore option of the background scan.
pub async fn background(
    State(state): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Ok(interval_minutes) = form
        .get("interval")
        .map_or("0", String::as_str)
        .trim()
        .parse::<u32>()
    else {
        return page(
            &state,
            StatusCode::UNPROCESSABLE_ENTITY,
            "The interval must be a number of minutes".to_owned(),
        );
    };
    let restore = form.get("restore").is_some_and(|value| value == "true");
    change(
        &state,
        |settings| {
            settings.scan = ScanSettings {
                interval_minutes,
                restore,
            };
        },
        history::plugins,
    )
}
