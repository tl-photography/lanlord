//! The settings page: choices that only change how lanlord looks.

use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::devices::Error;
use crate::plugins::{self, OverviewSettings};
use crate::{AppState, history, server_error};

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    nav: &'static str,
    overview: OverviewSettings,
    error: String,
}

fn page(overview: OverviewSettings, status: StatusCode, error: String) -> Response {
    let page = SettingsPage {
        nav: "settings",
        overview,
        error,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Shows the settings.
pub async fn show(State(state): State<AppState>) -> Response {
    match plugins::read_settings(&state.inner.plugins_path) {
        Ok(settings) => page(settings.overview, StatusCode::OK, String::new()),
        Err(error) => page(OverviewSettings::default(), StatusCode::OK, error.to_string()),
    }
}

/// The switches of the form; an unticked one is not sent.
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

/// Saves the settings.
pub async fn save(State(state): State<AppState>, Form(form): Form<SettingsForm>) -> Response {
    let Ok(_guard) = state.inner.write_lock.lock() else {
        return server_error(&"settings lock poisoned");
    };
    let mut settings = match plugins::read_settings(&state.inner.plugins_path) {
        Ok(settings) => settings,
        Err(error) => return server_error(&error),
    };
    let overview = OverviewSettings {
        show_mac: form.show_mac,
        show_ip: form.show_ip,
    };
    if settings.overview == overview {
        return Redirect::to("/settings").into_response();
    }
    settings.overview = overview;
    match plugins::save_settings(&state.inner.plugins_path, &settings) {
        Ok(()) => {
            history::record(
                &state.inner.history_path,
                &[format!(
                    "Overview changed: MAC {}, IP {}",
                    shown(overview.show_mac),
                    shown(overview.show_ip)
                )],
            );
            Redirect::to("/settings").into_response()
        }
        Err(Error::Invalid(message)) => page(overview, StatusCode::UNPROCESSABLE_ENTITY, message),
        Err(error) => server_error(&error),
    }
}
