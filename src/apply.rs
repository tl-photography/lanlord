//! The apply page: what each target would change, like `LuCI`'s list of unsaved changes, and the button that
//! applies it. Nothing is applied without that button.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

use crate::leases::Plan;
use crate::plugins::{self, Plugin};
use crate::{AppState, server_error};

/// Longest time for a preview of one target.
const PREVIEW_TIMEOUT: Duration = Duration::from_secs(20);
/// Longest time for applying: the changes, the router's reload and the check before the confirmation.
const APPLY_TIMEOUT: Duration = Duration::from_secs(60);

struct ChangeView {
    description: String,
    commands: String,
}

struct TargetView {
    name: String,
    title: &'static str,
    error: String,
    manages: bool,
    changes: Vec<ChangeView>,
    notes: Vec<String>,
    digest: String,
}

#[derive(Template)]
#[template(path = "apply.html")]
struct ApplyPage {
    nav: &'static str,
    targets: Vec<TargetView>,
    message: String,
    error: String,
}

/// The enabled plugins that apply changes; `None` if the plugin lock is poisoned.
fn targets(state: &AppState) -> Option<Vec<Arc<dyn Plugin>>> {
    let plugins = state.inner.plugins.read().ok()?;
    Some(
        plugins
            .iter()
            .filter(|plugin| plugin.is_target())
            .cloned()
            .collect(),
    )
}

fn view(plugin: &dyn Plugin, result: Result<Option<Plan>, String>) -> TargetView {
    let mut view = TargetView {
        name: plugin.name().to_owned(),
        title: plugins::plugin_type(plugin.kind()).map_or("Unknown type", |plugin_type| plugin_type.title),
        error: String::new(),
        manages: false,
        changes: Vec::new(),
        notes: Vec::new(),
        digest: String::new(),
    };
    match result {
        Ok(Some(plan)) => {
            view.manages = true;
            view.digest = plan.digest();
            view.changes = plan
                .changes
                .iter()
                .map(|change| ChangeView {
                    description: change.description().to_owned(),
                    commands: change.commands().join("\n"),
                })
                .collect();
            view.notes = plan.notes;
        }
        Ok(None) => {}
        Err(error) => view.error = error,
    }
    view
}

async fn page(state: &AppState, message: String, error: String) -> Response {
    let devices = match state.devices() {
        Ok(devices) => devices,
        Err(error) => return server_error(&error),
    };
    let Some(active) = targets(state) else {
        return server_error(&"plugin lock poisoned");
    };
    let mut tasks = tokio::task::JoinSet::new();
    for (index, plugin) in active.iter().cloned().enumerate() {
        let devices = devices.clone();
        tasks.spawn(async move {
            (
                index,
                tokio::time::timeout(PREVIEW_TIMEOUT, plugin.plan(devices)).await,
            )
        });
    }
    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(result) = joined {
            results.push(result);
        }
    }
    results.sort_by_key(|(index, _)| *index);
    let targets = results
        .into_iter()
        .map(|(index, result)| {
            let result =
                result.unwrap_or_else(|_| Err(format!("No answer within {} s", PREVIEW_TIMEOUT.as_secs())));
            view(active[index].as_ref(), result)
        })
        .collect();
    let status = if error.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let page = ApplyPage {
        nav: "apply",
        targets,
        message,
        error,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Shows what every target would change.
pub async fn list(State(state): State<AppState>) -> Response {
    page(&state, String::new(), String::new()).await
}

/// Applies the changes of one target, if they are still the ones shown (`digest`).
pub async fn apply(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let digest = form.get("digest").cloned().unwrap_or_default();
    let Some(active) = targets(&state) else {
        return server_error(&"plugin lock poisoned");
    };
    let plugin = active.into_iter().find(|plugin| plugin.name() == name);
    let Some(plugin) = plugin else {
        return page(&state, String::new(), format!("No target named {name}")).await;
    };
    let devices = match state.devices() {
        Ok(devices) => devices,
        Err(error) => return server_error(&error),
    };
    match tokio::time::timeout(APPLY_TIMEOUT, plugin.apply(devices, digest)).await {
        Ok(Ok(0)) => page(&state, format!("{name}: nothing to apply"), String::new()).await,
        Ok(Ok(count)) => {
            tracing::info!("{name}: {count} changes applied");
            let changes = if count == 1 { "change" } else { "changes" };
            page(
                &state,
                format!("{name}: {count} {changes} applied"),
                String::new(),
            )
            .await
        }
        Ok(Err(error)) => {
            tracing::warn!("{name}: apply failed: {error}");
            page(&state, String::new(), error).await
        }
        Err(_) => {
            let error = format!(
                "{name}: no answer within {} s; unconfirmed changes are undone by the router",
                APPLY_TIMEOUT.as_secs()
            );
            tracing::warn!("{error}");
            page(&state, String::new(), error).await
        }
    }
}
