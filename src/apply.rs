//! The apply page: what each target would change, like `LuCI`'s list of unsaved changes, and the button that
//! applies it. Nothing is applied without that button.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

use crate::devices::DeviceList;
use crate::history;
use crate::plugins::{self, Plugin};
use crate::preview::Preview;
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

impl ApplyPage {
    /// The number of targets with open changes.
    fn open_targets(&self) -> usize {
        self.targets
            .iter()
            .filter(|target| !target.changes.is_empty())
            .count()
    }

    /// The number of open changes of all targets.
    fn open_changes(&self) -> usize {
        self.targets.iter().map(|target| target.changes.len()).sum()
    }
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

fn view(plugin: &dyn Plugin, result: Result<Option<Preview>, String>) -> TargetView {
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
                .steps
                .iter()
                .map(|step| ChangeView {
                    description: step.description.clone(),
                    commands: step.details.join("\n"),
                })
                .collect();
            view.notes = plan.notes;
        }
        Ok(None) => {}
        Err(error) => view.error = error,
    }
    view
}

/// The plan of every target, each with a time limit, in the order of the plugins.
async fn previews(active: &[Arc<dyn Plugin>], devices: &DeviceList) -> Vec<Result<Option<Preview>, String>> {
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
    results
        .into_iter()
        .map(|(_, result)| {
            result.unwrap_or_else(|_| Err(format!("No answer within {} s", PREVIEW_TIMEOUT.as_secs())))
        })
        .collect()
}

async fn page(state: &AppState, message: String, error: String) -> Response {
    let devices = match state.devices() {
        Ok(devices) => devices,
        Err(error) => return server_error(&error),
    };
    let Some(active) = targets(state) else {
        return server_error(&"plugin lock poisoned");
    };
    let results = previews(&active, &devices).await;
    state.remember_pending(count_changes(&results));
    let targets = active
        .iter()
        .zip(results)
        .map(|(plugin, result)| view(plugin.as_ref(), result))
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

fn count_changes(results: &[Result<Option<Preview>, String>]) -> usize {
    results
        .iter()
        .filter_map(|result| result.as_ref().ok().and_then(Option::as_ref))
        .map(|plan| plan.steps.len())
        .sum()
}

/// How many changes the targets would make, as JSON for the badge in the top bar; cached for a short time.
pub async fn count(State(state): State<AppState>) -> Response {
    if let Some(changes) = state.pending() {
        return count_json(changes);
    }
    let devices = match state.devices() {
        Ok(devices) => devices,
        Err(error) => return server_error(&error),
    };
    let Some(active) = targets(&state) else {
        return server_error(&"plugin lock poisoned");
    };
    let changes = count_changes(&previews(&active, &devices).await);
    state.remember_pending(changes);
    count_json(changes)
}

fn count_json(changes: usize) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        format!("{{\"changes\":{changes}}}"),
    )
        .into_response()
}

/// Shows what every target would change.
pub async fn list(State(state): State<AppState>) -> Response {
    page(&state, String::new(), String::new()).await
}

/// Applies the changes of one target, if they are still the ones shown; logs the result and returns it as text.
async fn apply_target(state: &AppState, plugin: &dyn Plugin, digest: String) -> Result<String, String> {
    let name = plugin.name();
    let devices = state.devices().map_err(|error| error.to_string())?;
    let history = &state.inner.history_path;
    state.forget_pending();
    match tokio::time::timeout(APPLY_TIMEOUT, plugin.apply(devices, digest)).await {
        Ok(Ok(applied)) if applied.is_empty() => Ok(format!("{name}: nothing to apply")),
        Ok(Ok(applied)) => {
            let count = applied.len();
            tracing::info!("{name}: {count} changes applied");
            let entries: Vec<String> = applied
                .iter()
                .map(|change| format!("Applied to {name}: {change}"))
                .collect();
            history::record(history, &entries);
            let changes = if count == 1 { "change" } else { "changes" };
            Ok(format!("{name}: {count} {changes} applied"))
        }
        Ok(Err(error)) => {
            tracing::warn!("{name}: apply failed: {error}");
            history::record(history, &[format!("Apply to {name} failed: {error}")]);
            Err(error)
        }
        Err(_) => {
            let error = format!(
                "{name}: no answer within {} s; unconfirmed changes are undone by the router",
                APPLY_TIMEOUT.as_secs()
            );
            tracing::warn!("{error}");
            history::record(history, &[format!("Apply to {name} failed: {error}")]);
            Err(error)
        }
    }
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
    let Some(plugin) = active.iter().find(|plugin| plugin.name() == name) else {
        return page(&state, String::new(), format!("No target named {name}")).await;
    };
    match apply_target(&state, plugin.as_ref(), digest).await {
        Ok(message) => page(&state, message, String::new()).await,
        Err(error) => page(&state, String::new(), error).await,
    }
}

/// Applies every target the form has a digest for, one after the other; a failed target does not stop the others.
pub async fn apply_all(State(state): State<AppState>, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some(active) = targets(&state) else {
        return server_error(&"plugin lock poisoned");
    };
    let mut messages = Vec::new();
    let mut errors = Vec::new();
    for plugin in &active {
        let Some(digest) = form.get(&format!("digest-{}", plugin.name())) else {
            continue;
        };
        match apply_target(&state, plugin.as_ref(), digest.clone()).await {
            Ok(message) => messages.push(message),
            Err(error) => errors.push(error),
        }
    }
    page(&state, messages.join("; "), errors.join("; ")).await
}
