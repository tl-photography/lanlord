//! The background scan: looks at the plugins every few minutes, adds new devices and removes old guests, and tells the
//! notification plugins about that and about changes made outside lanlord (drift). With "restore" on, drift is undone through the normal
//! apply. Changes made in lanlord itself are never applied here: they wait for the Apply button.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::compare;
use crate::notify::Notification;
use crate::plan::Plan;
use crate::plugins::{self, Plugin};
use crate::{AppState, apply, guests, history, plugin_ui};

/// How often the task looks whether a scan is due.
const TICK: Duration = Duration::from_secs(60);

/// What the background scan remembers between runs.
#[derive(Default)]
pub(crate) struct WatchState {
    /// Per target: the fingerprint of the device list it last matched.
    in_sync: HashMap<String, String>,
    /// Per target: the digest of the drift already notified.
    drift: HashMap<String, String>,
    /// One line about the last run, for the Plugins page.
    pub(crate) last: String,
}

/// Starts the task; it reads the interval from the settings before every scan, so changes need no restart.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut last_run: Option<Instant> = None;
        loop {
            tokio::time::sleep(TICK).await;
            let settings = plugins::read_settings(&state.inner.plugins_path)
                .unwrap_or_default()
                .scan;
            let interval = Duration::from_secs(u64::from(settings.interval_minutes) * 60);
            if interval.is_zero() || last_run.is_some_and(|run| run.elapsed() < interval) {
                continue;
            }
            last_run = Some(Instant::now());
            run_once(&state).await;
        }
    });
}

fn fingerprint(plan: &Plan) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, format!("{plan:?}").as_bytes());
    digest.as_ref()[..16].iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// What the watch state says about the plan of one target: drift to report, with its digest.
fn check_drift(state: &AppState, name: &str, list: &str, steps: usize, digest: &str) -> bool {
    let Ok(mut watch) = state.inner.watch.lock() else {
        return false;
    };
    if steps == 0 {
        watch.in_sync.insert(name.to_owned(), list.to_owned());
        watch.drift.remove(name);
        return false;
    }
    if watch.in_sync.get(name).map(String::as_str) != Some(list)
        || watch.drift.get(name).map(String::as_str) == Some(digest)
    {
        return false;
    }
    watch.drift.insert(name.to_owned(), digest.to_owned());
    true
}

/// Finds drift on the targets; restores it if that is switched on. Returns texts for the notifications.
async fn drift(state: &AppState, active: &[Arc<dyn Plugin>], plan: &Plan, restore: bool) -> Vec<String> {
    let targets: Vec<Arc<dyn Plugin>> = active
        .iter()
        .filter(|plugin| plugin.is_target())
        .cloned()
        .collect();
    let list = fingerprint(plan);
    let mut texts = Vec::new();
    for (plugin, result) in targets.iter().zip(apply::previews(&targets, plan).await) {
        let Ok(Some(preview)) = result else { continue };
        let name = plugin.name();
        let digest = preview.digest();
        if !check_drift(state, name, &list, preview.steps.len(), &digest) {
            continue;
        }
        let what: Vec<&str> = preview
            .steps
            .iter()
            .map(|step| step.description.as_str())
            .collect();
        let what = what.join("; ");
        texts.push(if restore {
            match apply::apply_target(state, plugin.as_ref(), digest).await {
                Ok(result) => {
                    if let Ok(mut watch) = state.inner.watch.lock() {
                        watch.drift.remove(name);
                    }
                    format!("Restored after a change outside lanlord: {result} ({what})")
                }
                Err(error) => format!("{name} changed outside lanlord, restoring failed: {error} ({what})"),
            }
        } else {
            format!("{name} changed outside lanlord, see the Apply page: {what}")
        });
    }
    texts
}

pub(crate) async fn send(state: &AppState, active: &[Arc<dyn Plugin>], title: &str, texts: &[String]) {
    if texts.is_empty() {
        return;
    }
    history::record(&state.inner.history_path, texts);
    let notification = Notification {
        title: title.to_owned(),
        text: texts.join("\n"),
    };
    for plugin in active.iter().filter(|plugin| plugin.notifies()) {
        if let Err(error) = plugin.notify(notification.clone()).await {
            tracing::warn!("{}: notification failed: {error}", plugin.name());
        }
    }
}

/// One background scan.
pub async fn run_once(state: &AppState) {
    let Ok(active) = state.inner.plugins.read().map(|plugins| plugins.clone()) else {
        return;
    };
    let restore = plugins::read_settings(&state.inner.plugins_path)
        .unwrap_or_default()
        .scan
        .restore;
    let results = plugin_ui::observe_all(&active).await;
    let complete = results.iter().all(|result| matches!(result, Ok(Ok(_))));
    let observations: Vec<&compare::Observation> = results
        .iter()
        .filter_map(|result| match result {
            Ok(Ok(observation)) => Some(observation),
            _ => None,
        })
        .collect();
    let seconds = guests::now();
    let found = guests::take_in(state, &observations, complete, seconds);
    send(state, &active, "lanlord: devices", &found).await;
    let Ok(plan) = state.plan() else { return };
    let changed = drift(state, &active, &plan, restore).await;
    send(state, &active, "lanlord: change outside lanlord", &changed).await;
    if let Ok(mut watch) = state.inner.watch.lock() {
        watch.last = format!(
            "{} UTC: {} devices added or removed, {} outside changes",
            history::format_time(seconds),
            found.len(),
            changed.len()
        );
    }
}
