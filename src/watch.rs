//! The background scan: looks at the plugins every few minutes and tells the notification plugins about new unknown
//! devices and about changes made outside lanlord (drift). With "restore" on, drift is undone through the normal
//! apply. Changes made in lanlord itself are never applied here: they wait for the Apply button.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::compare::{self, Finding};
use crate::devices::{DeviceList, write_private};
use crate::notify::Notification;
use crate::plugins::{self, Plugin};
use crate::{AppState, apply, history, plugin_ui};

/// How often the task looks whether a scan is due.
const TICK: Duration = Duration::from_secs(60);

/// What the background scan remembers between runs.
#[derive(Default)]
pub(crate) struct WatchState {
    /// Unknown MAC addresses already notified; kept in `notified-devices` in the data directory.
    notified: Option<HashSet<String>>,
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

fn fingerprint(devices: &DeviceList) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, format!("{devices:?}").as_bytes());
    digest.as_ref()[..16].iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

fn notified_path(state: &AppState) -> std::path::PathBuf {
    state.inner.history_path.with_file_name("notified-devices")
}

/// New unknown devices of this scan, as texts; remembers them.
async fn new_unknown(state: &AppState, active: &[Arc<dyn Plugin>], devices: &DeviceList) -> Vec<String> {
    let groups = state.groups().groups;
    let mut found = Vec::new();
    let results = plugin_ui::observe_all(active).await;
    plugin_ui::remember(state, &results);
    for (plugin, result) in active.iter().zip(results) {
        let Ok(Ok(observation)) = result else { continue };
        for finding in compare::compare(devices, &groups, &observation) {
            if let Finding::Unknown { mac, ip, hostname } = finding {
                let address = ip.map_or_else(|| "no address".to_owned(), |ip| ip.to_string());
                let name = if hostname.is_empty() {
                    "without a name"
                } else {
                    &hostname
                };
                found.push((
                    mac.clone(),
                    format!(
                        "Unknown device {name} ({mac}, {address}), seen by {}",
                        plugin.name()
                    ),
                ));
            }
        }
    }
    let path = notified_path(state);
    let Ok(mut watch) = state.inner.watch.lock() else {
        return Vec::new();
    };
    let notified = watch.notified.get_or_insert_with(|| {
        std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    });
    let texts: Vec<String> = found
        .into_iter()
        .filter(|(mac, _)| notified.insert(mac.clone()))
        .map(|(_, text)| text)
        .collect();
    if !texts.is_empty() {
        let mut macs: Vec<&str> = notified.iter().map(String::as_str).collect();
        macs.sort_unstable();
        if let Err(error) = write_private(&path, &(macs.join("\n") + "\n")) {
            tracing::error!("cannot write {}: {error}", path.display());
        }
    }
    texts
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
async fn drift(
    state: &AppState,
    active: &[Arc<dyn Plugin>],
    devices: &DeviceList,
    restore: bool,
) -> Vec<String> {
    let targets: Vec<Arc<dyn Plugin>> = active
        .iter()
        .filter(|plugin| plugin.is_target())
        .cloned()
        .collect();
    let list = fingerprint(devices);
    let mut texts = Vec::new();
    for (plugin, result) in targets.iter().zip(apply::previews(&targets, devices).await) {
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

async fn send(state: &AppState, active: &[Arc<dyn Plugin>], title: &str, texts: &[String]) {
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
    let Ok(devices) = state.devices() else { return };
    let Ok(active) = state.inner.plugins.read().map(|plugins| plugins.clone()) else {
        return;
    };
    let restore = plugins::read_settings(&state.inner.plugins_path)
        .unwrap_or_default()
        .scan
        .restore;
    let unknown = new_unknown(state, &active, &devices).await;
    send(state, &active, "lanlord: unknown device", &unknown).await;
    let changed = drift(state, &active, &devices, restore).await;
    send(state, &active, "lanlord: change outside lanlord", &changed).await;
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    if let Ok(mut watch) = state.inner.watch.lock() {
        watch.last = format!(
            "{} UTC: {} new unknown, {} outside changes",
            history::format_time(seconds),
            unknown.len(),
            changed.len()
        );
    }
}
