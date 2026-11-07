//! What a scan changes in the list: unknown devices join the default group, and devices in the default group that were
//! not seen for a while leave it. The last-seen dates are kept apart from the list.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::AppState;
use crate::compare::Observation;
use crate::devices::{DeviceList, Interface, is_valid_name, write_private};

/// Days after which a device in the default group that was not seen is removed.
pub(crate) const PRUNE_AFTER_DAYS: u64 = 30;
const DAY: u64 = 86_400;

/// Seconds since the epoch.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn seen_path(state: &AppState) -> PathBuf {
    state.inner.history_path.with_file_name("last-seen")
}

/// Reads `<mac> <seconds>` lines; a line that does not fit is skipped.
fn read_seen(path: &Path) -> HashMap<String, u64> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (mac, time) = line.split_once(' ')?;
            Some((mac.to_owned(), time.parse().ok()?))
        })
        .collect()
}

fn write_seen(path: &Path, seen: &HashMap<String, u64>) {
    let mut lines: Vec<String> = seen.iter().map(|(mac, time)| format!("{mac} {time}\n")).collect();
    lines.sort_unstable();
    if let Err(error) = write_private(path, &lines.concat()) {
        tracing::error!("cannot write {}: {error}", path.display());
    }
}

/// A DNS name from the host name a device sent, or from its MAC address.
pub(crate) fn suggested_name(hostname: &str, mac: &str) -> String {
    let mut name = String::new();
    let mut separator = false;
    for character in hostname.chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !name.is_empty() {
                name.push('-');
            }
            name.push(character.to_ascii_lowercase());
            separator = false;
        } else if !name.is_empty() {
            separator = true;
        }
    }
    if is_valid_name(&name) {
        name
    } else {
        let suffix = mac.replace(':', "");
        format!("device-{}", &suffix[suffix.len().saturating_sub(6)..])
    }
}

/// The name, or the name with a number if it is taken.
fn unique_name(list: &DeviceList, name: &str) -> String {
    let taken = |candidate: &str| {
        list.interfaces
            .iter()
            .any(|interface| interface.name.eq_ignore_ascii_case(candidate))
    };
    if !taken(name) {
        return name.to_owned();
    }
    (2..1000)
        .map(|number| {
            let suffix = format!("-{number}");
            let base: String = name.chars().take(63 - suffix.len()).collect();
            format!("{}{suffix}", base.trim_end_matches('-'))
        })
        .find(|candidate| !taken(candidate))
        .unwrap_or_default()
}

/// Takes in one scan: adds unknown devices to the default group, marked as new, and removes devices of the default
/// group that were not seen for [`PRUNE_AFTER_DAYS`]. Without an answer from every plugin (`complete` false), nobody
/// is removed. Returns texts for the history and the notifications.
pub(crate) fn take_in(
    state: &AppState,
    observations: &[&Observation],
    complete: bool,
    now: u64,
) -> Vec<String> {
    let config = state.groups();
    let default = config.default_group.clone();
    let Some(group) = config.groups.iter().find(|group| group.name == default) else {
        return Vec::new();
    };
    let Ok(_guard) = state.inner.write_lock.lock() else {
        return Vec::new();
    };
    let Ok(mut list) = state.devices() else {
        return Vec::new();
    };
    let mut present: Vec<(String, String)> = Vec::new();
    for observed in observations.iter().flat_map(|observation| &observation.present) {
        let mac = observed.mac.to_ascii_lowercase();
        match present.iter_mut().find(|(known, _)| *known == mac) {
            Some((_, hostname)) if hostname.is_empty() => hostname.clone_from(&observed.hostname),
            Some(_) => {}
            None => present.push((mac, observed.hostname.clone())),
        }
    }
    let known: HashSet<String> = list
        .interfaces
        .iter()
        .map(|interface| interface.mac.clone())
        .collect();
    let mut texts = Vec::new();
    for (mac, hostname) in present.iter().filter(|(mac, _)| !known.contains(mac)) {
        let name = unique_name(&list, &suggested_name(hostname, mac));
        texts.push(format!("New device {name} ({mac}) added to {}", group.title()));
        list.interfaces.push(Interface {
            name,
            mac: mac.clone(),
            group: default.clone(),
            ip: None,
            self_assigned: false,
            unreviewed: true,
            note: String::new(),
            device: String::new(),
        });
    }
    let path = seen_path(state);
    let mut seen = read_seen(&path);
    for (mac, _) in &present {
        seen.insert(mac.clone(), now);
    }
    let mut removed = Vec::new();
    list.interfaces.retain(|interface| {
        if interface.group != default {
            return true;
        }
        let seen_at = *seen.entry(interface.mac.clone()).or_insert(now);
        let expired = complete && now.saturating_sub(seen_at) >= PRUNE_AFTER_DAYS * DAY;
        if expired {
            removed.push(format!(
                "{} removed from {}: not seen for {PRUNE_AFTER_DAYS} days",
                interface.name,
                group.title()
            ));
        }
        !expired
    });
    let in_default: HashSet<&str> = list
        .interfaces
        .iter()
        .filter(|interface| interface.group == default)
        .map(|interface| interface.mac.as_str())
        .collect();
    seen.retain(|mac, _| in_default.contains(mac.as_str()));
    texts.extend(removed);
    if !texts.is_empty() {
        if let Err(error) = list.save(&state.inner.devices_path, &config.group_names()) {
            tracing::error!("cannot save the devices found by a scan: {error}");
            return Vec::new();
        }
        state.forget_pending();
    }
    write_seen(&path, &seen);
    texts
}

#[cfg(test)]
mod tests;
