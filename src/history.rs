//! The change log: one line per change in `history.log` in the data directory, time in UTC and what changed,
//! before and after. Only appended, never rewritten; readable for the owner only.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::devices::Device;
use crate::plugins::Settings;

/// One entry of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Time in UTC, `YYYY-MM-DD HH:MM:SS`.
    pub time: String,
    /// What changed.
    pub text: String,
}

/// Formats seconds since 1970 as `YYYY-MM-DD HH:MM:SS` in UTC.
#[must_use]
pub fn format_time(seconds: u64) -> String {
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    // Days to the civil date, after Howard Hinnant's `civil_from_days`, for dates from 1970 on.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Appends entries with the current time. A failure is logged, it never stops the change itself.
pub fn record(path: &Path, texts: &[String]) {
    if texts.is_empty() {
        return;
    }
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let time = format_time(seconds);
    let mut lines = String::new();
    for text in texts {
        let text = text.replace(['\n', '\r', '\t'], " ");
        let _ = writeln!(lines, "{time}\t{text}");
    }
    let written = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(lines.as_bytes()));
    if let Err(error) = written {
        tracing::error!("cannot write the change log {}: {error}", path.display());
    }
}

/// The newest entries, newest first. A missing log has no entries.
#[must_use]
pub fn read_newest(path: &Path, count: usize) -> Vec<Entry> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut entries: Vec<Entry> = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| {
            let (time, text) = line.split_once('\t')?;
            Some(Entry {
                time: time.to_owned(),
                text: text.to_owned(),
            })
        })
        .collect();
    entries.reverse();
    entries.truncate(count);
    entries
}

fn optional(text: &str) -> &str {
    if text.is_empty() { "none" } else { text }
}

fn ip_text(device: &Device) -> String {
    device.ip.map_or_else(|| "none".to_owned(), |ip| ip.to_string())
}

/// Describes a new or changed device.
#[must_use]
pub fn device(before: Option<&Device>, after: &Device) -> Option<String> {
    let Some(before) = before else {
        return Some(format!(
            "Device {} added: group {}, MAC {}, IP {}",
            after.name,
            after.group,
            after.mac,
            ip_text(after)
        ));
    };
    let mut changes = Vec::new();
    let mut compare = |field: &str, old: &str, new: &str| {
        if old != new {
            changes.push(format!("{field} {} → {}", optional(old), optional(new)));
        }
    };
    compare("name", &before.name, &after.name);
    compare("group", &before.group, &after.group);
    compare("MAC", &before.mac, &after.mac);
    compare("IP", &ip_text(before), &ip_text(after));
    compare("note", &before.note, &after.note);
    compare("machine", &before.machine, &after.machine);
    (!changes.is_empty()).then(|| format!("Device {} changed: {}", before.name, changes.join(", ")))
}

/// Describes what changed between two group configurations.
#[must_use]
pub fn groups(before: &Config, after: &Config) -> Vec<String> {
    let mut texts = Vec::new();
    for group in &after.groups {
        match before.groups.iter().find(|old| old.name == group.name) {
            None => texts.push(format!("Group {} added: VLAN {}", group.name, group.vlan)),
            Some(old) if old != group => texts.push(format!(
                "Group {} changed: VLAN {} → {}, label {} → {}",
                group.name,
                old.vlan,
                group.vlan,
                optional(&old.label),
                optional(&group.label)
            )),
            Some(_) => {}
        }
    }
    for old in &before.groups {
        if after.groups.iter().all(|group| group.name != old.name) {
            texts.push(format!("Group {} deleted", old.name));
        }
    }
    if before.default_group != after.default_group {
        texts.push(format!(
            "Default group {} → {}",
            optional(&before.default_group),
            optional(&after.default_group)
        ));
    }
    texts
}

fn table_name(table: &toml::Table) -> String {
    table
        .get("name")
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn value_text(value: Option<&toml::Value>) -> String {
    match value {
        None => "none".to_owned(),
        Some(toml::Value::String(text)) => optional(text).to_owned(),
        Some(other) => other.to_string(),
    }
}

/// Describes what changed between two plugin settings. Settings hold no secrets, only file names of them.
#[must_use]
pub fn plugins(before: &Settings, after: &Settings) -> Vec<String> {
    let mut texts = Vec::new();
    if before.scan != after.scan {
        texts.push(format!(
            "Background scan changed: every {} minutes, restore {}",
            after.scan.interval_minutes,
            if after.scan.restore { "on" } else { "off" }
        ));
    }
    // One entry gone and one new of the same type is a rename.
    let gone: Vec<&toml::Table> = before
        .plugins
        .iter()
        .filter(|old| {
            after
                .plugins
                .iter()
                .all(|table| table_name(table) != table_name(old))
        })
        .collect();
    let new: Vec<&toml::Table> = after
        .plugins
        .iter()
        .filter(|table| {
            before
                .plugins
                .iter()
                .all(|old| table_name(old) != table_name(table))
        })
        .collect();
    let renamed = match (gone.as_slice(), new.as_slice()) {
        ([old], [table]) if old.get("type") == table.get("type") => Some((*old, *table)),
        _ => None,
    };
    if let Some((old, table)) = renamed {
        texts.push(format!(
            "Plugin {} renamed to {}",
            table_name(old),
            table_name(table)
        ));
    }
    for table in &after.plugins {
        let name = table_name(table);
        let old = before.plugins.iter().find(|old| table_name(old) == name);
        let old = old.or(renamed
            .filter(|(_, new)| table_name(new) == name)
            .map(|(old, _)| old));
        let Some(old) = old else {
            texts.push(format!(
                "Plugin {name} added: type {}",
                value_text(table.get("type"))
            ));
            continue;
        };
        let mut keys: Vec<&String> = old.keys().chain(table.keys()).collect();
        keys.sort();
        keys.dedup();
        let changes: Vec<String> = keys
            .into_iter()
            .filter(|key| key.as_str() != "name" && old.get(*key) != table.get(*key))
            .map(|key| {
                format!(
                    "{key} {} → {}",
                    value_text(old.get(key)),
                    value_text(table.get(key))
                )
            })
            .collect();
        if !changes.is_empty() {
            texts.push(format!("Plugin {name} changed: {}", changes.join(", ")));
        }
    }
    if renamed.is_none() {
        for old in gone {
            texts.push(format!("Plugin {} deleted", table_name(old)));
        }
    }
    texts
}

#[cfg(test)]
mod tests;
