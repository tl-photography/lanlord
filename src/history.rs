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
    for table in &after.plugins {
        let name = table_name(table);
        let Some(old) = before.plugins.iter().find(|old| table_name(old) == name) else {
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
            .filter(|key| old.get(*key) != table.get(*key))
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
    for old in &before.plugins {
        let name = table_name(old);
        if after.plugins.iter().all(|table| table_name(table) != name) {
            texts.push(format!("Plugin {name} deleted"));
        }
    }
    texts
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::net::Ipv4Addr;

    use super::*;
    use crate::config::Group;

    #[test]
    fn times_are_formatted_in_utc() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00");
        assert_eq!(format_time(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(format_time(1_793_913_025), "2026-11-05 21:10:25");
        assert_eq!(format_time(4_107_542_399), "2100-02-28 23:59:59");
    }

    #[test]
    fn entries_are_appended_and_read_newest_first() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.log");
        assert_eq!(read_newest(&path, 10), []);
        record(&path, &["first".to_owned()]);
        record(&path, &["second\nline".to_owned(), "third".to_owned()]);
        record(&path, &[]);
        let entries = read_newest(&path, 2);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "third");
        assert_eq!(entries[1].text, "second line", "one line per entry");
        let mode = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777, 0o600);
    }

    #[test]
    fn a_log_that_cannot_be_written_does_not_panic() {
        record(Path::new("/nonexistent/history.log"), &["lost".to_owned()]);
    }

    fn sample() -> Device {
        Device {
            name: "tv".to_owned(),
            mac: "00:00:00:00:00:01".to_owned(),
            group: "lan".to_owned(),
            ip: None,
            note: String::new(),
        }
    }

    #[test]
    fn device_changes_show_before_and_after() {
        let before = sample();
        assert_eq!(
            device(None, &before).unwrap(),
            "Device tv added: group lan, MAC 00:00:00:00:00:01, IP none"
        );
        let mut after = before.clone();
        after.group = "iot".to_owned();
        after.ip = Some(Ipv4Addr::new(192, 0, 2, 20));
        assert_eq!(
            device(Some(&before), &after).unwrap(),
            "Device tv changed: group lan → iot, IP none → 192.0.2.20"
        );
        assert_eq!(device(Some(&before), &before), None);
    }

    #[test]
    fn group_changes_are_listed() {
        let lan = Group {
            name: "lan".to_owned(),
            vlan: 1,
            label: String::new(),
        };
        let before = Config {
            default_group: "lan".to_owned(),
            groups: vec![lan.clone()],
        };
        let after = Config {
            default_group: "guest".to_owned(),
            groups: vec![
                Group {
                    label: "LAN".to_owned(),
                    ..lan
                },
                Group {
                    name: "guest".to_owned(),
                    vlan: 30,
                    label: String::new(),
                },
            ],
        };
        assert_eq!(
            groups(&before, &after),
            [
                "Group lan changed: VLAN 1 → 1, label none → LAN",
                "Group guest added: VLAN 30",
                "Default group lan → guest",
            ]
        );
        assert_eq!(groups(&after, &Config::default()).len(), 3);
    }

    #[test]
    fn plugin_changes_are_listed() {
        let parse = |text: &str| Settings {
            plugins: vec![toml::from_str(text).unwrap()],
        };
        let before = parse("name = \"router\"\ntype = \"openwrt\"\nenabled = true\nurl = \"https://a\"\n");
        let after = parse("name = \"router\"\ntype = \"openwrt\"\nenabled = false\nurl = \"https://b\"\n");
        assert_eq!(
            plugins(&before, &after),
            ["Plugin router changed: enabled true → false, url https://a → https://b"]
        );
        assert_eq!(
            plugins(&Settings::default(), &before),
            ["Plugin router added: type openwrt"]
        );
        assert_eq!(plugins(&before, &Settings::default()), ["Plugin router deleted"]);
    }
}
