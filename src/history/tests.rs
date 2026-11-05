//! Unit tests of `history`.

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
