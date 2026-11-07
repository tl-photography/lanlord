//! Unit tests of `compare`.

use super::*;
use crate::devices::Device;

fn groups() -> Vec<Group> {
    vec![
        Group {
            name: "lan".to_owned(),
            vlan: 1,
            label: String::new(),
        },
        Group {
            name: "iot".to_owned(),
            vlan: 20,
            label: String::new(),
        },
    ]
}

fn list() -> DeviceList {
    DeviceList {
        devices: vec![
            Device {
                name: "omv".to_owned(),
                mac: "00:00:00:00:00:01".to_owned(),
                group: "lan".to_owned(),
                ip: Some(Ipv4Addr::new(192, 0, 2, 2)),
                note: String::new(),
                machine: String::new(),
            },
            Device {
                name: "plug".to_owned(),
                mac: "00:00:00:00:00:02".to_owned(),
                group: "iot".to_owned(),
                ip: None,
                note: String::new(),
                machine: String::new(),
            },
        ],
    }
}

fn entry(mac: &str, name: &str, ip: Option<Ipv4Addr>, vlan: Option<u16>) -> Entry {
    Entry {
        mac: mac.to_owned(),
        name: name.to_owned(),
        ip,
        vlan,
    }
}

#[test]
fn matching_entries_give_no_findings() {
    let observation = Observation {
        seen: vec![Seen {
            mac: "00:00:00:00:00:01".to_owned(),
            ip: Some(Ipv4Addr::new(192, 0, 2, 2)),
            hostname: "omv".to_owned(),
        }],
        entries: Some(vec![
            entry(
                "00:00:00:00:00:01",
                "OMV",
                Some(Ipv4Addr::new(192, 0, 2, 2)),
                Some(1),
            ),
            entry("00:00:00:00:00:02", "plug", None, Some(20)),
        ]),
        ..Observation::default()
    };
    assert_eq!(compare(&list(), &groups(), &observation), []);
}

#[test]
fn unknown_devices_are_reported_once() {
    let stranger = Seen {
        mac: "00:00:00:00:00:99".to_owned(),
        ip: Some(Ipv4Addr::new(192, 0, 2, 99)),
        hostname: "phone".to_owned(),
    };
    let observation = Observation {
        seen: vec![stranger.clone(), stranger],
        entries: None,
        ..Observation::default()
    };
    assert_eq!(
        compare(&list(), &groups(), &observation),
        [Finding::Unknown {
            mac: "00:00:00:00:00:99".to_owned(),
            ip: Some(Ipv4Addr::new(192, 0, 2, 99)),
            hostname: "phone".to_owned(),
        }]
    );
}

#[test]
fn plugins_that_only_report_have_no_missing_entries() {
    let observation = Observation::default();
    assert_eq!(compare(&list(), &groups(), &observation), []);
}

#[test]
fn differences_per_device_and_foreign_entries_are_found() {
    let observation = Observation {
        seen: vec![],
        entries: Some(vec![
            entry(
                "00:00:00:00:00:01",
                "server",
                Some(Ipv4Addr::new(192, 0, 2, 3)),
                Some(20),
            ),
            entry("00:00:00:00:00:77", "old-tv", None, None),
        ]),
        ..Observation::default()
    };
    assert_eq!(
        compare(&list(), &groups(), &observation),
        [
            Finding::WrongName {
                device: "omv".to_owned(),
                actual: "server".to_owned(),
            },
            Finding::WrongIp {
                device: "omv".to_owned(),
                expected: Some(Ipv4Addr::new(192, 0, 2, 2)),
                actual: Some(Ipv4Addr::new(192, 0, 2, 3)),
            },
            Finding::WrongVlan {
                device: "omv".to_owned(),
                expected: 1,
                actual: 20,
            },
            Finding::Missing {
                device: "plug".to_owned(),
            },
            Finding::Foreign {
                mac: "00:00:00:00:00:77".to_owned(),
                name: "old-tv".to_owned(),
            },
        ]
    );
}
