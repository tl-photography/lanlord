//! Unit tests of `connections`.

use super::*;
use crate::compare::{Observation, WifiClient};
use crate::devices::{Medium, Role};

fn device(name: &str, role: Role, uplink: &str) -> Device {
    Device {
        name: name.to_owned(),
        mac: format!("aa:bb:cc:00:00:{:02x}", name.len()),
        group: "lan".to_owned(),
        ip: None,
        self_assigned: false,
        role,
        unreviewed: false,
        uplink: uplink.to_owned(),
        port: String::new(),
        medium: Medium::Cable,
        note: String::new(),
        machine: String::new(),
    }
}

fn names(tokens: &[Token]) -> Vec<String> {
    tokens
        .iter()
        .map(|token| match token {
            Token::Open => "(".to_owned(),
            Token::Close => ")".to_owned(),
            Token::EndNode => ".".to_owned(),
            Token::Node(node) => node.name.clone(),
        })
        .collect()
}

#[test]
fn the_tree_starts_at_the_router() {
    let list = DeviceList {
        devices: vec![
            device("nas", Role::Server, "sw"),
            device("sw", Role::Switch, "gw"),
            device("gw", Role::Router, ""),
            device("lonely", Role::Client, ""),
        ],
    };
    let (tokens, loose) = build(&list, &Live::default(), 0);
    assert_eq!(
        names(&tokens),
        ["(", "gw", "(", "sw", "(", "nas", ".", ")", ".", ")", ".", ")"]
    );
    assert_eq!(loose, [3]);
}

#[test]
fn a_loop_stays_outside_the_tree() {
    let list = DeviceList {
        devices: vec![device("a", Role::Client, "bb"), device("bb", Role::Client, "a")],
    };
    let (tokens, loose) = build(&list, &Live::default(), 0);
    assert_eq!(tokens, []);
    assert_eq!(loose, [0, 1]);
}

#[test]
fn a_missing_uplink_leaves_the_device_outside() {
    let list = DeviceList {
        devices: vec![device("gw", Role::Router, ""), device("tv", Role::Client, "gone")],
    };
    assert_eq!(build(&list, &Live::default(), 0).1, [1]);
}

#[test]
fn the_wifi_of_the_last_scan_beats_the_list() {
    let phone = device("phone", Role::Client, "gw");
    let mac = phone.mac.clone();
    let list = DeviceList {
        devices: vec![
            device("gw", Role::Router, ""),
            device("ap1", Role::AccessPoint, "gw"),
            phone,
        ],
    };
    let mut live = Live::default();
    let wifi = Observation {
        wifi: vec![WifiClient {
            mac,
            access_point: "ap1: Home (5 GHz)".to_owned(),
            signal: None,
        }],
        ..Observation::default()
    };
    live.record(100, [wifi].iter(), true);
    let (tokens, _) = build(&list, &live, 100);
    assert_eq!(
        names(&tokens),
        ["(", "gw", "(", "ap1", "(", "phone", ".", ")", ".", ")", ".", ")"]
    );
    assert!(
        tokens
            .iter()
            .any(|token| matches!(token, Token::Node(node) if node.link == "Wi-Fi: Home (5 GHz)"))
    );
}

#[test]
fn the_link_says_how_and_where() {
    let mut nas = device("nas", Role::Server, "gw");
    nas.port = "lan2".to_owned();
    let mut far = device("farther", Role::Client, "gw");
    far.medium = Medium::Powerline;
    let list = DeviceList {
        devices: vec![device("gw", Role::Router, ""), nas, far],
    };
    let live = Live::default();
    assert_eq!(place(&list.devices[1], &list, &live).unwrap().1, "lan2");
    assert_eq!(place(&list.devices[2], &list, &live).unwrap().1, "Powerline");
}

fn wired_on(switch: &str) -> Live {
    let mut live = Live::default();
    let ports = Observation {
        ports: vec![crate::compare::PortEntry {
            mac: "aa:bb:cc:00:00:01".to_owned(),
            switch: switch.to_owned(),
            port: "lan1".to_owned(),
        }],
        ..Observation::default()
    };
    live.record(100, [ports].iter(), true);
    live
}

fn with_mac(mut entry: Device) -> Device {
    entry.mac = "aa:bb:cc:00:00:01".to_owned();
    entry
}

#[test]
fn a_detected_port_places_a_device() {
    let list = DeviceList {
        devices: vec![
            device("gw", Role::Router, ""),
            with_mac(device("hub", Role::Client, "")),
        ],
    };
    let place = place(&list.devices[1], &list, &wired_on("gw"));
    assert_eq!(place, Some(("gw".to_owned(), "lan1, detected".to_owned())));
}

#[test]
fn a_set_connection_beats_a_detected_port() {
    let list = DeviceList {
        devices: vec![
            device("gw", Role::Router, ""),
            device("sw", Role::Switch, "gw"),
            with_mac(device("hub", Role::Client, "sw")),
        ],
    };
    let place = place(&list.devices[2], &list, &wired_on("gw"));
    assert_eq!(place.map(|(uplink, _)| uplink), Some("sw".to_owned()));
}

#[test]
fn a_port_of_an_unknown_or_the_own_device_places_nothing() {
    let list = DeviceList {
        devices: vec![with_mac(device("hub", Role::Client, ""))],
    };
    assert_eq!(place(&list.devices[0], &list, &wired_on("other")), None);
    assert_eq!(place(&list.devices[0], &list, &wired_on("hub")), None);
}

#[test]
fn a_device_others_hang_on_starts_a_tree_without_a_role() {
    let list = DeviceList {
        devices: vec![
            device("gw", Role::Client, ""),
            with_mac(device("hub", Role::Client, "")),
        ],
    };
    let (tokens, loose) = build(&list, &wired_on("gw"), 100);
    assert_eq!(names(&tokens), ["(", "gw", "(", "hub", ".", ")", ".", ")"]);
    assert_eq!(loose, Vec::<usize>::new());
}
