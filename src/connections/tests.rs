//! Unit tests of `connections`.

use super::*;
use crate::compare::{Observation, WifiClient};

fn device(name: &str, uplink: &str) -> Device {
    Device {
        name: name.to_owned(),
        mac: format!("aa:bb:cc:00:00:{:02x}", name.len()),
        group: "lan".to_owned(),
        ip: None,
        self_assigned: false,
        unreviewed: false,
        uplink: uplink.to_owned(),
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
fn the_tree_starts_at_the_device_others_hang_on() {
    let list = DeviceList {
        devices: vec![
            device("nas", "sw"),
            device("sw", "gw"),
            device("gw", ""),
            device("lonely", ""),
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
        devices: vec![device("a", "bb"), device("bb", "a")],
    };
    let (tokens, loose) = build(&list, &Live::default(), 0);
    assert_eq!(tokens, []);
    assert_eq!(loose, [0, 1]);
}

#[test]
fn a_missing_uplink_leaves_the_device_outside() {
    let list = DeviceList {
        devices: vec![device("gw", ""), device("tv", "gone")],
    };
    assert_eq!(build(&list, &Live::default(), 0).1, [0, 1]);
}

#[test]
fn the_wifi_of_the_last_scan_beats_the_list() {
    let phone = device("phone", "gw");
    let mac = phone.mac.clone();
    let list = DeviceList {
        devices: vec![device("gw", ""), device("ap1", "gw"), phone],
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
fn a_device_others_hang_on_starts_a_tree() {
    let list = DeviceList {
        devices: vec![device("gw", ""), device("hub", "gw")],
    };
    let (tokens, loose) = build(&list, &Live::default(), 0);
    assert_eq!(names(&tokens), ["(", "gw", "(", "hub", ".", ")", ".", ")"]);
    assert_eq!(loose, Vec::<usize>::new());
}
