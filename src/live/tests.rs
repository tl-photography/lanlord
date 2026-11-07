//! Unit tests of `live`.

use super::*;
use crate::compare::WifiClient;

const MAC: &str = "aa:bb:cc:00:00:01";

fn device(ip: [u8; 4]) -> Device {
    Device {
        name: "tv".to_owned(),
        mac: MAC.to_owned(),
        group: "iot".to_owned(),
        ip: Some(ip.into()),
        self_assigned: false,
        note: String::new(),
        machine: String::new(),
    }
}

fn lease(ip: [u8; 4]) -> Observation {
    Observation {
        seen: vec![Seen {
            mac: MAC.to_uppercase(),
            ip: Some(ip.into()),
            hostname: String::new(),
        }],
        ..Observation::default()
    }
}

#[test]
fn nothing_is_known_before_the_first_scan() {
    assert_eq!(
        Live::default().status(&device([192, 0, 2, 5]), 100),
        Status::default()
    );
}

#[test]
fn a_device_on_another_address_shows_it() {
    let mut live = Live::default();
    live.record(100, [lease([192, 0, 2, 5])].iter(), true);

    let status = live.status(&device([198, 51, 100, 5]), 100);
    assert_eq!(status.state, "seen");
    assert_eq!(status.actual_ip, "192.0.2.5");

    assert_eq!(live.status(&device([192, 0, 2, 5]), 100).actual_ip, "");
}

#[test]
fn a_device_gone_from_a_complete_scan_is_away() {
    let mut live = Live::default();
    live.record(100, [lease([192, 0, 2, 5])].iter(), true);
    live.record(7_300, [].iter(), true);

    let status = live.status(&device([192, 0, 2, 5]), 7_300);
    assert_eq!(status.state, "away");
    assert_eq!(status.away, "Not seen for 2 h");
}

#[test]
fn a_failed_plugin_makes_nobody_away() {
    let mut live = Live::default();
    live.record(100, [lease([192, 0, 2, 5])].iter(), true);
    live.record(200, [].iter(), false);
    assert_eq!(live.status(&device([192, 0, 2, 5]), 200).state, "seen");
}

#[test]
fn the_access_point_is_named_while_connected() {
    let mut live = Live::default();
    let wifi = Observation {
        wifi: vec![WifiClient {
            mac: MAC.to_owned(),
            access_point: "router: Home".to_owned(),
            signal: None,
        }],
        ..Observation::default()
    };
    live.record(100, [wifi].iter(), true);
    assert_eq!(
        live.status(&device([192, 0, 2, 5]), 100).detail,
        "Seen in the last scan, on router: Home"
    );

    live.record(200, [lease([192, 0, 2, 5])].iter(), true);
    assert_eq!(
        live.status(&device([192, 0, 2, 5]), 200).detail,
        "Seen in the last scan"
    );
}

#[test]
fn a_device_never_seen_is_away_unless_it_sets_its_address_itself() {
    let mut live = Live::default();
    live.record(100, [].iter(), true);
    assert_eq!(live.status(&device([192, 0, 2, 5]), 100).away, "Not seen yet");

    let mut router = device([192, 0, 2, 1]);
    router.self_assigned = true;
    assert_eq!(live.status(&router, 100), Status::default());
}

#[test]
fn a_neighbour_without_a_lease_is_seen() {
    let mut live = Live::default();
    let neighbour = Observation {
        neighbours: Some(lease([192, 0, 2, 5]).seen),
        ..Observation::default()
    };
    live.record(100, [neighbour].iter(), true);
    assert_eq!(live.status(&device([192, 0, 2, 5]), 100).state, "seen");
}

#[test]
fn a_lease_alone_is_not_seen_when_the_plugin_reads_neighbours() {
    let mut live = Live::default();
    let lease_only = Observation {
        neighbours: Some(Vec::new()),
        ..lease([192, 0, 2, 5])
    };
    live.record(100, [lease_only].iter(), true);

    let status = live.status(&device([198, 51, 100, 5]), 100);
    assert_eq!(status.state, "away");
    assert_eq!(status.away, "Not seen yet");
    assert_eq!(status.actual_ip, "192.0.2.5");
}

#[test]
fn times_are_short() {
    assert_eq!(ago(10), "1 min");
    assert_eq!(ago(3_599), "59 min");
    assert_eq!(ago(3_600), "1 h");
    assert_eq!(ago(200_000), "2 days");
}
