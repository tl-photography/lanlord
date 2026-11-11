use super::*;
use crate::plan::Service;

fn group(name: &str, vlan: u16, subnet: &str) -> Group {
    Group {
        name: name.to_owned(),
        vlan,
        subnet: subnet.to_owned(),
        label: String::new(),
        ssid: String::new(),
        ssid_password_file: String::new(),
        ssid_bands: Vec::new(),
        reachable_from: Vec::new(),
        reaches: Vec::new(),
    }
}

fn interface(name: &str, mac: &str, group: &str, ip: Option<Ipv4Addr>) -> Interface {
    Interface {
        name: name.to_owned(),
        mac: mac.to_owned(),
        group: group.to_owned(),
        ip,
        self_assigned: false,
        unreviewed: false,
        note: String::new(),
        device: String::new(),
    }
}

fn plan() -> Plan {
    let mut plan = Plan {
        groups: vec![
            group("lan", LAN_VLAN, "192.0.2.0/24"),
            group("iot", 20, "198.51.100.0/24"),
            group("guest", 30, ""),
        ],
        ..Plan::default()
    };
    plan.devices.interfaces = vec![
        interface(
            "Server",
            "aa:bb:cc:00:00:01",
            "lan",
            Some(Ipv4Addr::new(192, 0, 2, 10)),
        ),
        interface("Plug", "aa:bb:cc:00:00:02", "iot", None),
        interface(
            "Lamp",
            "aa:bb:cc:00:00:03",
            "iot",
            Some(Ipv4Addr::new(198, 51, 100, 7)),
        ),
        interface(
            "Stray",
            "aa:bb:cc:00:00:04",
            "gone",
            Some(Ipv4Addr::new(203, 0, 113, 9)),
        ),
    ];
    plan
}

#[test]
fn netmasks_follow_the_prefix() {
    for (prefix, mask) in [
        (0, Ipv4Addr::new(0, 0, 0, 0)),
        (8, Ipv4Addr::new(255, 0, 0, 0)),
        (24, Ipv4Addr::new(255, 255, 255, 0)),
        (30, Ipv4Addr::new(255, 255, 255, 252)),
        (32, Ipv4Addr::new(255, 255, 255, 255)),
        (40, Ipv4Addr::new(255, 255, 255, 255)),
    ] {
        assert_eq!(netmask(prefix), mask, "/{prefix}");
    }
}

#[test]
fn the_gateway_is_the_first_host() {
    for (subnet, expected) in [
        ("192.0.2.0/24", Some((Ipv4Addr::new(192, 0, 2, 1), 24))),
        ("192.0.2.77/24", Some((Ipv4Addr::new(192, 0, 2, 1), 24))),
        ("198.51.100.8/30", Some((Ipv4Addr::new(198, 51, 100, 9), 30))),
        ("198.51.100.8/31", None),
        ("", None),
    ] {
        assert_eq!(gateway(&group("any", 20, subnet)), expected, "{subnet:?}");
    }
}

#[test]
fn every_group_but_the_lan_is_a_candidate() {
    let plan = plan();
    let names: Vec<&str> = candidates(&plan)
        .iter()
        .map(|group| group.name.as_str())
        .collect();
    assert_eq!(names, ["iot", "guest"]);
}

#[test]
fn wifi_needs_an_ssid_and_a_password() {
    let mut with_ssid = group("iot", 20, "198.51.100.0/24");
    "Things".clone_into(&mut with_ssid.ssid);
    "iot.wifi".clone_into(&mut with_ssid.ssid_password_file);
    let passwords = HashMap::from([("iot".to_owned(), "secret-key".to_owned())]);
    let none = HashMap::new();
    for (group, passwords, wifi_expected, note) in [
        (group("lan", 1, ""), &passwords, false, None),
        (with_ssid.clone(), &passwords, true, None),
        (
            with_ssid.clone(),
            &none,
            false,
            Some("iot: the password file iot.wifi cannot be read, its Wi-Fi is left out"),
        ),
    ] {
        let mut notes = Vec::new();
        let found = wifi(&group, passwords, &mut notes);
        assert_eq!(found.is_some(), wifi_expected, "{}", group.name);
        assert_eq!(notes, note.into_iter().map(str::to_owned).collect::<Vec<_>>());
    }
    let mut notes = Vec::new();
    let found = wifi(&with_ssid, &passwords, &mut notes);
    assert_eq!(
        found.map(|wifi| (wifi.ssid, wifi.key)),
        Some(("Things", "secret-key"))
    );
}

#[test]
fn wifi_runs_on_its_bands() {
    let both: [String; 0] = [];
    let only_2g = ["2g".to_owned()];
    for (bands, band, on) in [
        (&both[..], "2g", true),
        (&both[..], "5g", true),
        (&only_2g[..], "2g", true),
        (&only_2g[..], "5g", false),
    ] {
        let wifi = Wifi {
            ssid: "Things",
            key: "secret-key",
            bands,
        };
        assert_eq!(wifi.on(band), on, "{bands:?} on {band}");
    }
}

#[test]
fn sources_are_the_groups_that_exist() {
    let mut plan = plan();
    plan.groups[1].reachable_from = vec!["lan".to_owned(), "gone".to_owned(), "guest".to_owned()];
    let names: Vec<&str> = sources(&plan, &plan.groups[1])
        .iter()
        .map(|group| group.name.as_str())
        .collect();
    assert_eq!(names, ["lan", "guest"]);
}

#[test]
fn ports_need_a_fixed_address() {
    let mut plan = plan();
    plan.groups[1].reaches = vec![
        "server:1883/tcp".to_owned(),
        "Plug:80/tcp".to_owned(),
        "Stray:53/udp".to_owned(),
        "nobody:22/tcp".to_owned(),
    ];
    let mut notes = Vec::new();
    let found = ports(&plan, &plan.groups[1], &mut notes);
    let summary: Vec<(&str, Ipv4Addr, Option<&str>, u16, &str)> = found
        .iter()
        .map(|port| {
            (
                port.interface.name.as_str(),
                port.ip,
                port.group.map(|group| group.name.as_str()),
                port.port,
                port.proto.as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("Server", Ipv4Addr::new(192, 0, 2, 10), Some("lan"), 1883, "tcp"),
            ("Stray", Ipv4Addr::new(203, 0, 113, 9), None, 53, "udp"),
        ]
    );
    assert_eq!(
        notes,
        [
            "iot: Plug has no fixed address, 80/tcp is left out",
            "iot: nobody has no fixed address, 22/tcp is left out",
        ]
    );
}

#[test]
fn ports_reach_every_interface_of_a_device() {
    let mut plan = plan();
    for interface in &mut plan.devices.interfaces[..2] {
        "nas".clone_into(&mut interface.device);
    }
    plan.devices.interfaces[1].ip = Some(Ipv4Addr::new(198, 51, 100, 20));
    plan.groups[2].reaches = vec!["NAS:445/tcp".to_owned()];
    let mut notes = Vec::new();
    let names: Vec<&str> = ports(&plan, &plan.groups[2], &mut notes)
        .iter()
        .map(|port| port.interface.name.as_str())
        .collect();
    assert_eq!(names, ["Server", "Plug"]);
    assert!(notes.is_empty(), "{notes:?}");
}

#[test]
fn the_dns_service_is_found_in_its_network() {
    for (address, group_name) in [
        (Ipv4Addr::new(192, 0, 2, 53), Some("lan")),
        (Ipv4Addr::new(198, 51, 100, 53), Some("iot")),
        (Ipv4Addr::new(203, 0, 113, 53), None),
    ] {
        let mut plan = plan();
        plan.services = vec![Service {
            kind: "dns",
            address,
            source: "filter".to_owned(),
        }];
        "filter".clone_into(&mut plan.dns_service);
        let found = dns_service(&plan);
        assert_eq!(
            found.map(|(address, group)| (address, group.map(|group| group.name.as_str()))),
            Some((address, group_name)),
            "{address}"
        );
    }
    assert_eq!(dns_service(&plan()), None, "no service chosen is the router");
}

#[test]
fn a_port_with_one_known_device_carries_its_vlan() {
    let plan = plan();
    let bridge_ports: Vec<String> = ["lan1", "lan2", "lan3", "lan4", "lan5"]
        .iter()
        .map(|port| (*port).to_owned())
        .collect();
    let seen = BTreeMap::from([
        (
            "lan1".to_owned(),
            BTreeSet::from(["aa:bb:cc:00:00:03".to_owned()]),
        ),
        (
            "lan2".to_owned(),
            BTreeSet::from(["aa:bb:cc:00:00:01".to_owned(), "aa:bb:cc:00:00:03".to_owned()]),
        ),
        (
            "lan3".to_owned(),
            BTreeSet::from(["aa:bb:cc:00:00:99".to_owned()]),
        ),
        (
            "lan4".to_owned(),
            BTreeSet::from(["aa:bb:cc:00:00:04".to_owned()]),
        ),
        ("wan".to_owned(), BTreeSet::from(["aa:bb:cc:00:00:02".to_owned()])),
    ]);
    for (built, expected) in [(&[20][..], vec![("lan1", 20)]), (&[][..], vec![])] {
        let access = access_ports(&plan, &bridge_ports, &seen, built);
        let access: Vec<(&str, u16)> = access.iter().map(|(port, vlan)| (port.as_str(), *vlan)).collect();
        assert_eq!(access, expected, "built {built:?}");
    }
}
