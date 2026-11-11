use serde_json::json;

use super::*;
use crate::plan::Service;

fn group(name: &str, vlan: u16, subnet: &str, ssid: &str) -> Group {
    Group {
        name: name.to_owned(),
        vlan,
        subnet: subnet.to_owned(),
        label: String::new(),
        ssid: ssid.to_owned(),
        ssid_password_file: if ssid.is_empty() {
            String::new()
        } else {
            format!("{name}.wifi")
        },
        ssid_bands: Vec::new(),
        reachable_from: Vec::new(),
        reaches: Vec::new(),
    }
}

fn router() -> Vec<Section> {
    let answer = |values: Value| json!({ "values": values });
    let mut current = sections(
        "network",
        &answer(json!({
            "cfg030f15": { ".type": "device", ".index": 1, "name": "br-lan", "type": "bridge", "ports": ["lan1", "lan2", "wan2"] },
            "lan": { ".type": "interface", ".index": 2, "device": "br-lan", "proto": "static", "ipaddr": "192.0.2.1" }
        })),
    );
    current.extend(sections(
        "firewall",
        &answer(json!({
            "cfg01": { ".type": "zone", ".index": 1, "name": "lan", "network": ["lan"] },
            "cfg02": { ".type": "zone", ".index": 2, "name": "wan", "network": ["wan", "wan6"] }
        })),
    ));
    current.extend(sections(
        "wireless",
        &answer(json!({ "radio0": { ".type": "wifi-device", ".index": 0, "type": "mac80211" } })),
    ));
    current
}

fn wanted_plan() -> Plan {
    Plan {
        groups: vec![
            group("lan", 1, "192.0.2.0/24", ""),
            group("iot", 20, "198.51.100.0/24", "Things"),
        ],
        services: vec![Service {
            kind: "dns",
            address: Ipv4Addr::new(192, 0, 2, 53),
            source: "filter".to_owned(),
        }],
        dns_service: "filter".to_owned(),
        ..Plan::default()
    }
}

fn passwords() -> HashMap<String, String> {
    HashMap::from([("iot".to_owned(), "secret-key".to_owned())])
}

/// The device after the changes, as a read-back would show it.
fn applied(mut current: Vec<Section>, changes: &[Change]) -> Vec<Section> {
    for change in changes {
        match change {
            Change::Add(section, _) => current.push(section.clone()),
            Change::Set {
                config, id, options, ..
            } => {
                let section = current
                    .iter_mut()
                    .find(|section| section.config == *config && section.id == *id)
                    .unwrap();
                section.options.extend(options.clone());
            }
            Change::Delete { config, id, .. } => {
                current.retain(|section| !(section.config == *config && section.id == *id));
            }
        }
    }
    current
}

fn find<'a>(changes: &'a [Change], id: &str) -> &'a Section {
    changes
        .iter()
        .find_map(|change| match change {
            Change::Add(section, _) if section.id == id => Some(section),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no new section {id}: {changes:#?}"))
}

#[test]
fn the_first_network_turns_the_bridge_into_vlans() {
    let result = plan(
        &wanted_plan(),
        &router(),
        Role::Router,
        &passwords(),
        &BTreeMap::new(),
    );
    assert_eq!(result.notes, Vec::<String>::new());
    let changes = &result.changes;
    assert_eq!(
        find(changes, "lanlordnet_vlan1").get("ports"),
        Some(&Opt::list(&["lan1:u*", "lan2:u*", "wan2:u*"]))
    );
    assert!(changes.contains(&Change::Set {
        config: "network".to_owned(),
        id: "lan".to_owned(),
        options: BTreeMap::from([("device".to_owned(), Opt::one("br-lan.1"))]),
        why: "LAN moves to br-lan.1".to_owned(),
    }));
    assert_eq!(
        find(changes, "lanlordnet_iot_vlan").get("ports"),
        Some(&Opt::list(&["lan1:t", "lan2:t", "wan2:t"]))
    );
    let interface = find(changes, "lanlordnet_iot");
    assert_eq!(interface.text("device"), "br-lan.20");
    assert_eq!(interface.text("ipaddr"), "198.51.100.1");
    assert_eq!(interface.text("netmask"), "255.255.255.0");
    let pool = changes
        .iter()
        .find_map(|change| match change {
            Change::Add(section, _) if section.config == "dhcp" => Some(section),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        pool.get("dhcp_option"),
        Some(&Opt::List(vec!["6,192.0.2.53".to_owned()]))
    );
    assert_eq!(pool.get("dhcpv6"), None, "IPv4 only");
    let dns = find(changes, "lanlordnet_iot_dns");
    assert_eq!(dns.text("dest"), "lan");
    assert_eq!(dns.text("dest_ip"), "192.0.2.53");
    assert_eq!(
        find(changes, "lanlordnet_iot_dnsredirect").text("dest_ip"),
        "192.0.2.53"
    );
    assert_eq!(find(changes, "lanlordnet_iot_wan").text("dest"), "wan");
    let wifi = find(changes, "lanlordnet_iot_radio0");
    assert_eq!(wifi.text("ssid"), "Things");
    assert_eq!(wifi.text("network"), "lanlordnet_iot");
    let shown: Vec<String> = result.steps().into_iter().flat_map(|step| step.details).collect();
    assert!(
        shown.contains(&"uci set wireless.lanlordnet_iot_radio0.key='***'".to_owned()),
        "{shown:?}"
    );
    assert!(
        !shown.iter().any(|line| line.contains("secret-key")),
        "the key is not shown"
    );
    let order: Vec<&str> = changes
        .iter()
        .map(|change| match change {
            Change::Add(section, _) => section.config.as_str(),
            Change::Set { config, .. } | Change::Delete { config, .. } => config.as_str(),
        })
        .collect();
    let mut sorted = order.clone();
    sorted.sort_by_key(|config| CONFIGS.iter().position(|known| known == config));
    assert_eq!(order, sorted, "network first, then dhcp, firewall and wireless");
}

#[test]
fn nothing_is_left_after_applying() {
    let first = plan(
        &wanted_plan(),
        &router(),
        Role::Router,
        &passwords(),
        &BTreeMap::new(),
    );
    let after = applied(router(), &first.changes);
    assert_eq!(
        plan(
            &wanted_plan(),
            &after,
            Role::Router,
            &passwords(),
            &BTreeMap::new()
        )
        .changes,
        []
    );
}

#[test]
fn without_a_dns_service_the_router_answers() {
    let mut wanted = wanted_plan();
    wanted.dns_service.clear();
    let changes = plan(&wanted, &router(), Role::Router, &passwords(), &BTreeMap::new()).changes;
    let dns = find(&changes, "lanlordnet_iot_dns");
    assert_eq!(dns.get("dest"), None, "to the router itself");
    assert_eq!(
        find(&changes, "lanlordnet_iot_dnsredirect").text("dest_ip"),
        "198.51.100.1"
    );
}

#[test]
fn an_access_point_only_bridges() {
    let changes = plan(
        &wanted_plan(),
        &router(),
        Role::AccessPoint,
        &passwords(),
        &BTreeMap::new(),
    )
    .changes;
    assert!(changes.iter().all(|change| match change {
        Change::Add(section, _) => section.config == "network" || section.config == "wireless",
        _ => true,
    }));
    let interface = find(&changes, "lanlordnet_iot");
    assert_eq!(interface.text("proto"), "none");
    assert_eq!(interface.get("ipaddr"), None);
}

#[test]
fn a_removed_group_takes_its_sections_and_the_lan_stays() {
    let first = plan(
        &wanted_plan(),
        &router(),
        Role::Router,
        &passwords(),
        &BTreeMap::new(),
    );
    let after = applied(router(), &first.changes);
    let mut fewer = wanted_plan();
    fewer.groups.truncate(1);
    let changes = plan(&fewer, &after, Role::Router, &passwords(), &BTreeMap::new()).changes;
    assert_ne!(changes, []);
    assert!(
        changes
            .iter()
            .all(|change| matches!(change, Change::Delete { id, .. } if id.starts_with("lanlordnet_iot"))),
        "{changes:#?}"
    );
}

#[test]
fn a_changed_subnet_changes_only_what_differs() {
    let first = plan(
        &wanted_plan(),
        &router(),
        Role::Router,
        &passwords(),
        &BTreeMap::new(),
    );
    let after = applied(router(), &first.changes);
    let mut moved = wanted_plan();
    moved.groups[1].subnet = "203.0.113.0/24".to_owned();
    let changes = plan(&moved, &after, Role::Router, &passwords(), &BTreeMap::new()).changes;
    assert_eq!(
        changes.len(),
        1,
        "only the interface, DNS stays at the service: {changes:#?}"
    );
    assert!(changes.iter().all(|change| matches!(change, Change::Set { .. })));
}

#[test]
fn vlans_set_up_outside_lanlord_are_left_alone() {
    let mut current = router();
    current.push(Section::new(
        "network",
        "cfg99".to_owned(),
        "bridge-vlan",
        &[("vlan", Opt::one("1"))],
    ));
    let result = plan(
        &wanted_plan(),
        &current,
        Role::Router,
        &passwords(),
        &BTreeMap::new(),
    );
    assert_eq!(result.changes, []);
    assert!(result.notes[0].contains("outside lanlord"), "{:?}", result.notes);
}

#[test]
fn a_group_without_subnet_or_password_is_explained() {
    let mut wanted = wanted_plan();
    wanted.groups.push(group("guest", 30, "", ""));
    let result = plan(
        &wanted,
        &router(),
        Role::Router,
        &HashMap::new(),
        &BTreeMap::new(),
    );
    assert!(
        result
            .notes
            .iter()
            .any(|note| note.contains("guest needs a subnet")),
        "{:?}",
        result.notes
    );
    assert!(
        result
            .notes
            .iter()
            .any(|note| note.contains("iot.wifi cannot be read")),
        "{:?}",
        result.notes
    );
}

#[test]
fn only_lan_groups_change_nothing() {
    let mut wanted = wanted_plan();
    wanted.groups.truncate(1);
    assert_eq!(
        plan(&wanted, &router(), Role::Router, &passwords(), &BTreeMap::new()),
        NetworkPlan::default()
    );
}

#[test]
fn a_port_with_one_device_carries_its_vlan_untagged() {
    let mut wanted = wanted_plan();
    let interface = |name: &str, mac: &str, group: &str| crate::devices::Interface {
        name: name.to_owned(),
        mac: mac.to_owned(),
        group: group.to_owned(),
        ..Default::default()
    };
    wanted.devices.interfaces = vec![
        interface("bridge", "aa:bb:cc:00:00:01", "iot"),
        interface("nas", "aa:bb:cc:00:00:02", "lan"),
        interface("tv", "aa:bb:cc:00:00:03", "iot"),
    ];
    let ports = BTreeMap::from([
        (
            "lan1".to_owned(),
            BTreeSet::from(["aa:bb:cc:00:00:01".to_owned()]),
        ),
        (
            "lan2".to_owned(),
            BTreeSet::from(["aa:bb:cc:00:00:02".to_owned(), "aa:bb:cc:00:00:03".to_owned()]),
        ),
        (
            "wan2".to_owned(),
            BTreeSet::from(["aa:bb:cc:00:00:99".to_owned()]),
        ),
    ]);
    let changes = plan(&wanted, &router(), Role::Router, &passwords(), &ports).changes;
    assert_eq!(
        find(&changes, "lanlordnet_vlan1").get("ports"),
        Some(&Opt::list(&["lan2:u*", "wan2:u*"])),
        "lan1 leaves the LAN, an unknown device stays"
    );
    assert_eq!(
        find(&changes, "lanlordnet_iot_vlan").get("ports"),
        Some(&Opt::list(&["lan1:u*", "lan2:t", "wan2:t"])),
        "a shared port carries the VLAN tagged"
    );
}

#[test]
fn a_port_never_moves_into_a_network_that_is_not_built() {
    let mut wanted = wanted_plan();
    wanted.groups[1].subnet.clear();
    wanted.devices.interfaces = vec![crate::devices::Interface {
        name: "bridge".to_owned(),
        mac: "aa:bb:cc:00:00:01".to_owned(),
        group: "iot".to_owned(),
        ..Default::default()
    }];
    let ports = BTreeMap::from([(
        "lan1".to_owned(),
        BTreeSet::from(["aa:bb:cc:00:00:01".to_owned()]),
    )]);
    let result = plan(&wanted, &router(), Role::Router, &passwords(), &ports);
    assert_eq!(result.changes, [], "no network, no change: {:?}", result.changes);
}

#[test]
fn the_lan_reaches_a_network_it_is_allowed_into() {
    let mut wanted = wanted_plan();
    wanted.groups[1].reachable_from = vec!["lan".to_owned()];
    wanted.groups.push(group("guest", 30, "203.0.113.0/24", ""));
    wanted.groups[2].reachable_from = vec!["iot".to_owned()];
    let result = plan(&wanted, &router(), Role::Router, &passwords(), &BTreeMap::new());
    let into_iot = find(&result.changes, "lanlordnet_iot_from_lan");
    assert_eq!(into_iot.get("src"), Some(&Opt::one("lan")));
    assert_eq!(into_iot.get("dest"), Some(&Opt::one("iot")));
    let into_guest = find(&result.changes, "lanlordnet_guest_from_iot");
    assert_eq!(into_guest.get("src"), Some(&Opt::one("iot")));
    assert!(
        result
            .steps()
            .iter()
            .any(|step| step.description == "lan may reach iot: new")
    );
    let after = applied(router(), &result.changes);
    wanted.groups[1].reachable_from.clear();
    let again = plan(&wanted, &after, Role::Router, &passwords(), &BTreeMap::new());
    assert!(again.changes.iter().any(|change| matches!(
        change,
        Change::Delete { id, .. } if id == "lanlordnet_iot_from_lan"
    )));
}

#[test]
fn a_group_that_is_no_network_reaches_nothing() {
    let mut wanted = wanted_plan();
    wanted.groups.push(group("guest", 30, "", ""));
    wanted.groups[1].reachable_from = vec!["guest".to_owned()];
    let result = plan(&wanted, &router(), Role::Router, &passwords(), &BTreeMap::new());
    assert!(
        result
            .notes
            .contains(&"iot: guest is not a network yet and cannot reach it".to_owned())
    );
    assert!(!result.changes.iter().any(|change| matches!(
        change,
        Change::Add(section, _) if section.id.contains("_from_")
    )));
}

#[test]
fn an_access_point_gets_no_forwardings() {
    let mut wanted = wanted_plan();
    wanted.groups[1].reachable_from = vec!["lan".to_owned()];
    let result = plan(
        &wanted,
        &router(),
        Role::AccessPoint,
        &passwords(),
        &BTreeMap::new(),
    );
    assert!(!result.changes.iter().any(|change| matches!(
        change,
        Change::Add(section, _) if section.config == "firewall"
    )));
}

#[test]
fn a_network_reaches_single_ports_of_a_server() {
    let mut wanted = wanted_plan();
    wanted.groups[1].reaches = vec![
        "Server:1883/tcp".to_owned(),
        "Server:5683/udp".to_owned(),
        "gone:80/tcp".to_owned(),
    ];
    wanted.devices.interfaces = vec![crate::devices::Interface {
        name: "Server".to_owned(),
        mac: "aa:bb:cc:00:00:02".to_owned(),
        group: "lan".to_owned(),
        ip: Some(Ipv4Addr::new(192, 0, 2, 10)),
        ..Default::default()
    }];
    let result = plan(&wanted, &router(), Role::Router, &passwords(), &BTreeMap::new());
    let mqtt = find(&result.changes, "lanlordnet_iot_to_server_1883_tcp");
    assert_eq!(mqtt.get("src"), Some(&Opt::one("iot")));
    assert_eq!(mqtt.get("dest"), Some(&Opt::one("lan")));
    assert_eq!(mqtt.get("dest_ip"), Some(&Opt::one("192.0.2.10")));
    assert_eq!(mqtt.get("dest_port"), Some(&Opt::one("1883")));
    assert_eq!(mqtt.get("proto"), Some(&Opt::one("tcp")));
    assert_eq!(
        find(&result.changes, "lanlordnet_iot_to_server_5683_udp").get("proto"),
        Some(&Opt::one("udp"))
    );
    assert!(
        result
            .notes
            .contains(&"iot: gone has no fixed address, 80/tcp is left out".to_owned())
    );
    assert!(
        result
            .steps()
            .iter()
            .any(|step| step.description == "firewall iot to Server 1883/tcp: new")
    );
}

#[test]
fn a_reached_port_must_look_like_a_port() {
    assert_eq!(
        crate::config::parse_reach("Server:1883/tcp").map(|reach| reach.port),
        Some(1883)
    );
    for bad in [
        "Server:0/tcp",
        "Server:1883",
        "Server:1883/icmp",
        ":1883/tcp",
        "Server:99999/udp",
    ] {
        assert!(crate::config::parse_reach(bad).is_none(), "{bad}");
    }
}

#[test]
fn a_group_can_choose_its_radios() {
    let mut current = router();
    current.extend(sections(
        "wireless",
        &json!({ "values": {
            "radio1": { ".type": "wifi-device", ".index": 1, "band": "2g" }
        } }),
    ));
    let mut wanted = wanted_plan();
    wanted.groups[1].ssid_bands = vec!["2g".to_owned()];
    let result = plan(&wanted, &current, Role::Router, &passwords(), &BTreeMap::new());
    assert_eq!(
        find(&result.changes, "lanlordnet_iot_radio1").get("device"),
        Some(&Opt::one("radio1"))
    );
    assert!(!result.changes.iter().any(|change| matches!(
        change,
        Change::Add(section, _) if section.id == "lanlordnet_iot_radio0"
    )));

    let after = applied(
        current.clone(),
        &plan(
            &wanted_plan(),
            &current,
            Role::Router,
            &passwords(),
            &BTreeMap::new(),
        )
        .changes,
    );
    let narrowed = plan(&wanted, &after, Role::Router, &passwords(), &BTreeMap::new());
    assert!(narrowed.changes.iter().any(|change| matches!(
        change,
        Change::Delete { id, .. } if id == "lanlordnet_iot_radio0"
    )));
}

#[test]
fn a_device_without_a_chosen_band_is_explained() {
    let mut wanted = wanted_plan();
    wanted.groups[1].ssid_bands = vec!["2g".to_owned()];
    let result = plan(&wanted, &router(), Role::Router, &passwords(), &BTreeMap::new());
    assert!(
        result.notes.contains(&"iot: no radio for its Wi-Fi".to_owned()),
        "{:?}",
        result.notes
    );
}
