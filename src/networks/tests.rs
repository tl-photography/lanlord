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
    let result = plan(&wanted_plan(), &router(), Role::Router, &passwords());
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
    let first = plan(&wanted_plan(), &router(), Role::Router, &passwords());
    let after = applied(router(), &first.changes);
    assert_eq!(
        plan(&wanted_plan(), &after, Role::Router, &passwords()).changes,
        []
    );
}

#[test]
fn without_a_dns_service_the_router_answers() {
    let mut wanted = wanted_plan();
    wanted.dns_service.clear();
    let changes = plan(&wanted, &router(), Role::Router, &passwords()).changes;
    let dns = find(&changes, "lanlordnet_iot_dns");
    assert_eq!(dns.get("dest"), None, "to the router itself");
    assert_eq!(
        find(&changes, "lanlordnet_iot_dnsredirect").text("dest_ip"),
        "198.51.100.1"
    );
}

#[test]
fn an_access_point_only_bridges() {
    let changes = plan(&wanted_plan(), &router(), Role::AccessPoint, &passwords()).changes;
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
    let first = plan(&wanted_plan(), &router(), Role::Router, &passwords());
    let after = applied(router(), &first.changes);
    let mut fewer = wanted_plan();
    fewer.groups.truncate(1);
    let changes = plan(&fewer, &after, Role::Router, &passwords()).changes;
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
    let first = plan(&wanted_plan(), &router(), Role::Router, &passwords());
    let after = applied(router(), &first.changes);
    let mut moved = wanted_plan();
    moved.groups[1].subnet = "203.0.113.0/24".to_owned();
    let changes = plan(&moved, &after, Role::Router, &passwords()).changes;
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
    let result = plan(&wanted_plan(), &current, Role::Router, &passwords());
    assert_eq!(result.changes, []);
    assert!(result.notes[0].contains("outside lanlord"), "{:?}", result.notes);
}

#[test]
fn a_group_without_subnet_or_password_is_explained() {
    let mut wanted = wanted_plan();
    wanted.groups.push(group("guest", 30, "", ""));
    let result = plan(&wanted, &router(), Role::Router, &HashMap::new());
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
        plan(&wanted, &router(), Role::Router, &passwords()),
        NetworkPlan::default()
    );
}
