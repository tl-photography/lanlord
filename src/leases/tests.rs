//! Unit tests of `leases`.

use super::*;
use crate::devices::Interface;

fn device(name: &str, mac: &str, ip: Option<[u8; 4]>) -> Interface {
    Interface {
        name: name.to_owned(),
        mac: mac.to_owned(),
        group: "lan".to_owned(),
        ip: ip.map(Ipv4Addr::from),
        ..Default::default()
    }
}

fn host(id: &str, name: &str, macs: &[&str], ip: &str) -> HostSection {
    HostSection {
        id: id.to_owned(),
        name: name.to_owned(),
        macs: macs.iter().map(|mac| (*mac).to_owned()).collect(),
        ip: ip.to_owned(),
        dns: "1".to_owned(),
    }
}

const LAN: Network = Network {
    address: Ipv4Addr::new(192, 0, 2, 1),
    prefix: 24,
};

fn list(devices: Vec<Interface>) -> DeviceList {
    DeviceList { interfaces: devices }
}

#[test]
fn networks_contain_their_addresses() {
    let all = Network {
        address: Ipv4Addr::new(10, 0, 0, 1),
        prefix: 0,
    };
    for (network, address, inside) in [
        (LAN, Ipv4Addr::new(192, 0, 2, 200), true),
        (LAN, Ipv4Addr::new(192, 0, 3, 2), false),
        (all, Ipv4Addr::new(198, 51, 100, 1), true),
    ] {
        assert_eq!(network.contains(address), inside, "{address} in {network:?}");
    }
}

#[test]
fn section_ids_are_uci_names() {
    assert_eq!(section_id("Living-Room-TV"), "lanlord_living_room_tv");
}

#[test]
fn an_unnamed_entry_is_taken_over() {
    let devices = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
    let hosts = [host("cfg01", "OMV", &["00:00:00:00:00:01"], "192.0.2.2")];
    let plan = plan(&devices, &hosts, &[LAN], &HashMap::new());
    assert_eq!(plan.changes.len(), 2);
    assert_eq!(plan.changes[0].commands(), ["uci delete dhcp.cfg01"]);
    assert_eq!(
        plan.changes[1].commands(),
        [
            "uci set dhcp.lanlord_omv=host",
            "uci set dhcp.lanlord_omv.name='OMV'",
            "uci set dhcp.lanlord_omv.mac='00:00:00:00:00:01'",
            "uci set dhcp.lanlord_omv.ip='192.0.2.2'",
            "uci set dhcp.lanlord_omv.dns='1'",
        ]
    );
    assert!(plan.changes[1].description().contains("static lease"));
}

#[test]
fn own_sections_only_change_what_differs() {
    let devices = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 3]))]);
    let hosts = [host("lanlord_omv", "OMV", &["00:00:00:00:00:01"], "192.0.2.2")];
    let plan = plan(&devices, &hosts, &[LAN], &HashMap::new());
    assert_eq!(plan.changes.len(), 1);
    assert_eq!(
        plan.changes[0].commands(),
        ["uci set dhcp.lanlord_omv.ip='192.0.2.3'"]
    );
    assert_eq!(plan.changes[0].description(), "OMV: change ip");

    let same = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
    assert_eq!(
        super::plan(&same, &hosts, &[LAN], &HashMap::new()),
        LeasePlan::default()
    );
}

#[test]
fn devices_outside_the_served_networks_wait() {
    let devices = list(vec![device(
        "plug",
        "00:00:00:00:00:02",
        Some([198, 51, 100, 20]),
    )]);
    let hosts = [
        host("cfg02", "plug", &["00:00:00:00:00:02"], "192.0.2.20"),
        host("lanlord_plug", "plug", &["00:00:00:00:00:02"], "192.0.2.20"),
    ];
    let plan = plan(&devices, &hosts, &[LAN], &HashMap::new());
    assert_eq!(plan.changes, []);
    assert!(plan.notes[0].starts_with("plug waits"));
}

#[test]
fn leases_of_removed_devices_and_devices_without_address_go() {
    let devices = list(vec![device("tv", "00:00:00:00:00:03", None)]);
    let hosts = [
        host("lanlord_tv", "tv", &["00:00:00:00:00:03"], "192.0.2.30"),
        host("lanlord_old", "old", &["00:00:00:00:00:09"], "192.0.2.90"),
        host("cfg09", "foreign", &["00:00:00:00:00:08"], "192.0.2.80"),
    ];
    let plan = plan(&devices, &hosts, &[LAN], &HashMap::new());
    let commands: Vec<String> = plan.changes.iter().flat_map(Change::commands).collect();
    assert_eq!(
        commands,
        ["uci delete dhcp.lanlord_tv", "uci delete dhcp.lanlord_old"]
    );
    assert!(plan.changes[1].description().contains("old (lanlord_old)"));
}

#[test]
fn shared_entries_and_taken_addresses_are_left_out() {
    let devices = list(vec![
        device("a", "00:00:00:00:00:01", Some([192, 0, 2, 10])),
        device("b", "00:00:00:00:00:02", Some([192, 0, 2, 11])),
    ]);
    let hosts = [
        host(
            "cfg01",
            "",
            &["00:00:00:00:00:01", "00:00:00:00:00:05"],
            "192.0.2.10",
        ),
        host("cfg02", "printer", &["00:00:00:00:00:06"], "192.0.2.11"),
    ];
    let plan = plan(&devices, &hosts, &[LAN], &HashMap::new());
    assert_eq!(plan.changes, []);
    assert!(plan.notes[0].contains("entry cfg01 holds several"));
    assert!(plan.notes[1].contains("address of entry printer (cfg02)"));
}

#[test]
fn a_mac_moved_to_another_device_is_fixed_with_that_device() {
    let devices = list(vec![
        device("new", "00:00:00:00:00:01", Some([192, 0, 2, 10])),
        device("old", "00:00:00:00:00:02", Some([192, 0, 2, 11])),
    ]);
    let hosts = [host("lanlord_old", "old", &["00:00:00:00:00:01"], "192.0.2.11")];
    let plan = plan(&devices, &hosts, &[LAN], &HashMap::new());
    let commands: Vec<String> = plan.changes.iter().flat_map(Change::commands).collect();
    assert_eq!(commands[0], "uci set dhcp.lanlord_new=host");
    assert!(commands.contains(&"uci set dhcp.lanlord_old.mac='00:00:00:00:00:02'".to_owned()));
}

#[test]
fn the_digest_follows_the_changes() {
    let devices = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
    let first = plan(&devices, &[], &[LAN], &HashMap::new());
    assert_eq!(first.digest().len(), 32);
    assert_eq!(
        first.digest(),
        plan(&devices, &[], &[LAN], &HashMap::new()).digest()
    );
    let other = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 3]))]);
    assert_ne!(
        first.digest(),
        plan(&other, &[], &[LAN], &HashMap::new()).digest()
    );
}

#[test]
fn a_renamed_device_gets_a_warning() {
    let devices = list(vec![device("New", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
    let hosts = [host("lanlord_old", "Old", &["00:00:00:00:00:01"], "192.0.2.2")];
    let plan = plan(&devices, &hosts, &[LAN], &HashMap::new());
    let commands: Vec<String> = plan.changes.iter().flat_map(Change::commands).collect();
    assert!(
        commands.contains(&"uci delete dhcp.lanlord_old".to_owned()),
        "{commands:?}"
    );
    assert!(
        commands.contains(&"uci set dhcp.lanlord_new=host".to_owned()),
        "{commands:?}"
    );
    let delete = plan
        .changes
        .iter()
        .find(|change| matches!(change, Change::Delete { .. }))
        .unwrap();
    assert!(
        delete
            .description()
            .starts_with("Rename Old (lanlord_old) to New"),
        "{delete:?}"
    );
    assert_eq!(
        plan.notes,
        ["Old is now New: its DNS name changes, update what still uses the old name"]
    );
}

#[test]
fn a_device_that_sets_its_address_itself_gets_no_lease() {
    let mut router = device("router", "aa:bb:cc:dd:ee:01", Some([192, 0, 2, 1]));
    router.self_assigned = true;
    let list = DeviceList {
        interfaces: vec![router],
    };
    let networks = [LAN];
    let plan = plan(&list, &[], &networks, &HashMap::new());
    assert!(plan.changes.is_empty(), "{:?}", plan.changes);
}

#[test]
fn a_device_that_sets_its_address_itself_gets_a_name_instead() {
    let mut router = device("router", "aa:bb:cc:dd:ee:01", Some([192, 0, 2, 1]));
    router.self_assigned = true;
    let devices = list(vec![router]);
    let mut plan = LeasePlan::default();
    plan_names(&devices, &[], &[LAN], &mut plan);
    assert_eq!(plan.changes.len(), 1);
    assert!(matches!(&plan.changes[0], Change::Add { section, .. } if section == "lanlordname_router"));

    let name = NameSection {
        id: "lanlordname_router".to_owned(),
        name: "router".to_owned(),
        ip: "192.0.2.1".to_owned(),
    };
    let mut plan = LeasePlan::default();
    plan_names(&devices, std::slice::from_ref(&name), &[LAN], &mut plan);
    assert!(plan.changes.is_empty(), "{:?}", plan.changes);

    let moved = NameSection {
        ip: "192.0.2.2".to_owned(),
        ..name.clone()
    };
    let mut plan = LeasePlan::default();
    plan_names(&devices, &[moved], &[LAN], &mut plan);
    assert!(matches!(&plan.changes[0], Change::Set { .. }));

    let mut plan = LeasePlan::default();
    plan_names(&list(Vec::new()), &[name], &[LAN], &mut plan);
    assert!(matches!(&plan.changes[0], Change::Delete { section, .. } if section == "lanlordname_router"));
}

#[test]
fn a_name_outside_the_served_networks_waits_and_stays() {
    let mut router = device("router", "aa:bb:cc:dd:ee:01", Some([198, 51, 100, 1]));
    router.self_assigned = true;
    let name = NameSection {
        id: "lanlordname_router".to_owned(),
        name: "router".to_owned(),
        ip: "198.51.100.1".to_owned(),
    };
    let mut plan = LeasePlan::default();
    plan_names(&list(vec![router]), &[name], &[LAN], &mut plan);
    assert!(plan.changes.is_empty(), "{:?}", plan.changes);
}

const IOT: Network = Network {
    address: Ipv4Addr::new(198, 51, 100, 1),
    prefix: 24,
};

#[test]
fn a_device_still_in_another_network_keeps_a_lease_there() {
    let devices = list(vec![device("Plug", "00:00:00:00:00:09", Some([198, 51, 100, 9]))]);
    let seen = HashMap::from([("00:00:00:00:00:09".to_owned(), Ipv4Addr::new(192, 0, 2, 9))]);
    let waiting = plan(&devices, &[], &[LAN, IOT], &seen);
    assert_eq!(
        waiting.changes[0].commands().last().map(String::as_str),
        Some("uci set dhcp.lanlord_plug.dns='1'")
    );
    assert!(
        waiting.changes[0]
            .commands()
            .contains(&"uci set dhcp.lanlord_plug.ip='192.0.2.9'".to_owned())
    );
    assert_eq!(
        waiting.notes,
        ["Plug waits at 192.0.2.9: it gets 198.51.100.9 once it is in that network"]
    );
    let moved = HashMap::from([("00:00:00:00:00:09".to_owned(), Ipv4Addr::new(198, 51, 100, 150))]);
    let there = plan(&devices, &[], &[LAN, IOT], &moved);
    assert!(
        there.changes[0]
            .commands()
            .contains(&"uci set dhcp.lanlord_plug.ip='198.51.100.9'".to_owned())
    );
    assert_eq!(there.notes, Vec::<String>::new());
}
