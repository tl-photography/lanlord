//! Unit tests of `leases`.

use super::*;
use crate::devices::Device;

fn device(name: &str, mac: &str, ip: Option<[u8; 4]>) -> Device {
    Device {
        name: name.to_owned(),
        mac: mac.to_owned(),
        group: "lan".to_owned(),
        ip: ip.map(Ipv4Addr::from),
        note: String::new(),
        machine: String::new(),
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

fn list(devices: Vec<Device>) -> DeviceList {
    DeviceList { devices }
}

#[test]
fn networks_contain_their_addresses() {
    assert!(LAN.contains(Ipv4Addr::new(192, 0, 2, 200)));
    assert!(!LAN.contains(Ipv4Addr::new(192, 0, 3, 2)));
    let all = Network {
        address: Ipv4Addr::new(10, 0, 0, 1),
        prefix: 0,
    };
    assert!(all.contains(Ipv4Addr::new(198, 51, 100, 1)));
}

#[test]
fn section_ids_are_uci_names() {
    assert_eq!(section_id("Living-Room-TV"), "lanlord_living_room_tv");
}

#[test]
fn an_unnamed_entry_is_taken_over() {
    let devices = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
    let hosts = [host("cfg01", "OMV", &["00:00:00:00:00:01"], "192.0.2.2")];
    let plan = plan(&devices, &hosts, &[LAN]);
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
    let plan = plan(&devices, &hosts, &[LAN]);
    assert_eq!(plan.changes.len(), 1);
    assert_eq!(
        plan.changes[0].commands(),
        ["uci set dhcp.lanlord_omv.ip='192.0.2.3'"]
    );
    assert_eq!(plan.changes[0].description(), "OMV: change ip");

    let same = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
    assert_eq!(super::plan(&same, &hosts, &[LAN]), Plan::default());
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
    let plan = plan(&devices, &hosts, &[LAN]);
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
    let plan = plan(&devices, &hosts, &[LAN]);
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
    let plan = plan(&devices, &hosts, &[LAN]);
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
    let plan = plan(&devices, &hosts, &[LAN]);
    let commands: Vec<String> = plan.changes.iter().flat_map(Change::commands).collect();
    assert_eq!(commands[0], "uci set dhcp.lanlord_new=host");
    assert!(commands.contains(&"uci set dhcp.lanlord_old.mac='00:00:00:00:00:02'".to_owned()));
}

#[test]
fn the_digest_follows_the_changes() {
    let devices = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
    let first = plan(&devices, &[], &[LAN]);
    assert_eq!(first.digest().len(), 32);
    assert_eq!(first.digest(), plan(&devices, &[], &[LAN]).digest());
    let other = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 3]))]);
    assert_ne!(first.digest(), plan(&other, &[], &[LAN]).digest());
}

#[test]
fn a_renamed_device_gets_a_warning() {
    let devices = list(vec![device("New", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
    let hosts = [host("lanlord_old", "Old", &["00:00:00:00:00:01"], "192.0.2.2")];
    let plan = plan(&devices, &hosts, &[LAN]);
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
