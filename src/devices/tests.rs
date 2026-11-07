//! Unit tests of `devices`.

#![allow(clippy::unwrap_used)]

use super::*;

fn groups() -> Vec<String> {
    vec!["lan".to_owned(), "iot".to_owned()]
}

fn device(name: &str, mac: &str) -> Device {
    Device {
        name: name.to_owned(),
        mac: mac.to_owned(),
        group: "lan".to_owned(),
        ip: None,
        note: String::new(),
        self_assigned: false,
        machine: String::new(),
    }
}

#[test]
fn mac_addresses_are_normalized() {
    assert_eq!(
        normalize_mac("AA-BB-CC-00-11-22").as_deref(),
        Some("aa:bb:cc:00:11:22")
    );
    assert_eq!(
        normalize_mac(" aa:bb:cc:00:11:22 ").as_deref(),
        Some("aa:bb:cc:00:11:22")
    );
    for invalid in [
        "",
        "aa:bb:cc:00:11",
        "aa:bb:cc:00:11:2g",
        "aabbcc001122",
        "aa:bb:cc:00:11:223",
    ] {
        assert_eq!(normalize_mac(invalid), None, "{invalid}");
    }
}

#[test]
fn names_must_be_dns_names() {
    for valid in ["OMV", "HueBridge", "living-room-1", "a"] {
        assert!(is_valid_name(valid), "{valid}");
    }
    for invalid in ["", "-a", "a-", "a_b", "a.b", "a b", &"x".repeat(64)] {
        assert!(!is_valid_name(invalid), "{invalid}");
    }
}

#[test]
fn duplicates_and_unknown_groups_are_rejected() {
    let mut list = DeviceList {
        devices: vec![device("a", "00:00:00:00:00:01"), device("A", "00:00:00:00:00:02")],
    };
    assert!(list.validate(&groups()).is_err(), "names differ only in case");

    list.devices[1].name = "b".to_owned();
    list.devices[1].mac = "00:00:00:00:00:01".to_owned();
    assert!(list.validate(&groups()).is_err(), "same MAC");

    list.devices[1].mac = "00:00:00:00:00:02".to_owned();
    list.devices[0].ip = Some(Ipv4Addr::new(192, 0, 2, 10));
    list.devices[1].ip = Some(Ipv4Addr::new(192, 0, 2, 10));
    assert!(list.validate(&groups()).is_err(), "same IP");

    list.devices[1].ip = None;
    list.devices[1].group = "guest".to_owned();
    assert!(list.validate(&groups()).is_err(), "unknown group");

    list.devices[1].group = "iot".to_owned();
    assert!(list.validate(&groups()).is_ok());
}

#[test]
fn save_and_load_keep_the_list() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("devices.toml");
    let mut list = DeviceList {
        devices: vec![device("OMV", "00:00:00:00:00:01")],
    };
    list.devices[0].ip = Some(Ipv4Addr::new(192, 0, 2, 2));
    list.devices[0].note = "server".to_owned();

    list.save(&path, &groups()).unwrap();
    assert_eq!(DeviceList::load(&path, &groups()).unwrap(), list);

    let mode = fs::metadata(&path).unwrap().permissions();
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777, 0o600);
    assert!(!path.with_extension("toml.tmp").exists());
}

#[test]
fn missing_file_is_an_empty_list_and_unknown_fields_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("devices.toml");
    assert_eq!(DeviceList::load(&path, &groups()).unwrap(), DeviceList::default());

    fs::write(
        &path,
        "[[device]]\nname = \"a\"\nmac = \"00:00:00:00:00:01\"\ngroup = \"lan\"\nvlan = 5\n",
    )
    .unwrap();
    assert!(matches!(DeviceList::load(&path, &groups()), Err(Error::Parse(_))));
}

#[test]
fn interfaces_are_nested_in_the_file_and_older_files_still_load() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("devices.toml");
    let older = "[[device]]\nname = \"Dock\"\nmac = \"00:00:00:00:00:01\"\ngroup = \"lan\"\nmachine = \"ThinkPad\"\n\n\
                 [[device]]\nname = \"Wifi\"\nmac = \"00:00:00:00:00:02\"\ngroup = \"iot\"\nmachine = \"ThinkPad\"\n\n\
                 [[device]]\nname = \"tv\"\nmac = \"00:00:00:00:00:03\"\ngroup = \"lan\"\n";
    fs::write(&path, older).unwrap();
    let list = DeviceList::load(&path, &groups()).unwrap();
    assert_eq!(list.devices.len(), 3);
    assert_eq!(list.devices[1].machine, "ThinkPad");

    list.save(&path, &groups()).unwrap();
    let saved = fs::read_to_string(&path).unwrap();
    assert!(saved.contains("[[device.interface]]"), "{saved}");
    assert_eq!(saved.matches("machine").count(), 0, "{saved}");
    assert_eq!(
        saved.matches("[[device]]").count(),
        2,
        "a machine and a plain device: {saved}"
    );
    assert!(
        saved.contains("name = \"tv\"\nmac = "),
        "plain devices stay flat: {saved}"
    );
    assert_eq!(
        DeviceList::load(&path, &groups()).unwrap(),
        list,
        "the same list comes back"
    );
}

#[test]
fn a_device_needs_a_mac_or_interfaces() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("devices.toml");
    fs::write(&path, "[[device]]\nname = \"a\"\ngroup = \"lan\"\n").unwrap();
    assert!(matches!(DeviceList::load(&path, &groups()), Err(Error::Parse(_))));
    fs::write(
        &path,
        "[[device]]\nname = \"a\"\nmac = \"00:00:00:00:00:01\"\ngroup = \"lan\"\n\n\
         [[device.interface]]\nname = \"b\"\nmac = \"00:00:00:00:00:02\"\n",
    )
    .unwrap();
    assert!(matches!(DeviceList::load(&path, &groups()), Err(Error::Parse(_))));
}
