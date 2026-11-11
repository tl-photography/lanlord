use super::*;

#[test]
fn names_come_from_the_host_name_or_the_mac() {
    assert_eq!(
        suggested_name("Living Room TV", "aa:bb:cc:dd:ee:ff"),
        "living-room-tv"
    );
    assert_eq!(suggested_name("", "aa:bb:cc:dd:ee:ff"), "device-ddeeff");
    assert_eq!(suggested_name("***", "aa:bb:cc:dd:ee:ff"), "device-ddeeff");
}

#[test]
fn a_taken_name_gets_a_number() {
    let interface = |name: &str| Interface {
        name: name.to_owned(),
        ..Default::default()
    };
    let list = DeviceList {
        interfaces: vec![interface("phone"), interface("Phone-2")],
    };
    assert_eq!(unique_name(&list, "tv"), "tv");
    assert_eq!(unique_name(&list, "phone"), "phone-3");
    let long = "a".repeat(63);
    let list = DeviceList {
        interfaces: vec![interface(&long)],
    };
    assert_eq!(unique_name(&list, &long).len(), 63);
}

#[test]
fn last_seen_lines_survive_a_round_trip() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("last-seen");
    let seen = HashMap::from([
        ("aa:bb:cc:dd:ee:01".to_owned(), 5),
        ("aa:bb:cc:dd:ee:02".to_owned(), 7),
    ]);
    write_seen(&path, &seen);
    assert_eq!(read_seen(&path), seen);
    std::fs::write(&path, "broken\naa:bb:cc:dd:ee:03 x\naa:bb:cc:dd:ee:04 9\n").unwrap();
    assert_eq!(
        read_seen(&path),
        HashMap::from([("aa:bb:cc:dd:ee:04".to_owned(), 9)])
    );
}
