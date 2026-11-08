use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::*;

/// One row of the fake agent.
fn answer(id: u32, oid: &[u32], value: &[u8]) -> Vec<u8> {
    let binding = tlv(TAG_SEQUENCE, &[encode_oid(oid), value.to_vec()].concat());
    let bindings = tlv(TAG_SEQUENCE, &binding);
    let pdu = tlv(
        TAG_RESPONSE,
        &[integer(id), integer(0), integer(0), bindings].concat(),
    );
    tlv(
        TAG_SEQUENCE,
        &[integer(VERSION_2C), tlv(TAG_OCTET_STRING, b"secret"), pdu].concat(),
    )
}

/// The request id and OID of a request.
fn parse_request(bytes: &[u8]) -> (u32, Vec<u32>) {
    let (message, _) = expect(TAG_SEQUENCE, bytes).unwrap();
    let (_, rest) = expect(TAG_INTEGER, message).unwrap();
    let (community, rest) = expect(TAG_OCTET_STRING, rest).unwrap();
    assert_eq!(community, b"secret");
    let (pdu, _) = expect(TAG_GET_NEXT, rest).unwrap();
    let (id, rest) = expect(TAG_INTEGER, pdu).unwrap();
    let (_, rest) = expect(TAG_INTEGER, rest).unwrap();
    let (_, rest) = expect(TAG_INTEGER, rest).unwrap();
    let (bindings, _) = expect(TAG_SEQUENCE, rest).unwrap();
    let (binding, _) = expect(TAG_SEQUENCE, bindings).unwrap();
    let (oid, _) = expect(TAG_OID, binding).unwrap();
    (decode_number(id), decode_oid(oid).unwrap())
}

/// Answers GETNEXT from `rows`, until the socket is dropped with the test.
async fn agent(rows: BTreeMap<Vec<u32>, Vec<u8>>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0; 2048];
        while let Ok((size, from)) = socket.recv_from(&mut buffer).await {
            let (id, oid) = parse_request(&buffer[..size]);
            let reply = match rows
                .range((std::ops::Bound::Excluded(oid.clone()), std::ops::Bound::Unbounded))
                .next()
            {
                Some((next, value)) => answer(id, next, value),
                None => answer(id, &oid, &tlv(TAG_END_OF_MIB, &[])),
            };
            socket.send_to(&reply, from).await.unwrap();
        }
    });
    address
}

fn row(table: &[u32], index: &[u32]) -> Vec<u32> {
    [table, index].concat()
}

fn plugin(host: &str, data: &Path) -> Snmp {
    let path = data.join("switch.community");
    fs::write(&path, "secret\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut table = toml::Table::new();
    table.insert("host".to_owned(), toml::Value::String(host.to_owned()));
    table.insert(
        "community_file".to_owned(),
        toml::Value::String("switch.community".to_owned()),
    );
    Snmp::new("switch".to_owned(), table, data).unwrap()
}

#[test]
fn messages_survive_encoding() {
    for number in [0, 1, 127, 128, 255, 256, 70_000, u32::MAX] {
        let encoded = integer(number);
        let (content, _) = expect(TAG_INTEGER, &encoded).unwrap();
        assert_eq!(decode_number(content), number);
    }
    let oid = [1, 3, 6, 1, 2, 1, 17, 200, 70_000];
    let encoded = encode_oid(&oid);
    let (content, _) = expect(TAG_OID, &encoded).unwrap();
    assert_eq!(decode_oid(content).unwrap(), oid);
    let long = vec![7; 300];
    let encoded = tlv(TAG_OCTET_STRING, &long);
    let (content, rest) = expect(TAG_OCTET_STRING, &encoded).unwrap();
    assert_eq!(content, long);
    assert_eq!(rest.len(), 0);
}

#[test]
fn a_broken_answer_is_refused() {
    assert!(response(&[]).is_none());
    assert!(response(&[0x30, 0x84, 1]).is_none());
    assert!(response(&tlv(TAG_SEQUENCE, &[1, 2, 3])).is_none());
}

#[tokio::test]
async fn a_port_with_one_device_reports_its_vlan() {
    let mut rows = BTreeMap::new();
    // VLAN 1, then the MAC address. Port 0 is the switch itself, port 3 leads to several devices.
    rows.insert(row(VLAN_FDB, &[1, 170, 187, 204, 0, 0, 1]), integer(2));
    rows.insert(row(VLAN_FDB, &[1, 170, 187, 204, 0, 0, 2]), integer(3));
    rows.insert(row(VLAN_FDB, &[20, 170, 187, 204, 0, 0, 3]), integer(3));
    rows.insert(row(VLAN_FDB, &[1, 170, 187, 204, 0, 0, 4]), integer(0));
    rows.insert(row(PORT_VLAN, &[2]), integer(20));
    rows.insert(row(PORT_VLAN, &[3]), integer(1));
    let address = agent(rows).await;
    let data = tempfile::tempdir().unwrap();
    let observation = plugin(&address.to_string(), data.path()).read().await.unwrap();
    assert!(observation.partial);
    assert_eq!(
        observation.assigned.unwrap(),
        [Assigned {
            mac: "aa:bb:cc:00:00:01".to_owned(),
            name: String::new(),
            ip: None,
            vlan: Some(20),
        }]
    );
}

#[tokio::test]
async fn the_plain_table_is_the_fallback() {
    let mut rows = BTreeMap::new();
    rows.insert(row(FDB, &[170, 187, 204, 0, 0, 1]), integer(4));
    rows.insert(row(PORT_VLAN, &[4]), integer(1));
    let address = agent(rows).await;
    let data = tempfile::tempdir().unwrap();
    let observation = plugin(&address.to_string(), data.path()).read().await.unwrap();
    assert_eq!(observation.assigned.unwrap()[0].vlan, Some(1));
}

#[tokio::test]
async fn a_community_file_for_everyone_is_refused() {
    let data = tempfile::tempdir().unwrap();
    let plugin = plugin("127.0.0.1:1", data.path());
    fs::set_permissions(&plugin.community_file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(plugin.read().await.unwrap_err().contains("0600"));
}
