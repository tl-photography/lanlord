//! Unit tests of `plugins/openwrt`.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::devices::DeviceList;

const FINGERPRINT: &str =
    "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

#[test]
fn fingerprints_are_parsed_with_and_without_colons() {
    let parsed = parse_fingerprint(FINGERPRINT).unwrap();
    assert_eq!(parsed[1], 0x11);
    assert_eq!(
        parse_fingerprint(&FINGERPRINT.replace(':', "").to_lowercase()),
        Some(parsed)
    );
    assert_eq!(parse_fingerprint("00:11"), None);
    assert_eq!(parse_fingerprint(&FINGERPRINT.replace("FF", "GG")), None);
}

#[test]
fn only_the_pinned_certificate_is_trusted() {
    let certificate = CertificateDer::from(vec![1, 2, 3]);
    let digest = ring::digest::digest(&ring::digest::SHA256, &[1, 2, 3]);
    let mut fingerprint = [0; 32];
    fingerprint.copy_from_slice(digest.as_ref());
    let verifier = PinnedCertificate {
        fingerprint,
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    };
    let name = ServerName::try_from("router.lan").unwrap();
    assert!(
        verifier
            .verify_server_cert(&certificate, &[], &name, &[], UnixTime::now())
            .is_ok()
    );
    let other = CertificateDer::from(vec![1, 2, 4]);
    assert!(
        verifier
            .verify_server_cert(&other, &[], &name, &[], UnixTime::now())
            .is_err()
    );
    assert_ne!(verifier.supported_verify_schemes(), Vec::new());
}

#[test]
fn leases_hosts_and_stations_become_one_entry_per_mac() {
    let leases = json!({ "dhcp_leases": [
            { "macaddr": "AA:BB:CC:00:00:01", "ipaddr": "192.0.2.10", "hostname": "phone" },
            { "macaddr": "aa:bb:cc:00:00:02", "ipaddr": "192.0.2.11" },
            { "macaddr": "broken", "ipaddr": "192.0.2.12" }
        ] });
    let hosts = json!({ "values": {
            "cfg01": { ".type": "host", "name": "tv", "mac": "aa:bb:cc:00:00:03 AA:BB:CC:00:00:04", "ip": "192.0.2.20" },
            "cfg02": { ".type": "host", "name": "plug", "mac": ["aa:bb:cc:00:00:05"] },
            "cfg03": { ".type": "host", "name": "copy", "mac": "aa:bb:cc:00:00:05", "ip": "192.0.2.99" }
        } });
    let stations = json!({ "values": {
            "cfg10": { ".type": "wifi-station", "mac": "aa:bb:cc:00:00:05", "vid": "20" },
            "cfg11": { ".type": "wifi-station", "mac": "aa:bb:cc:00:00:06", "vid": "30" },
            "cfg12": { ".type": "wifi-station", "mac": "aa:bb:cc:00:00:07", "vid": "9999" }
        } });
    let observation = observation(&leases, &hosts, &stations);
    assert_eq!(observation.present.len(), 2);
    assert_eq!(observation.present[0].hostname, "phone");
    assert_eq!(observation.present[1].hostname, "");
    let entries = observation.assigned.unwrap();
    let entry = |mac: &str| entries.iter().find(|entry| entry.mac == mac).unwrap();
    assert_eq!(entries.len(), 4, "the station with VLAN 9999 is ignored");
    assert_eq!(entry("aa:bb:cc:00:00:03").name, "tv");
    assert_eq!(entry("aa:bb:cc:00:00:04").ip, Some(Ipv4Addr::new(192, 0, 2, 20)));
    assert_eq!(
        entry("aa:bb:cc:00:00:05").name,
        "plug",
        "the first entry of a MAC wins"
    );
    assert_eq!(entry("aa:bb:cc:00:00:05").vlan, Some(20));
    assert_eq!(
        entry("aa:bb:cc:00:00:06").name,
        "",
        "a station without a static lease"
    );
    assert_eq!(entry("aa:bb:cc:00:00:06").vlan, Some(30));
}

#[test]
fn ubus_errors_are_explained() {
    for (answer, expected) in [
        (json!({ "result": [0, { "a": 1 }] }), Ok(json!({ "a": 1 }))),
        (json!({ "result": [0] }), Ok(json!({}))),
        (json!({ "result": [6] }), Err("rpcd ACL")),
        (json!({ "result": [4] }), Err("not found")),
        (json!({ "result": [5] }), Err("no data")),
        (json!({ "result": [9] }), Err("ubus error 9")),
        (
            json!({ "error": { "code": -32002, "message": "Access denied" } }),
            Err("access denied"),
        ),
        (json!({}), Err("")),
        (json!({ "result": [] }), Err("")),
    ] {
        match (result(&answer), expected) {
            (Ok(value), Ok(wanted)) => assert_eq!(value, wanted, "{answer}"),
            (Err(error), Err(wanted)) => assert!(error.contains(wanted), "{answer}: {error}"),
            (got, wanted) => panic!("{answer}: {got:?}, expected {wanted:?}"),
        }
    }
}

fn settings_table(url: &str) -> toml::Table {
    toml::from_str(&format!(
            "url = \"{url}\"\nuser = \"lanlord\"\npassword_file = \"router.password\"\ncertificate = \"{FINGERPRINT}\"\n"
        ))
        .unwrap()
}

#[test]
fn plain_http_is_only_allowed_to_the_own_host() {
    let data = Path::new("/data");
    for (url, allowed) in [
        ("https://router.lan", true),
        ("http://127.0.0.1:8080", true),
        ("http://router.lan", false),
        ("ftp://router.lan", false),
        ("not a url", false),
    ] {
        let built = OpenWrt::new("router".to_owned(), settings_table(url), data);
        assert_eq!(built.is_ok(), allowed, "{url}");
    }
    let mut table = settings_table("https://router.lan");
    table.insert("certificate".to_owned(), toml::Value::String("12".to_owned()));
    assert!(OpenWrt::new("router".to_owned(), table, data).is_err());
}

/// A small ubus API like `OpenWrt`'s: one password and the calls lanlord makes. `wifi` answers `iwinfo devices`.
async fn fake_router(stations: Value) -> String {
    fake_router_with_wifi(stations, json!([4])).await
}

async fn fake_router_with_wifi(stations: Value, wifi: Value) -> String {
    use axum::{Json, Router, routing::post};
    let handler = move |Json(request): Json<Value>| {
        let stations = stations.clone();
        let wifi = wifi.clone();
        async move {
            let params = request["params"].as_array().cloned().unwrap_or_default();
            let object = params[1].as_str().unwrap_or_default();
            let method = params[2].as_str().unwrap_or_default();
            let result = match (object, method) {
                ("session", "login") if params[3]["password"] == "secret" => {
                    json!([0, { "ubus_rpc_session": "session-1" }])
                }
                _ if params[0] != "session-1" => json!([6]),
                ("luci-rpc", "getDHCPLeases") => json!([0, { "dhcp_leases": [
                        { "macaddr": "aa:bb:cc:00:00:01", "ipaddr": "192.0.2.10", "hostname": "phone" }
                    ] }]),
                ("uci", "get") if params[3]["config"] == "dhcp" => json!([0, { "values": {
                        "cfg1": { "name": "tv", "mac": "aa:bb:cc:00:00:02", "ip": "192.0.2.20" }
                    } }]),
                ("uci", "get") => stations,
                ("iwinfo", "devices") => wifi,
                ("iwinfo", "assoclist") => json!([0, { "results": [
                        { "mac": "AA:BB:CC:00:00:01", "signal": -43 },
                        { "mac": "aa:bb:cc:00:00:09", "signal": -71 }
                    ] }]),
                _ => json!([3]),
            };
            Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, Router::new().route("/ubus", post(handler))).await });
    format!("http://127.0.0.1:{}", address.port())
}

fn plugin(url: &str, data: &Path, password: &str, mode: u32) -> OpenWrt {
    let path = data.join("router.password");
    std::fs::write(&path, password).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    OpenWrt::new("router".to_owned(), settings_table(url), data).unwrap()
}

#[tokio::test]
async fn reads_a_router_through_ubus() {
    let data = tempfile::tempdir().unwrap();
    let router = plugin(&fake_router(json!([4])).await, data.path(), "secret\n", 0o600);
    assert_eq!(router.name(), "router");
    assert_eq!(router.kind(), "openwrt");
    let observation = router.observe().await.unwrap();
    assert_eq!(observation.present[0].hostname, "phone");
    let entries = observation.assigned.unwrap();
    assert_eq!(entries[0].name, "tv");
    assert_eq!(entries[0].vlan, None, "no wireless configuration on this device");
}

#[tokio::test]
async fn reads_station_vlans_of_an_access_point() {
    let data = tempfile::tempdir().unwrap();
    let stations = json!([0, { "values": { "cfg9": { "mac": "aa:bb:cc:00:00:02", "vid": "20" } } }]);
    let access_point = plugin(&fake_router(stations).await, data.path(), "secret", 0o600);
    let entries = access_point.observe().await.unwrap().assigned.unwrap();
    assert_eq!(entries[0].vlan, Some(20));
}

#[tokio::test]
async fn login_and_permission_problems_are_reported() {
    let data = tempfile::tempdir().unwrap();
    for (login, password, mode, expected) in [
        (json!([4]), "wrong", 0o600, "login as lanlord failed"),
        (json!([6]), "secret", 0o600, "rpcd ACL"),
        (json!([4]), "secret", 0o644, "mode 0600"),
        (json!([4]), " \n", 0o600, "empty"),
    ] {
        let router = plugin(&fake_router(login).await, data.path(), password, mode);
        let error = router.observe().await.unwrap_err();
        assert!(error.contains(expected), "{expected}: {error}");
    }

    let missing = OpenWrt::new(
        "router".to_owned(),
        settings_table("http://127.0.0.1:9"),
        &data.path().join("nowhere"),
    )
    .unwrap();
    assert!(missing.observe().await.is_err());
}

#[tokio::test]
async fn unreachable_devices_fail_quickly() {
    let data = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let router = plugin(&format!("http://127.0.0.1:{port}"), data.path(), "secret", 0o600);
    assert!(router.observe().await.is_err());
}

/// A router like rpcd: uci changes are staged per session, `apply` commits them and keeps a snapshot until
/// `confirm`, `rollback` restores it. `lose_changes` makes `apply` keep the old state; `deny` refuses one method.
#[derive(Default)]
struct FakeUci {
    committed: serde_json::Map<String, Value>,
    /// The other configurations, by name.
    others: serde_json::Map<String, Value>,
    staged: Vec<(String, Value)>,
    snapshot: Option<(serde_json::Map<String, Value>, serde_json::Map<String, Value>)>,
    calls: Vec<String>,
    lose_changes: bool,
    deny: &'static str,
    serves_dhcp: bool,
}

impl FakeUci {
    fn answer(&mut self, method: &str, arguments: &Value) -> Value {
        match method {
            "get" if arguments["config"] != "dhcp" => {
                let values = self
                    .others
                    .get(arguments["config"].as_str().unwrap_or_default())
                    .cloned();
                return json!([0, { "values": values.unwrap_or_else(|| json!({})) }]);
            }
            "get" => {
                let mut values = self.committed.clone();
                let ignore = if self.serves_dhcp { "0" } else { "1" };
                values.insert(
                    "lan".to_owned(),
                    json!({ ".type": "dhcp", ".name": "lan", "interface": "lan", "ignore": ignore }),
                );
                values.insert(
                    "wan".to_owned(),
                    json!({ ".type": "dhcp", ".name": "wan", "interface": "wan", "ignore": "1" }),
                );
                return json!([0, { "values": values }]);
            }
            _ if method == self.deny => return json!([6]),
            "add" | "set" | "delete" => self.staged.push((method.to_owned(), arguments.clone())),
            "apply" => {
                self.snapshot = Some((self.committed.clone(), self.others.clone()));
                for (method, arguments) in std::mem::take(&mut self.staged) {
                    if !self.lose_changes {
                        self.commit(&method, &arguments);
                    }
                }
            }
            "confirm" => self.snapshot = None,
            "rollback" => (self.committed, self.others) = self.snapshot.take().unwrap_or_default(),
            "revert" => self.staged.clear(),
            _ => return json!([3]),
        }
        self.calls.push(method.to_owned());
        json!([0])
    }

    fn commit(&mut self, method: &str, arguments: &Value) {
        let values = arguments["values"].as_object().cloned().unwrap_or_default();
        let config = arguments["config"].as_str().unwrap_or("dhcp");
        let sections = if config == "dhcp" {
            &mut self.committed
        } else {
            self.others
                .entry(config.to_owned())
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .unwrap()
        };
        match method {
            "add" => {
                let name = arguments["name"].as_str().unwrap().to_owned();
                let mut section = values;
                section.insert(".type".to_owned(), arguments["type"].clone());
                section.insert(".name".to_owned(), json!(name));
                sections.insert(name, Value::Object(section));
            }
            "set" => {
                let section = arguments["section"].as_str().unwrap();
                sections[section].as_object_mut().unwrap().extend(values);
            }
            _ => {
                sections.remove(arguments["section"].as_str().unwrap());
            }
        }
    }
}

async fn fake_target(fake: FakeUci) -> (String, Arc<std::sync::Mutex<FakeUci>>) {
    use axum::{Json, Router, routing::post};
    let state = Arc::new(std::sync::Mutex::new(fake));
    let shared = state.clone();
    let handler = move |Json(request): Json<Value>| {
        let state = shared.clone();
        async move {
            let params = request["params"].as_array().cloned().unwrap_or_default();
            let object = params[1].as_str().unwrap_or_default();
            let method = params[2].as_str().unwrap_or_default();
            let result = match object {
                "session" => json!([0, { "ubus_rpc_session": "session-1" }]),
                // Like an access point's ACL: no interfaces for a device without DHCP.
                "network.interface" if !state.lock().unwrap().serves_dhcp => json!([6]),
                "network.interface" => json!([0, { "interface": [
                        { "interface": "lan", "ipv4-address": [{ "address": "192.0.2.1", "mask": 24 }] },
                        { "interface": "wan", "ipv4-address": [{ "address": "198.51.100.2", "mask": 24 }] }
                    ] }]),
                "uci" => state.lock().unwrap().answer(method, &params[3]),
                "luci-rpc" => json!([0, { "dhcp_leases": [] }]),
                "network.device" => json!([0, { "bridge-members": ["lan1", "phy0-ap0"] }]),
                "file"
                    if params[3]["path"]
                        .as_str()
                        .unwrap_or_default()
                        .ends_with("port_no") =>
                {
                    json!([0, { "data": "0x1\n" }])
                }
                "file" => {
                    let mut entry = vec![0xaa, 0xbb, 0xcc, 0, 0, 1, 1];
                    entry.resize(16, 0);
                    json!([0, { "data": BASE64.encode(entry) }])
                }
                _ => json!([3]),
            };
            Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, Router::new().route("/ubus", post(handler))).await });
    (format!("http://127.0.0.1:{}", address.port()), state)
}

fn router_with_omv() -> FakeUci {
    let mut fake = FakeUci {
        serves_dhcp: true,
        ..FakeUci::default()
    };
    fake.committed.insert(
            "cfg01".to_owned(),
            json!({ ".type": "host", ".name": "cfg01", "name": "OMV", "mac": "aa:bb:cc:00:00:01", "ip": "192.0.2.2", "dns": "1" }),
        );
    fake
}

fn devices() -> DeviceList {
    let device = |name: &str, mac: &str, ip: [u8; 4]| crate::devices::Interface {
        name: name.to_owned(),
        mac: mac.to_owned(),
        group: "lan".to_owned(),
        ip: Some(Ipv4Addr::from(ip)),
        ..Default::default()
    };
    DeviceList {
        interfaces: vec![
            device("OMV", "aa:bb:cc:00:00:01", [192, 0, 2, 2]),
            device("plug", "aa:bb:cc:00:00:02", [203, 0, 113, 20]),
        ],
    }
}

#[tokio::test]
async fn applies_static_leases_and_confirms_after_reading_them_back() {
    let data = tempfile::tempdir().unwrap();
    let (url, fake) = fake_target(router_with_omv()).await;
    let router = plugin(&url, data.path(), "secret", 0o600);
    assert!(router.is_target());

    let plan = router.plan(devices().into()).await.unwrap().unwrap();
    assert_eq!(plan.steps.len(), 2, "take over cfg01 as lanlord_omv");
    assert!(plan.notes[0].starts_with("plug waits"));

    assert_eq!(
        router.apply(devices().into(), plan.digest()).await.unwrap().len(),
        2
    );
    {
        let fake = fake.lock().unwrap();
        assert_eq!(fake.calls, ["delete", "add", "apply", "confirm"]);
        assert!(fake.committed.contains_key("lanlord_omv"));
        assert!(!fake.committed.contains_key("cfg01"));
    }
    assert_eq!(router.plan(devices().into()).await.unwrap().unwrap().steps, []);
    assert_eq!(
        router
            .apply(devices().into(), LeasePlan::default().digest())
            .await
            .unwrap(),
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn changes_that_differ_from_the_preview_are_not_applied() {
    let data = tempfile::tempdir().unwrap();
    let (url, fake) = fake_target(router_with_omv()).await;
    let router = plugin(&url, data.path(), "secret", 0o600);
    let error = router
        .apply(devices().into(), "stale".to_owned())
        .await
        .unwrap_err();
    assert!(error.contains("changed since the preview"), "{error}");
    assert_eq!(fake.lock().unwrap().calls, Vec::<String>::new());
}

#[tokio::test]
async fn changes_the_router_does_not_show_are_rolled_back() {
    let data = tempfile::tempdir().unwrap();
    let (url, fake) = fake_target(FakeUci {
        lose_changes: true,
        ..router_with_omv()
    })
    .await;
    let router = plugin(&url, data.path(), "secret", 0o600);
    let digest = router.plan(devices().into()).await.unwrap().unwrap().digest();
    let error = router.apply(devices().into(), digest).await.unwrap_err();
    assert!(error.contains("rolled back"), "{error}");
    assert_eq!(fake.lock().unwrap().calls, ["delete", "add", "apply", "rollback"]);
}

#[tokio::test]
async fn a_refused_change_discards_the_staged_ones() {
    let data = tempfile::tempdir().unwrap();
    let (url, fake) = fake_target(FakeUci {
        deny: "add",
        ..router_with_omv()
    })
    .await;
    let router = plugin(&url, data.path(), "secret", 0o600);
    let digest = router.plan(devices().into()).await.unwrap().unwrap().digest();
    let error = router.apply(devices().into(), digest).await.unwrap_err();
    assert!(error.contains("rpcd ACL"), "{error}");
    assert_eq!(
        fake.lock().unwrap().calls,
        ["delete", "revert", "revert", "revert", "revert", "revert"],
        "every configuration is reverted"
    );
}

#[tokio::test]
async fn an_access_point_without_dhcp_has_nothing_to_apply() {
    let data = tempfile::tempdir().unwrap();
    let (url, _) = fake_target(FakeUci::default()).await;
    let access_point = plugin(&url, data.path(), "secret", 0o600);
    assert_eq!(access_point.plan(devices().into()).await.unwrap(), None);
    let error = access_point
        .apply(devices().into(), String::new())
        .await
        .unwrap_err();
    assert!(error.contains("nothing to apply"), "{error}");
}

#[tokio::test]
async fn another_dhcp_server_keeps_the_static_leases() {
    let data = tempfile::tempdir().unwrap();
    let (url, fake) = fake_target(router_with_omv()).await;
    let router = plugin(&url, data.path(), "secret", 0o600);
    let plan = Plan {
        devices: devices(),
        services: vec![crate::plan::Service {
            kind: "dhcp",
            address: Ipv4Addr::new(192, 0, 2, 53),
            source: "filter".to_owned(),
        }],
        dhcp_service: "filter".to_owned(),
        ..Plan::default()
    };
    assert_eq!(router.plan(plan).await.unwrap(), None);
    assert!(
        fake.lock().unwrap().committed.contains_key("cfg01"),
        "its own lease stays"
    );
}

#[tokio::test]
async fn wifi_clients_are_present_without_a_lease() {
    let data = tempfile::tempdir().unwrap();
    let url = fake_router_with_wifi(json!([4]), json!([0, { "devices": ["phy0-ap0"] }])).await;
    let observation = plugin(&url, data.path(), "secret", 0o600)
        .observe()
        .await
        .unwrap();
    assert!(
        observation
            .present
            .iter()
            .any(|present| present.mac == "aa:bb:cc:00:00:09" && present.ip.is_none()),
        "a Wi-Fi client without a lease is present"
    );
    assert_eq!(
        observation.present.len(),
        2,
        "the leased phone is not added twice"
    );
    assert_eq!(observation.notes, Vec::<String>::new());
}

#[tokio::test]
async fn missing_rights_for_wifi_become_a_note() {
    let data = tempfile::tempdir().unwrap();
    let url = fake_router_with_wifi(json!([4]), json!([6])).await;
    let observation = plugin(&url, data.path(), "secret", 0o600)
        .observe()
        .await
        .unwrap();
    assert!(
        observation.notes[0].starts_with("Wi-Fi clients not read:"),
        "{:?}",
        observation.notes
    );
    assert!(observation.notes[0].contains("rpcd ACL"));
}

#[test]
fn dns_names_are_domain_sections() {
    assert_eq!(leases::section_type(&leases::name_id("RouterMain")), "domain");
    assert_eq!(leases::section_type(&leases::section_id("RouterMain")), "host");
    let change = Change::Add {
        section: leases::name_id("RouterMain"),
        values: Vec::new(),
        why: String::new(),
    };
    assert_eq!(change.commands(), ["uci set dhcp.lanlordname_routermain=domain"]);
}

fn router_with_a_bridge() -> FakeUci {
    let mut fake = router_with_omv();
    fake.others.insert(
        "network".to_owned(),
        json!({
            "cfg030f15": { ".type": "device", ".index": 1, "name": "br-lan", "type": "bridge", "ports": ["lan1", "lan2"] },
            "lan": { ".type": "interface", ".index": 2, "device": "br-lan", "proto": "static" }
        }),
    );
    fake.others.insert(
        "firewall".to_owned(),
        json!({ "cfg01": { ".type": "zone", "name": "lan", "network": ["lan"] }, "cfg02": { ".type": "zone", "name": "wan", "network": ["wan"] } }),
    );
    fake
}

fn plan_with_iot() -> Plan {
    let group = |name: &str, vlan: u16, subnet: &str| crate::config::Group {
        name: name.to_owned(),
        vlan,
        subnet: subnet.to_owned(),
        label: String::new(),
        ssid: String::new(),
        ssid_password_file: String::new(),
        ssid_bands: Vec::new(),
        reachable_from: Vec::new(),
        reaches: Vec::new(),
    };
    Plan {
        devices: devices(),
        groups: vec![
            group("lan", 1, "192.0.2.0/24"),
            group("iot", 20, "203.0.113.0/24"),
        ],
        ..Plan::default()
    }
}

fn managing(url: &str, data: &Path) -> OpenWrt {
    std::fs::write(data.join("router.password"), "secret").unwrap();
    std::fs::set_permissions(
        data.join("router.password"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut table = settings_table(url);
    table.insert("manage_networks".to_owned(), toml::Value::Boolean(true));
    OpenWrt::new("router".to_owned(), table, data).unwrap()
}

#[tokio::test]
async fn builds_a_network_and_confirms_after_reading_it_back() {
    let data = tempfile::tempdir().unwrap();
    let (url, fake) = fake_target(router_with_a_bridge()).await;
    let router = managing(&url, data.path());
    let preview = router.plan(plan_with_iot()).await.unwrap().unwrap();
    let steps: Vec<&str> = preview
        .steps
        .iter()
        .map(|step| step.description.as_str())
        .collect();
    assert!(steps.contains(&"LAN moves to br-lan.1"), "{steps:?}");
    assert!(steps.contains(&"firewall zone iot: new"), "{steps:?}");
    router.apply(plan_with_iot(), preview.digest()).await.unwrap();
    {
        let fake_now = fake.lock().unwrap();
        assert_eq!(fake_now.calls.last().map(String::as_str), Some("confirm"));
        assert_eq!(fake_now.others["network"]["lan"]["device"], "br-lan.1");
        assert_eq!(
            fake_now.others["network"]["lanlordnet_iot"]["ipaddr"],
            "203.0.113.1"
        );
        assert_eq!(
            fake_now.others["firewall"]["lanlordnet_iot_zone"][".type"],
            "zone"
        );
    }
    let again = router.plan(plan_with_iot()).await.unwrap().unwrap();
    assert!(
        again.steps.iter().all(|step| !step.description.contains("iot")),
        "nothing of the network is left: {:?}",
        again.steps
    );
}

#[tokio::test]
async fn without_the_setting_networks_are_left_alone() {
    let data = tempfile::tempdir().unwrap();
    let (url, _fake) = fake_target(router_with_a_bridge()).await;
    let router = plugin(&url, data.path(), "secret", 0o600);
    let preview = router.plan(plan_with_iot()).await.unwrap().unwrap();
    assert!(preview.steps.iter().all(|step| !step.description.contains("iot")));
}

#[test]
fn the_forwarding_table_keeps_learned_addresses() {
    let mut table = Vec::new();
    let mut entry = |mac: [u8; 6], port: u8, local: u8| {
        table.extend_from_slice(&mac);
        table.extend_from_slice(&[port, local, 0, 0, 0, 0, 0, 0, 0, 0]);
    };
    entry([0xaa, 0xbb, 0xcc, 0, 0, 1], 3, 0);
    entry([0xaa, 0xbb, 0xcc, 0, 0, 2], 3, 1);
    entry([0x33, 0x33, 0, 0, 0, 1], 3, 0);
    assert_eq!(forwarding_table(&table), [("aa:bb:cc:00:00:01".to_owned(), 3)]);
    assert_eq!(port_number("0x4\n"), Some(4));
    assert_eq!(port_number("none"), None);
    assert!(is_wifi("phy0-ap0"));
    assert!(!is_wifi("lan1"));
    let history = read_port_history("lan1 AA:BB:CC:00:00:01\nlan1 aa:bb:cc:00:00:01\nbroken\nlan2 x\n");
    assert_eq!(history.len(), 1);
    assert_eq!(history["lan1"].len(), 1);
}

#[test]
fn only_a_device_without_dhcp_and_entries_has_nothing_to_compare() {
    let serving = json!({ "values": { "lan": { ".type": "dhcp", "interface": "lan" } } });
    let not_serving = json!({ "values": { "lan": { ".type": "dhcp", "interface": "lan", "ignore": "1" } } });
    let station = Assigned {
        mac: "aa:bb:cc:00:00:01".to_owned(),
        vlan: Some(20),
        ..Assigned::default()
    };
    for (entries, dhcp, expected) in [
        (Vec::new(), &not_serving, None),
        (Vec::new(), &serving, Some(0)),
        (vec![station], &not_serving, Some(1)),
    ] {
        let mut observation = Observation {
            assigned: Some(entries),
            ..Observation::default()
        };
        drop_empty_entries(&mut observation, dhcp);
        assert_eq!(
            observation.assigned.map(|entries| entries.len()),
            expected,
            "{dhcp}"
        );
    }
}

#[tokio::test]
async fn a_scan_remembers_which_device_is_on_which_port() {
    let data = tempfile::tempdir().unwrap();
    let (url, _fake) = fake_target(router_with_a_bridge()).await;
    let router = managing(&url, data.path());
    let ports = data.path().join("router.ports");
    std::fs::write(&ports, "lan2 aa:bb:cc:00:00:09\n").unwrap();

    let observation = router.observe().await.unwrap();
    assert!(
        !observation
            .notes
            .iter()
            .any(|note| note.starts_with("Ports not read")),
        "{:?}",
        observation.notes
    );
    assert_eq!(
        std::fs::read_to_string(&ports).unwrap(),
        "lan1 aa:bb:cc:00:00:01\nlan2 aa:bb:cc:00:00:09\n",
        "the new port is added and the old one stays"
    );
}
