//! Unit tests of `plugins/openwrt`.

#![allow(clippy::unwrap_used)]

use super::*;

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
    assert_eq!(observation.seen.len(), 2);
    assert_eq!(observation.seen[0].hostname, "phone");
    assert_eq!(observation.seen[1].hostname, "");
    let entries = observation.entries.unwrap();
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
    assert_eq!(
        result(&json!({ "result": [0, { "a": 1 }] })).unwrap(),
        json!({ "a": 1 })
    );
    assert_eq!(result(&json!({ "result": [0] })).unwrap(), json!({}));
    assert!(
        result(&json!({ "result": [6] }))
            .unwrap_err()
            .contains("rpcd ACL")
    );
    assert_eq!(result(&json!({ "result": [4] })).unwrap_err(), "not found");
    assert_eq!(result(&json!({ "result": [5] })).unwrap_err(), "no data");
    assert_eq!(result(&json!({ "result": [9] })).unwrap_err(), "ubus error 9");
    assert_eq!(
        result(&json!({ "error": { "code": -32002, "message": "Access denied" } })).unwrap_err(),
        "access denied"
    );
    assert!(result(&json!({})).is_err());
    assert!(result(&json!({ "result": [] })).is_err());
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
    let build = |url: &str| OpenWrt::new("router".to_owned(), settings_table(url), data);
    assert!(build("https://router.lan").is_ok());
    assert!(build("http://127.0.0.1:8080").is_ok());
    assert!(build("http://router.lan").is_err());
    assert!(build("ftp://router.lan").is_err());
    assert!(build("not a url").is_err());
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
                ("iwinfo", "info") => json!([0, { "ssid": "Home", "frequency": 5180 }]),
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
    assert_eq!(observation.seen[0].hostname, "phone");
    let entries = observation.entries.unwrap();
    assert_eq!(entries[0].name, "tv");
    assert_eq!(entries[0].vlan, None, "no wireless configuration on this device");
}

#[tokio::test]
async fn reads_station_vlans_of_an_access_point() {
    let data = tempfile::tempdir().unwrap();
    let stations = json!([0, { "values": { "cfg9": { "mac": "aa:bb:cc:00:00:02", "vid": "20" } } }]);
    let access_point = plugin(&fake_router(stations).await, data.path(), "secret", 0o600);
    let entries = access_point.observe().await.unwrap().entries.unwrap();
    assert_eq!(entries[0].vlan, Some(20));
}

#[tokio::test]
async fn login_and_permission_problems_are_reported() {
    let data = tempfile::tempdir().unwrap();
    let wrong = plugin(&fake_router(json!([4])).await, data.path(), "wrong", 0o600);
    assert!(
        wrong
            .observe()
            .await
            .unwrap_err()
            .contains("login as lanlord failed")
    );

    let denied = plugin(&fake_router(json!([6])).await, data.path(), "secret", 0o600);
    assert!(denied.observe().await.unwrap_err().contains("rpcd ACL"));

    let open = plugin(&fake_router(json!([4])).await, data.path(), "secret", 0o644);
    assert!(open.observe().await.unwrap_err().contains("mode 0600"));

    let empty = plugin(&fake_router(json!([4])).await, data.path(), " \n", 0o600);
    assert!(empty.observe().await.unwrap_err().contains("empty"));

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
    staged: Vec<(String, Value)>,
    snapshot: Option<serde_json::Map<String, Value>>,
    calls: Vec<String>,
    lose_changes: bool,
    deny: &'static str,
    serves_dhcp: bool,
}

impl FakeUci {
    fn answer(&mut self, method: &str, arguments: &Value) -> Value {
        match method {
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
                self.snapshot = Some(self.committed.clone());
                for (method, arguments) in std::mem::take(&mut self.staged) {
                    if !self.lose_changes {
                        self.commit(&method, &arguments);
                    }
                }
            }
            "confirm" => self.snapshot = None,
            "rollback" => self.committed = self.snapshot.take().unwrap_or_default(),
            "revert" => self.staged.clear(),
            _ => return json!([3]),
        }
        self.calls.push(method.to_owned());
        json!([0])
    }

    fn commit(&mut self, method: &str, arguments: &Value) {
        let values = arguments["values"].as_object().cloned().unwrap_or_default();
        match method {
            "add" => {
                let name = arguments["name"].as_str().unwrap().to_owned();
                let mut section = values;
                section.insert(".type".to_owned(), json!("host"));
                section.insert(".name".to_owned(), json!(name));
                self.committed.insert(name, Value::Object(section));
            }
            "set" => {
                let section = arguments["section"].as_str().unwrap();
                self.committed[section].as_object_mut().unwrap().extend(values);
            }
            _ => {
                self.committed.remove(arguments["section"].as_str().unwrap());
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
                "network.interface" => json!([0, { "interface": [
                        { "interface": "lan", "ipv4-address": [{ "address": "192.0.2.1", "mask": 24 }] },
                        { "interface": "wan", "ipv4-address": [{ "address": "198.51.100.2", "mask": 24 }] }
                    ] }]),
                "uci" => state.lock().unwrap().answer(method, &params[3]),
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
    let device = |name: &str, mac: &str, ip: [u8; 4]| crate::devices::Device {
        name: name.to_owned(),
        mac: mac.to_owned(),
        group: "lan".to_owned(),
        ip: Some(Ipv4Addr::from(ip)),
        note: String::new(),
    };
    DeviceList {
        devices: vec![
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

    let plan = router.plan(devices()).await.unwrap().unwrap();
    assert_eq!(plan.steps.len(), 2, "take over cfg01 as lanlord_omv");
    assert!(plan.notes[0].starts_with("plug waits"));

    assert_eq!(router.apply(devices(), plan.digest()).await.unwrap().len(), 2);
    {
        let fake = fake.lock().unwrap();
        assert_eq!(fake.calls, ["delete", "add", "apply", "confirm"]);
        assert!(fake.committed.contains_key("lanlord_omv"));
        assert!(!fake.committed.contains_key("cfg01"));
    }
    assert_eq!(router.plan(devices()).await.unwrap().unwrap().steps, []);
    assert_eq!(
        router.apply(devices(), Plan::default().digest()).await.unwrap(),
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn changes_that_differ_from_the_preview_are_not_applied() {
    let data = tempfile::tempdir().unwrap();
    let (url, fake) = fake_target(router_with_omv()).await;
    let router = plugin(&url, data.path(), "secret", 0o600);
    let error = router.apply(devices(), "stale".to_owned()).await.unwrap_err();
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
    let digest = router.plan(devices()).await.unwrap().unwrap().digest();
    let error = router.apply(devices(), digest).await.unwrap_err();
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
    let digest = router.plan(devices()).await.unwrap().unwrap().digest();
    let error = router.apply(devices(), digest).await.unwrap_err();
    assert!(error.contains("rpcd ACL"), "{error}");
    assert_eq!(fake.lock().unwrap().calls, ["delete", "revert"]);
}

#[tokio::test]
async fn an_access_point_without_dhcp_has_nothing_to_apply() {
    let data = tempfile::tempdir().unwrap();
    let (url, _) = fake_target(FakeUci::default()).await;
    let access_point = plugin(&url, data.path(), "secret", 0o600);
    assert_eq!(access_point.plan(devices()).await.unwrap(), None);
    let error = access_point.apply(devices(), String::new()).await.unwrap_err();
    assert!(error.contains("serves no DHCP"), "{error}");
}

#[tokio::test]
async fn wifi_clients_are_reported_with_their_access_point() {
    let data = tempfile::tempdir().unwrap();
    let url = fake_router_with_wifi(json!([4]), json!([0, { "devices": ["phy0-ap0"] }])).await;
    let observation = plugin(&url, data.path(), "secret", 0o600)
        .observe()
        .await
        .unwrap();
    assert_eq!(observation.wifi.len(), 2);
    assert_eq!(observation.wifi[0].access_point, "router: Home (5 GHz)");
    assert_eq!(observation.wifi[0].mac, "aa:bb:cc:00:00:01");
    assert_eq!(observation.wifi[1].signal, Some(-71));
    assert!(
        observation
            .seen
            .iter()
            .any(|seen| seen.mac == "aa:bb:cc:00:00:09" && seen.ip.is_none()),
        "a Wi-Fi client without a lease is seen"
    );
    assert_eq!(observation.seen.len(), 2, "the leased phone is not added twice");
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
    assert_eq!(observation.wifi, []);
    assert!(
        observation.notes[0].starts_with("Wi-Fi clients not read:"),
        "{:?}",
        observation.notes
    );
    assert!(observation.notes[0].contains("rpcd ACL"));
}

#[test]
fn bands_follow_the_frequency() {
    assert_eq!(
        access_point("ap", "phy1-ap0", &json!({ "ssid": "Home", "frequency": 2412 })),
        "ap: Home (2.4 GHz)"
    );
    assert_eq!(
        access_point("ap", "phy2-ap0", &json!({ "ssid": "Home", "frequency": 5955 })),
        "ap: Home (6 GHz)"
    );
    assert_eq!(access_point("ap", "phy0-ap0", &json!({})), "ap: phy0-ap0");
}
