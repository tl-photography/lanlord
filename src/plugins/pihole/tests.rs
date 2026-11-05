//! Unit tests of `plugins/pihole`.

#![allow(clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

use super::*;
use crate::devices::Device;

const FINGERPRINT: &str =
    "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

fn device(name: &str, group: &str, ip: Option<[u8; 4]>) -> Device {
    Device {
        name: name.to_owned(),
        mac: format!("00:00:00:00:00:{:02x}", name.len()),
        group: group.to_owned(),
        ip: ip.map(Ipv4Addr::from),
        note: String::new(),
    }
}

fn entry(client: &str, comment: &str, groups: &[u64]) -> ClientEntry {
    ClientEntry {
        client: client.to_owned(),
        comment: comment.to_owned(),
        groups: groups.to_vec(),
    }
}

fn state(groups: &[(&str, u64)], clients: Vec<ClientEntry>) -> PiHoleState {
    PiHoleState {
        groups: groups
            .iter()
            .map(|(name, id)| ((*name).to_owned(), *id))
            .collect(),
        clients,
    }
}

fn details(plan: &Plan) -> Vec<String> {
    plan.changes
        .iter()
        .map(|change| change.operation.detail())
        .collect()
}

#[test]
fn groups_and_clients_are_added_for_devices_with_an_address() {
    let devices = DeviceList {
        devices: vec![
            device("tv", "iot", Some([192, 0, 2, 20])),
            device("plug", "iot", Some([192, 0, 2, 21])),
            device("phone", "guest", None),
        ],
    };
    let plan = plan(&devices, &state(&[("Default", 0)], Vec::new()));
    assert_eq!(
        details(&plan),
        [
            r#"POST /api/groups {"comment":"lanlord group","enabled":true,"name":"iot"}"#,
            r#"POST /api/clients {"client":"192.0.2.20","comment":"lanlord: tv","groups":["Default","iot"]}"#,
            r#"POST /api/clients {"client":"192.0.2.21","comment":"lanlord: plug","groups":["Default","iot"]}"#,
        ]
    );
    assert_eq!(plan.changes[1].description, "tv: client 192.0.2.20 in iot");
}

#[test]
fn own_clients_follow_the_device_and_others_are_left_alone() {
    let devices = DeviceList {
        devices: vec![
            device("tv", "lan", Some([192, 0, 2, 20])),
            device("nas", "lan", Some([192, 0, 2, 2])),
            device("same", "lan", Some([192, 0, 2, 3])),
        ],
    };
    let pihole = state(
        &[("Default", 0), ("lan", 1), ("iot", 2)],
        vec![
            entry("192.0.2.20", "lanlord: tv", &[0, 2]),
            entry("192.0.2.2", "my server", &[0]),
            entry("192.0.2.3", "lanlord: same", &[1, 0]),
            entry("192.0.2.99", "lanlord: old", &[0, 1]),
            entry("192.0.2.98", "kept", &[0]),
        ],
    );
    let plan = plan(&devices, &pihole);
    assert_eq!(
        details(&plan),
        [
            r#"PUT /api/clients/192.0.2.20 {"comment":"lanlord: tv","groups":["Default","lan"]}"#,
            "DELETE /api/clients/192.0.2.99",
        ]
    );
    assert_eq!(
        plan.changes[1].description,
        "Remove client 192.0.2.99 (old): no device with this address"
    );
    assert_eq!(
        plan.notes,
        ["nas is left out: Pi-hole already has client 192.0.2.2, not added by lanlord"]
    );
}

#[test]
fn group_ids_are_looked_up_by_name() {
    let groups: HashMap<String, u64> = [("iot".to_owned(), 4)].into();
    assert_eq!(
        group_ids(&["Default".to_owned(), "iot".to_owned()], &groups),
        Ok(vec![0, 4])
    );
    assert_eq!(group_ids(&["guest".to_owned()], &groups), Err("guest".to_owned()));
    assert_eq!(
        group_names(&[0, 4, 9], &groups),
        ["#0", "#9", "iot"].map(str::to_owned).into()
    );
}

#[test]
fn the_network_table_reports_devices_with_a_real_mac() {
    let devices = json!({ "devices": [
            { "hwaddr": "AA:BB:CC:00:00:01", "ips": [{ "ip": "192.0.2.10", "name": "phone.lan" }] },
            { "hwaddr": "ip-192.0.2.50", "ips": [{ "ip": "192.0.2.50", "name": "" }] },
            { "hwaddr": "aa:bb:cc:00:00:02", "ips": [] }
        ] });
    let observation = observation(&devices);
    assert_eq!(observation.entries, None);
    assert_eq!(observation.seen.len(), 2);
    assert_eq!(observation.seen[0].hostname, "phone.lan");
    assert_eq!(observation.seen[0].ip, Some(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(observation.seen[1].ip, None);
}

/// A Pi-hole like v6: one app password, sessions that must be ended, groups get ids on creation.
/// A new random password for each test, so no password is in the code.
fn random_password() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).unwrap();
    bytes.iter().fold(String::new(), |mut hex, byte| {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

#[derive(Default)]
struct Fake {
    password: String,
    groups: Vec<(String, u64)>,
    clients: Vec<Value>,
    sessions: usize,
    calls: Vec<String>,
    refuse_clients: bool,
}

async fn fake_pihole(fake: Fake) -> (String, Arc<Mutex<Fake>>) {
    use axum::extract::{Path as UrlPath, State};
    use axum::http::{HeaderMap, StatusCode as Status};
    use axum::routing::{delete, get, post};
    use axum::{Json, Router};

    type Shared = Arc<Mutex<Fake>>;
    fn authorized(headers: &HeaderMap) -> bool {
        headers.get("x-ftl-sid").is_some_and(|sid| sid == "sid-1")
    }
    let unauthorized = || {
        (
            Status::UNAUTHORIZED,
            Json(json!({ "error": { "message": "Unauthorized" } })),
        )
    };

    let shared = Arc::new(Mutex::new(fake));
    let router = Router::new()
            .route(
                "/api/auth",
                post(|State(fake): State<Shared>, Json(body): Json<Value>| async move {
                    let expected = fake.lock().unwrap().password.clone();
                    if body["password"] != expected.as_str() {
                        let refused = json!({ "session": { "valid": false, "message": "password incorrect" } });
                        return (Status::UNAUTHORIZED, Json(refused));
                    }
                    fake.lock().unwrap().sessions += 1;
                    (Status::OK, Json(json!({ "session": { "valid": true, "sid": "sid-1" } })))
                })
                .delete(|State(fake): State<Shared>| async move {
                    fake.lock().unwrap().sessions -= 1;
                    Status::NO_CONTENT
                }),
            )
            .route(
                "/api/groups",
                get(move |State(fake): State<Shared>, headers: HeaderMap| async move {
                    if !authorized(&headers) {
                        return unauthorized();
                    }
                    let groups: Vec<Value> = fake
                        .lock()
                        .unwrap()
                        .groups
                        .iter()
                        .map(|(name, id)| json!({ "name": name, "id": id }))
                        .collect();
                    (Status::OK, Json(json!({ "groups": groups })))
                })
                .post(|State(fake): State<Shared>, Json(body): Json<Value>| async move {
                    let mut fake = fake.lock().unwrap();
                    let id = u64::try_from(fake.groups.len()).unwrap();
                    fake.groups.push((body["name"].as_str().unwrap().to_owned(), id));
                    fake.calls.push(format!("add group {}", body["name"]));
                    Status::CREATED
                }),
            )
            .route(
                "/api/clients",
                get(|State(fake): State<Shared>| async move {
                    Json(json!({ "clients": fake.lock().unwrap().clients }))
                })
                .post(|State(fake): State<Shared>, Json(body): Json<Value>| async move {
                    let mut fake = fake.lock().unwrap();
                    if fake.refuse_clients {
                        return (Status::BAD_REQUEST, Json(json!({ "error": { "message": "Invalid client" } })));
                    }
                    fake.calls.push(format!("add client {} {}", body["client"], body["groups"]));
                    fake.clients.push(body);
                    (Status::CREATED, Json(json!({})))
                }),
            )
            .route(
                "/api/clients/{client}",
                delete(|State(fake): State<Shared>, UrlPath(client): UrlPath<String>| async move {
                    let mut fake = fake.lock().unwrap();
                    fake.clients.retain(|entry| entry["client"] != client.as_str());
                    fake.calls.push(format!("delete client {client}"));
                    Status::NO_CONTENT
                }),
            )
            .route(
                "/api/network/devices",
                get(|| async { Json(json!({ "devices": [{ "hwaddr": "aa:bb:cc:00:00:01", "ips": [{ "ip": "192.0.2.10", "name": "phone" }] }] })) }),
            )
            .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });
    (format!("http://127.0.0.1:{}", address.port()), shared)
}

fn plugin(url: &str, data: &Path, password: &str) -> PiHole {
    plugin_with(url, data, password, "")
}

fn plugin_with(url: &str, data: &Path, password: &str, extra: &str) -> PiHole {
    let path = data.join("pihole.password");
    std::fs::write(&path, password).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let table: toml::Table = toml::from_str(&format!(
        "url = \"{url}\"\npassword_file = \"pihole.password\"\ncertificate = \"{FINGERPRINT}\"\n{extra}"
    ))
    .unwrap();
    PiHole::new("pihole".to_owned(), table, data).unwrap()
}

fn devices() -> DeviceList {
    DeviceList {
        devices: vec![device("tv", "iot", Some([192, 0, 2, 20]))],
    }
}

fn with_old_client(password: &str) -> Fake {
    Fake {
        password: password.to_owned(),
        groups: vec![("Default".to_owned(), 0)],
        clients: vec![json!({ "client": "192.0.2.99", "comment": "lanlord: old", "groups": [0] })],
        ..Fake::default()
    }
}

#[tokio::test]
async fn applies_groups_then_clients_and_always_logs_out() {
    let data = tempfile::tempdir().unwrap();
    let password = random_password();
    let (url, fake) = fake_pihole(with_old_client(&password)).await;
    let pihole = plugin(&url, data.path(), &format!("{password}\n"));
    assert!(pihole.is_target());
    assert_eq!(pihole.kind(), "pihole");

    let preview = pihole.plan(devices()).await.unwrap().unwrap();
    assert_eq!(preview.steps.len(), 3);
    let applied = pihole.apply(devices(), preview.digest()).await.unwrap();
    assert_eq!(applied.len(), 3);
    {
        let fake = fake.lock().unwrap();
        assert_eq!(
            fake.calls,
            [
                r#"add group "iot""#,
                r#"add client "192.0.2.20" [0,1]"#,
                "delete client 192.0.2.99"
            ]
        );
        assert_eq!(fake.sessions, 0, "every session is ended");
    }
    assert_eq!(pihole.plan(devices()).await.unwrap().unwrap().steps, []);

    assert_eq!(
        pihole.observe().await.unwrap(),
        Observation::default(),
        "devices are only reported when switched on"
    );
    let reporting = plugin_with(&url, data.path(), &password, "report_devices = true\n");
    let seen = reporting.observe().await.unwrap().seen;
    assert_eq!(seen[0].hostname, "phone");
    assert_eq!(fake.lock().unwrap().sessions, 0);
}

#[tokio::test]
async fn stale_previews_wrong_passwords_and_refusals_are_reported() {
    let data = tempfile::tempdir().unwrap();
    let password = random_password();
    let (url, fake) = fake_pihole(with_old_client(&password)).await;
    let pihole = plugin(&url, data.path(), &password);
    let error = pihole.apply(devices(), "stale".to_owned()).await.unwrap_err();
    assert!(error.contains("changed since the preview"), "{error}");
    assert_eq!(fake.lock().unwrap().calls, Vec::<String>::new());

    let other = tempfile::tempdir().unwrap();
    let wrong = plugin(&url, other.path(), &random_password());
    let error = wrong.plan(devices()).await.unwrap_err();
    assert!(
        error.contains("HTTP 401: password incorrect, check the app password"),
        "{error}"
    );

    fake.lock().unwrap().refuse_clients = true;
    let digest = pihole.plan(devices()).await.unwrap().unwrap().digest();
    let error = pihole.apply(devices(), digest).await.unwrap_err();
    assert!(error.contains("HTTP 400: Invalid client"), "{error}");
    assert!(
        error.contains("made before: Add the Pi-hole group iot"),
        "{error}"
    );
    assert_eq!(fake.lock().unwrap().sessions, 0);
}

#[test]
fn plain_http_is_only_allowed_to_the_own_host() {
    let data = Path::new("/data");
    let build = |url: &str| {
        let table: toml::Table = toml::from_str(&format!(
            "url = \"{url}\"\npassword_file = \"pihole.password\"\ncertificate = \"{FINGERPRINT}\"\n"
        ))
        .unwrap();
        PiHole::new("pihole".to_owned(), table, data)
    };
    assert!(build("https://pi.hole").is_ok());
    assert!(build("http://pi.hole").is_err());
    assert!(build("http://127.0.0.1:8080").is_ok());
}
