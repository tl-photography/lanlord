//! Plugin `pihole`: Pi-hole v6 through its REST API.
//!
//! As target, every lanlord group becomes a Pi-hole group, and every device with a fixed address becomes a Pi-hole
//! client in the `Default` group and its own group, so blocklists can follow the groups. lanlord owns the clients
//! whose comment starts with `lanlord: ` and leaves all others alone; groups are only added, never deleted, because
//! they may carry blocklist assignments. As source, Pi-hole's network table reports the devices it has seen.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use reqwest::{Client, Method, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};

use super::openwrt::{MAX_RESPONSE_BYTES, client, parse_fingerprint, read_password, secure_url};
use super::{BoxFuture, Field, FieldKind, Plugin, PluginType, settings};
use crate::compare::{Observation, Seen};
use crate::devices::{DeviceList, Error, normalize_mac};
use crate::preview::{Preview, Step};

/// Start of the comment of the clients lanlord owns.
const OWN_COMMENT: &str = "lanlord: ";
/// Comment of the groups lanlord adds.
const GROUP_COMMENT: &str = "lanlord group";
/// Pi-hole's built-in group, id 0; every client lanlord adds stays in it.
const DEFAULT_GROUP: &str = "Default";

/// The type description for `lanlord.toml` and the web interface.
pub(super) const TYPE: PluginType = PluginType {
    kind: "pihole",
    title: "Pi-hole",
    description: "Puts every device with a fixed address into a Pi-hole group named after its lanlord group, so \
                  blocklists follow the groups, and reports the devices in Pi-hole's network table. Uses the \
                  REST API of Pi-hole v6 with an app password.",
    fields: &[
        Field {
            key: "url",
            label: "Address",
            kind: FieldKind::Url,
            placeholder: "https://pi.hole",
        },
        Field {
            key: "password_file",
            label: "App password file",
            kind: FieldKind::DataFile,
            placeholder: "pihole.password",
        },
        Field {
            key: "certificate",
            label: "Certificate fingerprint (SHA-256)",
            kind: FieldKind::Fingerprint,
            placeholder: "AB:CD:...",
        },
    ],
    build: |name, table, data_dir| Ok(Arc::new(PiHole::new(name, table, data_dir)?)),
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    url: String,
    password_file: String,
    certificate: String,
}

/// A client entry of Pi-hole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientEntry {
    /// IP address, subnet, MAC address or host name.
    pub client: String,
    /// Comment; lanlord's own start with `lanlord: `.
    pub comment: String,
    /// Group ids.
    pub groups: Vec<u64>,
}

/// The groups and clients of Pi-hole.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PiHoleState {
    /// Group ids by name.
    pub groups: HashMap<String, u64>,
    /// All clients.
    pub clients: Vec<ClientEntry>,
}

/// One change, with group names; the ids are looked up when it is made.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Operation {
    AddGroup {
        name: String,
    },
    AddClient {
        client: String,
        comment: String,
        groups: Vec<String>,
    },
    SetClient {
        client: String,
        comment: String,
        groups: Vec<String>,
    },
    DeleteClient {
        client: String,
    },
}

impl Operation {
    fn detail(&self) -> String {
        match self {
            Self::AddGroup { name } => format!(
                "POST /api/groups {}",
                json!({ "name": name, "comment": GROUP_COMMENT, "enabled": true })
            ),
            Self::AddClient {
                client,
                comment,
                groups,
            } => format!(
                "POST /api/clients {}",
                json!({ "client": client, "comment": comment, "groups": groups })
            ),
            Self::SetClient {
                client,
                comment,
                groups,
            } => format!(
                "PUT /api/clients/{client} {}",
                json!({ "comment": comment, "groups": groups })
            ),
            Self::DeleteClient { client } => format!("DELETE /api/clients/{client}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Planned {
    operation: Operation,
    description: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    changes: Vec<Planned>,
    notes: Vec<String>,
}

impl Plan {
    fn preview(&self) -> Preview {
        Preview {
            steps: self
                .changes
                .iter()
                .map(|change| Step {
                    description: change.description.clone(),
                    details: vec![change.operation.detail()],
                })
                .collect(),
            notes: self.notes.clone(),
        }
    }
}

fn group_names(ids: &[u64], groups: &HashMap<String, u64>) -> BTreeSet<String> {
    ids.iter()
        .map(|id| {
            groups
                .iter()
                .find(|(_, group_id)| *group_id == id)
                .map_or_else(|| format!("#{id}"), |(name, _)| name.clone())
        })
        .collect()
}

/// Plans the groups and clients: missing groups first, then the clients of the devices with a fixed address, then
/// the removal of own clients that no device needs any more.
fn plan(devices: &DeviceList, state: &PiHoleState) -> Plan {
    let mut plan = Plan::default();
    let with_address: Vec<_> = devices
        .devices
        .iter()
        .filter(|device| device.ip.is_some())
        .collect();

    let mut added_groups = BTreeSet::new();
    for device in &with_address {
        if !state.groups.contains_key(&device.group) && added_groups.insert(device.group.clone()) {
            plan.changes.push(Planned {
                operation: Operation::AddGroup {
                    name: device.group.clone(),
                },
                description: format!("Add the Pi-hole group {}", device.group),
            });
        }
    }

    let mut wanted_clients = BTreeSet::new();
    for device in &with_address {
        let Some(ip) = device.ip else { continue };
        let client = ip.to_string();
        let comment = format!("{OWN_COMMENT}{}", device.name);
        let groups: BTreeSet<String> = [DEFAULT_GROUP.to_owned(), device.group.clone()].into();
        let group_list: Vec<String> = groups.iter().cloned().collect();
        match state.clients.iter().find(|entry| entry.client == client) {
            None => plan.changes.push(Planned {
                operation: Operation::AddClient {
                    client: client.clone(),
                    comment,
                    groups: group_list,
                },
                description: format!("{}: client {client} in {}", device.name, device.group),
            }),
            Some(entry) if !entry.comment.starts_with(OWN_COMMENT) => {
                plan.notes.push(format!(
                    "{} is left out: Pi-hole already has client {client}, not added by lanlord",
                    device.name
                ));
            }
            Some(entry) => {
                if entry.comment != comment || group_names(&entry.groups, &state.groups) != groups {
                    plan.changes.push(Planned {
                        operation: Operation::SetClient {
                            client: client.clone(),
                            comment,
                            groups: group_list,
                        },
                        description: format!("{}: client {client} now in {}", device.name, device.group),
                    });
                }
            }
        }
        wanted_clients.insert(client);
    }

    for entry in &state.clients {
        if entry.comment.starts_with(OWN_COMMENT) && !wanted_clients.contains(&entry.client) {
            plan.changes.push(Planned {
                operation: Operation::DeleteClient {
                    client: entry.client.clone(),
                },
                description: format!(
                    "Remove client {} ({}): no device with this address",
                    entry.client,
                    entry.comment.trim_start_matches(OWN_COMMENT)
                ),
            });
        }
    }
    plan
}

/// One Pi-hole.
pub struct PiHole {
    name: String,
    api: Url,
    password_file: PathBuf,
    client: Client,
}

impl PiHole {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let Settings {
            url,
            password_file,
            certificate,
        } = settings(&name, table)?;
        let invalid = |message: &str| Error::Invalid(format!("{name}: {message}"));
        let mut api = secure_url(&name, &url)?;
        api.set_path("/api/");
        api.set_query(None);
        let fingerprint =
            parse_fingerprint(&certificate).ok_or_else(|| invalid("invalid certificate fingerprint"))?;
        let client = client(fingerprint).map_err(|error| invalid(&error))?;
        Ok(Self {
            name,
            api,
            password_file: data_dir.join(password_file),
            client,
        })
    }

    /// Sends one request and returns the answer, or the error as text.
    async fn request(
        &self,
        method: Method,
        path: &str,
        session: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        let url = self
            .api
            .join(path)
            .map_err(|_| format!("{}: invalid path {path}", self.name))?;
        let mut request = self.client.request(method.clone(), url);
        if let Some(session) = session {
            request = request.header("X-FTL-SID", session);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| format!("{}: {error}", self.name))?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("{}: {error}", self.name))?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(format!("{}: answer is larger than 1 MiB", self.name));
            }
            bytes.extend_from_slice(&chunk);
        }
        let answer: Value = if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&bytes).map_err(|_| format!("{}: answer is not JSON", self.name))?
        };
        if status.is_success() {
            return Ok(answer);
        }
        let message = answer
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("no details");
        let hint = if status == StatusCode::UNAUTHORIZED {
            ", check the app password"
        } else {
            ""
        };
        Err(format!(
            "{}: {method} /api/{path}: HTTP {}: {message}{hint}",
            self.name,
            status.as_u16()
        ))
    }

    async fn login(&self) -> Result<String, String> {
        let password = read_password(&self.password_file).await?;
        let answer = self
            .request(Method::POST, "auth", None, Some(&json!({ "password": password })))
            .await?;
        let session = answer.get("session").cloned().unwrap_or_default();
        if session.get("valid").and_then(Value::as_bool) != Some(true) {
            return Err(format!("{}: login failed, check the app password", self.name));
        }
        session
            .get("sid")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("{}: login answer has no session", self.name))
    }

    /// Ends the session: Pi-hole allows only a few at the same time.
    async fn logout(&self, session: &str) {
        let _ = self.request(Method::DELETE, "auth", Some(session), None).await;
    }

    async fn state(&self, session: &str) -> Result<PiHoleState, String> {
        let groups = self.request(Method::GET, "groups", Some(session), None).await?;
        let clients = self.request(Method::GET, "clients", Some(session), None).await?;
        Ok(parse_state(&groups, &clients))
    }

    async fn read(&self) -> Result<Observation, String> {
        let session = self.login().await?;
        let devices = self
            .request(Method::GET, "network/devices", Some(&session), None)
            .await;
        self.logout(&session).await;
        Ok(observation(&devices?))
    }

    async fn preview(&self, devices: DeviceList) -> Result<Option<Preview>, String> {
        let session = self.login().await?;
        let state = self.state(&session).await;
        self.logout(&session).await;
        Ok(Some(plan(&devices, &state?).preview()))
    }

    async fn write(&self, devices: DeviceList, digest: String) -> Result<Vec<String>, String> {
        let session = self.login().await?;
        let result = self.write_in(&session, &devices, &digest).await;
        self.logout(&session).await;
        result
    }

    /// Makes the changes in order: groups first, then the clients with the group ids Pi-hole gave them. Pi-hole has
    /// no rollback; lanlord reads it again afterwards and reports what is missing.
    async fn write_in(
        &self,
        session: &str,
        devices: &DeviceList,
        digest: &str,
    ) -> Result<Vec<String>, String> {
        let plan = plan(devices, &self.state(session).await?);
        if plan.preview().digest() != digest {
            return Err(format!(
                "{}: Pi-hole or the list changed since the preview, check the changes again",
                self.name
            ));
        }
        let mut done = Vec::new();
        let mut groups: Option<HashMap<String, u64>> = None;
        for change in &plan.changes {
            let failed = |error: String| {
                if done.is_empty() {
                    error
                } else {
                    format!("{error}; made before: {}", done.join("; "))
                }
            };
            let (method, path, body) = match &change.operation {
                Operation::AddGroup { name } => (
                    Method::POST,
                    "groups".to_owned(),
                    Some(json!({ "name": name, "comment": GROUP_COMMENT, "enabled": true })),
                ),
                Operation::AddClient {
                    client,
                    comment,
                    groups: names,
                }
                | Operation::SetClient {
                    client,
                    comment,
                    groups: names,
                } => {
                    if groups.is_none() {
                        groups = Some(self.state(session).await.map_err(failed)?.groups);
                    }
                    let ids = group_ids(names, groups.as_ref().unwrap_or(&HashMap::new()))
                        .map_err(|name| failed(format!("{}: Pi-hole has no group {name}", self.name)))?;
                    let body = json!({ "client": client, "comment": comment, "groups": ids });
                    if matches!(change.operation, Operation::AddClient { .. }) {
                        (Method::POST, "clients".to_owned(), Some(body))
                    } else {
                        (Method::PUT, format!("clients/{client}"), Some(body))
                    }
                }
                Operation::DeleteClient { client } => (Method::DELETE, format!("clients/{client}"), None),
            };
            self.request(method, &path, Some(session), body.as_ref())
                .await
                .map_err(failed)?;
            done.push(change.description.clone());
        }
        let left = plan_left(devices, &self.state(session).await?);
        if left > 0 {
            return Err(format!(
                "{}: {left} changes are still missing after applying; made: {}",
                self.name,
                done.join("; ")
            ));
        }
        Ok(done)
    }
}

fn plan_left(devices: &DeviceList, state: &PiHoleState) -> usize {
    plan(devices, state).changes.len()
}

/// The ids of group names, or the first name Pi-hole does not have.
fn group_ids(names: &[String], groups: &HashMap<String, u64>) -> Result<Vec<u64>, String> {
    names
        .iter()
        .map(|name| {
            if name == DEFAULT_GROUP {
                return Ok(groups.get(name).copied().unwrap_or(0));
            }
            groups.get(name).copied().ok_or_else(|| name.clone())
        })
        .collect()
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn parse_state(groups: &Value, clients: &Value) -> PiHoleState {
    let list = |value: &Value, key: &str| -> Vec<Value> {
        value
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    PiHoleState {
        groups: list(groups, "groups")
            .iter()
            .filter_map(|group| Some((text(group, "name"), group.get("id")?.as_u64()?)))
            .collect(),
        clients: list(clients, "clients")
            .iter()
            .map(|client| ClientEntry {
                client: text(client, "client"),
                comment: text(client, "comment"),
                groups: client
                    .get("groups")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_u64)
                    .collect(),
            })
            .collect(),
    }
}

/// The devices of the network table; routed devices without a real MAC address are left out.
fn observation(devices: &Value) -> Observation {
    let seen = devices
        .get("devices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|device| {
            let mac = normalize_mac(device.get("hwaddr")?.as_str()?)?;
            let first = device
                .get("ips")
                .and_then(Value::as_array)
                .and_then(|ips| ips.first())
                .cloned()
                .unwrap_or_default();
            Some(Seen {
                mac,
                ip: first
                    .get("ip")
                    .and_then(Value::as_str)
                    .and_then(|ip| ip.parse().ok()),
                hostname: text(&first, "name"),
            })
        })
        .collect();
    Observation { seen, entries: None }
}

impl Plugin for PiHole {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "pihole"
    }

    fn observe(&self) -> BoxFuture<'_, Result<Observation, String>> {
        Box::pin(self.read())
    }

    fn is_target(&self) -> bool {
        true
    }

    fn plan(&self, devices: DeviceList) -> BoxFuture<'_, Result<Option<Preview>, String>> {
        Box::pin(self.preview(devices))
    }

    fn apply(&self, devices: DeviceList, digest: String) -> BoxFuture<'_, Result<Vec<String>, String>> {
        Box::pin(self.write(devices, digest))
    }
}

#[cfg(test)]
mod tests {
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
    #[derive(Default)]
    struct Fake {
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
                    if body["password"] != "app-password" {
                        return Json(json!({ "session": { "valid": false } }));
                    }
                    fake.lock().unwrap().sessions += 1;
                    Json(json!({ "session": { "valid": true, "sid": "sid-1" } }))
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
        let path = data.join("pihole.password");
        std::fs::write(&path, password).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let table: toml::Table = toml::from_str(&format!(
            "url = \"{url}\"\npassword_file = \"pihole.password\"\ncertificate = \"{FINGERPRINT}\"\n"
        ))
        .unwrap();
        PiHole::new("pihole".to_owned(), table, data).unwrap()
    }

    fn devices() -> DeviceList {
        DeviceList {
            devices: vec![device("tv", "iot", Some([192, 0, 2, 20]))],
        }
    }

    fn with_old_client() -> Fake {
        Fake {
            groups: vec![("Default".to_owned(), 0)],
            clients: vec![json!({ "client": "192.0.2.99", "comment": "lanlord: old", "groups": [0] })],
            ..Fake::default()
        }
    }

    #[tokio::test]
    async fn applies_groups_then_clients_and_always_logs_out() {
        let data = tempfile::tempdir().unwrap();
        let (url, fake) = fake_pihole(with_old_client()).await;
        let pihole = plugin(&url, data.path(), "app-password\n");
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

        let seen = pihole.observe().await.unwrap().seen;
        assert_eq!(seen[0].hostname, "phone");
        assert_eq!(fake.lock().unwrap().sessions, 0);
    }

    #[tokio::test]
    async fn stale_previews_wrong_passwords_and_refusals_are_reported() {
        let data = tempfile::tempdir().unwrap();
        let (url, fake) = fake_pihole(with_old_client()).await;
        let pihole = plugin(&url, data.path(), "app-password");
        let error = pihole.apply(devices(), "stale".to_owned()).await.unwrap_err();
        assert!(error.contains("changed since the preview"), "{error}");
        assert_eq!(fake.lock().unwrap().calls, Vec::<String>::new());

        let other = tempfile::tempdir().unwrap();
        let wrong = plugin(&url, other.path(), "wrong");
        assert!(
            wrong
                .plan(devices())
                .await
                .unwrap_err()
                .contains("check the app password")
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
}
