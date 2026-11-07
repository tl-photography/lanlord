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
use crate::compare::{Observation, Present};
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
            optional: true,
        },
        Field {
            key: "device",
            label: "Device (optional, its fixed address is used when the address is empty)",
            kind: FieldKind::Interface,
            placeholder: "",
            optional: true,
        },
        Field {
            key: "password_file",
            label: "App password file",
            kind: FieldKind::DataFile,
            placeholder: "pihole.password",
            optional: false,
        },
        Field {
            key: "certificate",
            label: "Certificate fingerprint (SHA-256)",
            kind: FieldKind::Fingerprint,
            placeholder: "AB:CD:...",
            optional: false,
        },
        Field {
            key: "report_devices",
            label: "Report devices (only if Pi-hole sees real MAC addresses, not behind Docker NAT)",
            kind: FieldKind::Switch,
            placeholder: "",
            optional: false,
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
    #[serde(default)]
    report_devices: bool,
    /// Only used to fill an empty address and for the device page.
    #[serde(default, rename = "device")]
    _device: String,
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
        .interfaces
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
    /// Whether the network table is reported; behind Docker NAT it only holds virtual interfaces.
    report_devices: bool,
}

impl PiHole {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let Settings {
            url,
            password_file,
            certificate,
            report_devices,
            ..
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
            report_devices,
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
            .or_else(|| answer.pointer("/session/message"))
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
        if !self.report_devices {
            return Ok(Observation::default());
        }
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
            Some(Present {
                mac,
                ip: first
                    .get("ip")
                    .and_then(Value::as_str)
                    .and_then(|ip| ip.parse().ok()),
                hostname: text(&first, "name"),
            })
        })
        .collect();
    Observation {
        present: seen,
        ..Observation::default()
    }
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
mod tests;
