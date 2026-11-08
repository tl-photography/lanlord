//! Plugin `openwrt`: reads an `OpenWrt` router or access point through its ubus JSON-RPC API, the API `LuCI` uses.
//! lanlord logs in as its own rpcd user, whose rights an ACL on the device limits, and trusts only the pinned TLS
//! certificate of the device.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::{Client, Url};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{BoxFuture, Field, FieldKind, Plugin, PluginType, settings};
use crate::compare::{Assigned, Observation, Present};
use crate::devices::{Error, normalize_mac};
use crate::leases::{self, Change, HostSection, LeasePlan, NameSection, Network};
use crate::networks;
use crate::plan::Plan;
use crate::preview::Preview;

/// Static leases, DNS names and served networks of a device.
type LeaseState = (
    Vec<HostSection>,
    Vec<NameSection>,
    Vec<Network>,
    HashMap<String, Ipv4Addr>,
);

/// Longest time for one request to the device.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest answer that is read.
pub(super) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Lifetime of the rpcd session in seconds; one scan needs only a few.
const SESSION_TIMEOUT: u64 = 60;
/// Session id for the login call.
const NO_SESSION: &str = "00000000000000000000000000000000";
/// The bridge whose ports are read.
const BRIDGE: &str = "br-lan";
/// Size of one entry in the kernel's forwarding table of a bridge.
const FDB_ENTRY_BYTES: usize = 16;
/// Seconds after which the router undoes applied changes that lanlord has not confirmed.
const ROLLBACK_SECONDS: u64 = 30;
/// The same for changes of the networks: the device reloads its network before lanlord can read it again.
const NETWORK_ROLLBACK_SECONDS: u64 = 60;
/// Tries to read the device again after applying, and the pause between them.
const READ_BACK_TRIES: u32 = 10;
const READ_BACK_PAUSE: Duration = Duration::from_secs(3);

/// The type description for `lanlord.toml` and the web interface.
pub(super) const TYPE: PluginType = PluginType {
    kind: "openwrt",
    title: "OpenWrt",
    description: "Reads the DHCP leases, static leases and Wi-Fi VLANs of an OpenWrt router or access point \
                  through its ubus API, as its own rpcd user, and applies the static leases of a router that serves \
                  DHCP. With Manage networks on, it also builds a network per group.",
    fields: &[
        Field {
            key: "url",
            label: "Address",
            kind: FieldKind::Url,
            placeholder: "https://router.lan",
            optional: true,
        },
        Field {
            key: "device",
            label: "Device (optional, its fixed address is used when the address is empty)",
            kind: FieldKind::Device,
            placeholder: "",
            optional: true,
        },
        Field {
            key: "user",
            label: "rpcd user",
            kind: FieldKind::Word,
            placeholder: "lanlord",
            optional: false,
        },
        Field {
            key: "password_file",
            label: "Password file",
            kind: FieldKind::DataFile,
            placeholder: "router.password",
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
            key: "manage_networks",
            label: "Manage networks: a VLAN, interface, DHCP pool, firewall zone and Wi-Fi per group (needs rights for \
                    network, firewall and wireless)",
            kind: FieldKind::Switch,
            placeholder: "",
            optional: true,
        },
    ],
    build: |name, table, data_dir| Ok(Arc::new(OpenWrt::new(name, table, data_dir)?)),
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    url: String,
    user: String,
    password_file: String,
    certificate: String,
    #[serde(default)]
    manage_networks: bool,
    /// Only used to fill an empty address and for the device page.
    #[serde(default, rename = "device")]
    _device: String,
}

/// What a device gets: its static leases if it serves DHCP, and its networks if the plugin manages them.
struct DevicePlan {
    leases: Option<LeasePlan>,
    networks: Option<networks::NetworkPlan>,
}

impl DevicePlan {
    fn preview(&self) -> Option<Preview> {
        if self.leases.is_none() && self.networks.is_none() {
            return None;
        }
        let mut preview = self.leases.as_ref().map(LeasePlan::preview).unwrap_or_default();
        if let Some(network_plan) = &self.networks {
            preview.steps.extend(network_plan.steps());
            preview.notes.extend(network_plan.notes.iter().cloned());
        }
        Some(preview)
    }

    fn is_empty(&self) -> bool {
        self.leases
            .as_ref()
            .is_none_or(|lease_plan| lease_plan.changes.is_empty())
            && self
                .networks
                .as_ref()
                .is_none_or(|network_plan| network_plan.changes.is_empty())
    }
}

/// One `OpenWrt` device.
pub struct OpenWrt {
    name: String,
    endpoint: Url,
    user: String,
    password_file: PathBuf,
    client: Client,
    /// Whether the plugin builds the networks of the groups.
    manage_networks: bool,
    /// The data directory, for the Wi-Fi passwords of the groups.
    data_dir: PathBuf,
}

impl OpenWrt {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let Settings {
            url,
            user,
            password_file,
            certificate,
            manage_networks,
            ..
        } = settings(&name, table)?;
        let invalid = |message: &str| Error::Invalid(format!("{name}: {message}"));
        let mut endpoint = secure_url(&name, &url)?;
        endpoint.set_path("/ubus");
        endpoint.set_query(None);
        let fingerprint =
            parse_fingerprint(&certificate).ok_or_else(|| invalid("invalid certificate fingerprint"))?;
        let client = client(fingerprint).map_err(|error| invalid(&error))?;
        Ok(Self {
            name,
            endpoint,
            user,
            password_file: data_dir.join(password_file),
            client,
            manage_networks,
            data_dir: data_dir.to_path_buf(),
        })
    }

    async fn read(&self) -> Result<Observation, String> {
        let password = read_password(&self.password_file).await?;
        let session = self.login(&password).await?;
        let leases = self
            .call(&session, "luci-rpc", "getDHCPLeases", &json!({}))
            .await?;
        let hosts = self
            .call(
                &session,
                "uci",
                "get",
                &json!({ "config": "dhcp", "type": "host" }),
            )
            .await?;
        // Devices without Wi-Fi have no wireless configuration.
        let stations = match self
            .call(
                &session,
                "uci",
                "get",
                &json!({ "config": "wireless", "type": "wifi-station" }),
            )
            .await
        {
            Ok(stations) => stations,
            Err(error) if error.ends_with("not found") || error.ends_with("no data") => json!({}),
            Err(error) => return Err(error),
        };
        let dhcp = self
            .call(&session, "uci", "get", &json!({ "config": leases::CONFIG }))
            .await?;
        let mut observation = observation(&leases, &hosts, &stations);
        drop_empty_entries(&mut observation, &dhcp);
        match self.wifi_clients(&session).await {
            Ok(clients) => add_wifi(&mut observation, clients),
            // No Wi-Fi hardware, no iwinfo.
            Err(error) if error.ends_with("not found") => {}
            Err(error) => observation.notes.push(format!("Wi-Fi clients not read: {error}")),
        }
        if self.manage_networks
            && let Err(error) = self.learn_ports(&session).await
        {
            observation.notes.push(format!("Ports not read: {error}"));
        }
        Ok(observation)
    }

    /// The file with every MAC address ever seen per bridge port.
    fn ports_path(&self) -> PathBuf {
        self.data_dir.join(format!("{}.ports", self.name))
    }

    /// Reads the bridge table, adds it to the port history and returns the history.
    async fn learn_ports(&self, session: &str) -> Result<PortHistory, String> {
        let learned = self.bridge_ports(session).await?;
        let path = self.ports_path();
        let mut history = read_port_history(&tokio::fs::read_to_string(&path).await.unwrap_or_default());
        let before = history.clone();
        for (port, mac) in learned {
            history.entry(port).or_default().insert(mac);
        }
        if history != before {
            let text: String = history
                .iter()
                .flat_map(|(port, macs)| macs.iter().map(move |mac| format!("{port} {mac}\n")))
                .collect();
            crate::devices::write_private(&path, &text)
                .map_err(|error| format!("{}: {error}", path.display()))?;
        }
        Ok(history)
    }

    /// The MAC addresses the bridge learned on its cabled ports, with the port.
    async fn bridge_ports(&self, session: &str) -> Result<Vec<(String, String)>, String> {
        let status = self
            .call(session, "network.device", "status", &json!({ "name": BRIDGE }))
            .await?;
        let mut ports = HashMap::new();
        for member in status
            .get("bridge-members")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|member| !is_wifi(member))
        {
            let path = format!("/sys/class/net/{BRIDGE}/brif/{member}/port_no");
            let answer = self
                .call(session, "file", "read", &json!({ "path": path }))
                .await?;
            if let Some(number) = answer.get("data").and_then(Value::as_str).and_then(port_number) {
                ports.insert(number, member.to_owned());
            }
        }
        let path = format!("/sys/class/net/{BRIDGE}/brforward");
        let table = self
            .call(session, "file", "read", &json!({ "path": path, "base64": true }))
            .await?;
        let data = table.get("data").and_then(Value::as_str).unwrap_or_default();
        let bytes = BASE64.decode(data).map_err(|error| error.to_string())?;
        Ok(forwarding_table(&bytes)
            .into_iter()
            .filter_map(|(mac, number)| Some((ports.get(&number)?.clone(), mac)))
            .collect())
    }

    /// The devices connected to each Wi-Fi interface of the device.
    async fn wifi_clients(&self, session: &str) -> Result<Vec<String>, String> {
        let devices = self.call(session, "iwinfo", "devices", &json!({})).await?;
        let mut clients = Vec::new();
        for device in devices
            .get("devices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let arguments = json!({ "device": device });
            let associated = self.call(session, "iwinfo", "assoclist", &arguments).await?;
            clients.extend(wifi(&associated));
        }
        Ok(clients)
    }

    /// The static leases and the networks the device serves with DHCP. A device without a DHCP pool, like an access
    /// point, is not asked for its interfaces: its ACL does not need to allow that.
    async fn lease_state(&self, session: &str) -> Result<LeaseState, String> {
        let dhcp = self
            .call(session, "uci", "get", &json!({ "config": leases::CONFIG }))
            .await?;
        let served = served_interfaces(&dhcp);
        if served.is_empty() {
            return Ok((
                host_sections(&dhcp),
                name_sections(&dhcp),
                Vec::new(),
                HashMap::new(),
            ));
        }
        let dump = self
            .call(session, "network.interface", "dump", &json!({}))
            .await?;
        let leases = self
            .call(session, "luci-rpc", "getDHCPLeases", &json!({}))
            .await?;
        Ok((
            host_sections(&dhcp),
            name_sections(&dhcp),
            served_networks(&served, &dump),
            held_addresses(&leases),
        ))
    }

    /// The sections of the configurations the networks touch.
    async fn network_state(&self, session: &str) -> Result<Vec<networks::Section>, String> {
        let mut current = Vec::new();
        for config in networks::CONFIGS {
            match self
                .call(session, "uci", "get", &json!({ "config": config }))
                .await
            {
                Ok(answer) => current.extend(networks::sections(config, &answer)),
                Err(error) if error.ends_with("not found") || error.ends_with("no data") => {}
                Err(error) => return Err(format!("{config}: {error}")),
            }
        }
        Ok(current)
    }

    /// The Wi-Fi passwords of the groups with an SSID of their own, by group; unreadable files are left out.
    async fn wifi_passwords(&self, plan: &Plan) -> HashMap<String, String> {
        let mut passwords = HashMap::new();
        for group in plan.groups.iter().filter(|group| !group.ssid.is_empty()) {
            if let Ok(password) = read_password(&self.data_dir.join(&group.ssid_password_file)).await {
                passwords.insert(group.name.clone(), password);
            }
        }
        passwords
    }

    async fn plan_in(&self, session: &str, plan: &Plan) -> Result<DevicePlan, String> {
        let (hosts, names, served, held) = self.lease_state(session).await?;
        let leases = (!served.is_empty()).then(|| {
            let mut lease_plan = leases::plan(&plan.devices, &hosts, &served, &held);
            leases::plan_names(&plan.devices, &names, &served, &mut lease_plan);
            lease_plan
        });
        let networks = if self.manage_networks {
            let current = self.network_state(session).await?;
            let role = if served.is_empty() {
                networks::Role::AccessPoint
            } else {
                networks::Role::Router
            };
            let ports = match self.learn_ports(session).await {
                Ok(ports) => ports,
                Err(error) => {
                    tracing::warn!("{}: ports not read: {error}", self.name);
                    std::collections::BTreeMap::new()
                }
            };
            Some(networks::plan(
                plan,
                &current,
                role,
                &self.wifi_passwords(plan).await,
                &ports,
            ))
        } else {
            None
        };
        Ok(DevicePlan { leases, networks })
    }

    async fn preview(&self, plan: Plan) -> Result<Option<Preview>, String> {
        let password = read_password(&self.password_file).await?;
        let session = self.login(&password).await?;
        Ok(self.plan_in(&session, &plan).await?.preview())
    }

    /// Reads the device again after applying. While it reloads its network it may not answer for a moment.
    async fn read_back(&self, session: &str, plan: &Plan) -> Result<DevicePlan, String> {
        let mut last = String::new();
        for _ in 0..READ_BACK_TRIES {
            match self.plan_in(session, plan).await {
                Ok(left) => return Ok(left),
                Err(error) => last = error,
            }
            tokio::time::sleep(READ_BACK_PAUSE).await;
        }
        Err(last)
    }

    async fn revert(&self, session: &str) {
        for config in std::iter::once(leases::CONFIG).chain(networks::CONFIGS) {
            let _ = self
                .call(session, "uci", "revert", &json!({ "config": config }))
                .await;
        }
    }

    /// Stages the changes, applies them with rollback, reads the device again and confirms only if nothing is
    /// left to change. Without the confirmation, the device undoes the changes after [`ROLLBACK_SECONDS`], or
    /// [`NETWORK_ROLLBACK_SECONDS`] for networks.
    async fn write(&self, plan: Plan, digest: String) -> Result<Vec<String>, String> {
        let password = read_password(&self.password_file).await?;
        let session = self.login(&password).await?;
        let planned = self.plan_in(&session, &plan).await?;
        let preview = planned
            .preview()
            .ok_or_else(|| format!("{}: serves no DHCP, there is nothing to apply", self.name))?;
        if preview.digest() != digest {
            return Err(format!(
                "{}: the device or the list changed since the preview, check the changes again",
                self.name
            ));
        }
        if planned.is_empty() {
            return Ok(Vec::new());
        }
        let lease_changes = planned
            .leases
            .as_ref()
            .map_or(&[][..], |lease_plan| &lease_plan.changes[..]);
        let network_changes = planned
            .networks
            .as_ref()
            .map_or(&[][..], |network_plan| &network_plan.changes[..]);
        for change in lease_changes {
            if let Err(error) = self.stage(&session, change).await {
                self.revert(&session).await;
                return Err(error);
            }
        }
        for change in network_changes {
            if let Err(error) = self.stage_network(&session, change).await {
                self.revert(&session).await;
                return Err(error);
            }
        }
        let timeout = if network_changes.is_empty() {
            ROLLBACK_SECONDS
        } else {
            NETWORK_ROLLBACK_SECONDS
        };
        self.call(
            &session,
            "uci",
            "apply",
            &json!({ "rollback": true, "timeout": timeout }),
        )
        .await?;
        let left = self.read_back(&session, &plan).await;
        if !matches!(&left, Ok(after) if after.is_empty()) {
            let _ = self.call(&session, "uci", "rollback", &json!({})).await;
            return Err(format!(
                "{}: the device does not show the changes after applying, they were rolled back",
                self.name
            ));
        }
        self.call(&session, "uci", "confirm", &json!({})).await?;
        Ok(preview.steps.into_iter().map(|step| step.description).collect())
    }

    async fn stage_network(&self, session: &str, change: &networks::Change) -> Result<(), String> {
        let values =
            |options: &std::collections::BTreeMap<String, networks::Opt>| -> serde_json::Map<String, Value> {
                options
                    .iter()
                    .map(|(key, value)| (key.clone(), value.json()))
                    .collect()
            };
        let (method, arguments) = match change {
            networks::Change::Add(section, _) => (
                "add",
                json!({ "config": section.config, "type": section.kind, "name": section.id, "values": values(&section.options) }),
            ),
            networks::Change::Set {
                config, id, options, ..
            } => (
                "set",
                json!({ "config": config, "section": id, "values": values(options) }),
            ),
            networks::Change::Delete { config, id, .. } => {
                ("delete", json!({ "config": config, "section": id }))
            }
        };
        self.call(session, "uci", method, &arguments).await.map(|_| ())
    }

    async fn stage(&self, session: &str, change: &Change) -> Result<(), String> {
        let values = |values: &[(String, String)]| -> serde_json::Map<String, Value> {
            values
                .iter()
                .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                .collect()
        };
        let (method, arguments) = match change {
            Change::Add {
                section,
                values: options,
                ..
            } => (
                "add",
                json!({ "config": leases::CONFIG, "type": leases::section_type(section), "name": section, "values": values(options) }),
            ),
            Change::Set {
                section,
                values: options,
                ..
            } => (
                "set",
                json!({ "config": leases::CONFIG, "section": section, "values": values(options) }),
            ),
            Change::Delete { section, .. } => {
                ("delete", json!({ "config": leases::CONFIG, "section": section }))
            }
        };
        self.call(session, "uci", method, &arguments).await.map(|_| ())
    }

    async fn login(&self, password: &str) -> Result<String, String> {
        let arguments = json!({ "username": self.user, "password": password, "timeout": SESSION_TIMEOUT });
        let data = self
            .call(NO_SESSION, "session", "login", &arguments)
            .await
            .map_err(|error| format!("login as {} failed: {error}", self.user))?;
        data.get("ubus_rpc_session")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "login answer has no session".to_owned())
    }

    /// Calls one ubus method and returns its data.
    async fn call(
        &self,
        session: &str,
        object: &str,
        method: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [session, object, method, arguments],
        });
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .json(&body)
            .send()
            .await
            .map_err(|error| format!("{}: {error}", self.name))?;
        if !response.status().is_success() {
            return Err(format!("{}: HTTP {}", self.name, response.status()));
        }
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
        let answer: Value =
            serde_json::from_slice(&bytes).map_err(|_| format!("{}: answer is not JSON", self.name))?;
        result(&answer).map_err(|error| format!("{}: {object} {method}: {error}", self.name))
    }
}

impl Plugin for OpenWrt {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "openwrt"
    }

    fn observe(&self) -> BoxFuture<'_, Result<Observation, String>> {
        Box::pin(self.read())
    }

    fn is_target(&self) -> bool {
        true
    }

    fn plan(&self, plan: Plan) -> BoxFuture<'_, Result<Option<Preview>, String>> {
        Box::pin(self.preview(plan))
    }

    fn apply(&self, plan: Plan, digest: String) -> BoxFuture<'_, Result<Vec<String>, String>> {
        Box::pin(self.write(plan, digest))
    }
}

/// Parses a device address: `https`, or plain `http` to the own host only, which would otherwise send the password
/// readable over the network.
pub(super) fn secure_url(name: &str, url: &str) -> Result<Url, Error> {
    let invalid = |message: &str| Error::Invalid(format!("{name}: {message}"));
    let endpoint = Url::parse(url).map_err(|_| invalid("invalid address"))?;
    let local = matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost"));
    if endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && local) {
        return Err(invalid("the address must use https://"));
    }
    Ok(endpoint)
}

/// Reads the password file; it must be readable for the owner only.
pub(super) async fn read_password(path: &Path) -> Result<String, String> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{}: the password file must have mode 0600",
            path.display()
        ));
    }
    let password = tokio::fs::read_to_string(path)
        .await
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let password = password.trim();
    if password.is_empty() {
        return Err(format!("{}: the password file is empty", path.display()));
    }
    Ok(password.to_owned())
}

/// The data of a ubus JSON-RPC answer: `{"result": [0, data]}`, or the error as text.
fn result(answer: &Value) -> Result<Value, String> {
    if let Some(error) = answer.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return Err(message.to_lowercase());
    }
    let result = answer
        .get("result")
        .and_then(Value::as_array)
        .ok_or("answer has no result")?;
    match result.first().and_then(Value::as_u64) {
        Some(0) => Ok(result.get(1).cloned().unwrap_or_else(|| json!({}))),
        Some(4) => Err("not found".to_owned()),
        Some(5) => Err("no data".to_owned()),
        Some(6) => Err("permission denied, check the rpcd ACL of the lanlord user".to_owned()),
        Some(code) => Err(format!("ubus error {code}")),
        None => Err("answer has no status".to_owned()),
    }
}

/// MAC addresses of a uci option: a text with one or more addresses separated by spaces, or a list.
fn macs(value: Option<&Value>) -> Vec<String> {
    let texts: Vec<&str> = match value {
        Some(Value::String(text)) => text.split_whitespace().collect(),
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    texts.into_iter().filter_map(normalize_mac).collect()
}

fn sections(data: &Value) -> impl Iterator<Item = &Value> {
    data.get("values")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|values| values.values())
}

/// An access point that serves no DHCP and has no entries has nothing to compare with the list.
fn drop_empty_entries(observation: &mut Observation, dhcp: &Value) {
    if observation.assigned.as_ref().is_some_and(Vec::is_empty) && served_interfaces(dhcp).is_empty() {
        observation.assigned = None;
    }
}

/// The address each MAC holds now, from the DHCP leases.
fn held_addresses(leases: &Value) -> HashMap<String, Ipv4Addr> {
    observation(leases, &json!({}), &json!({}))
        .present
        .into_iter()
        .filter_map(|present| Some((present.mac, present.ip?)))
        .collect()
}

/// Builds the observation from the leases, the static leases and the Wi-Fi stations. One entry per MAC address;
/// a station adds its VLAN, a MAC that appears twice keeps its first entry.
fn observation(leases: &Value, hosts: &Value, stations: &Value) -> Observation {
    let seen = leases
        .get("dhcp_leases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|lease| {
            let mac = normalize_mac(lease.get("macaddr")?.as_str()?)?;
            let ip = lease
                .get("ipaddr")
                .and_then(Value::as_str)
                .and_then(|ip| ip.parse().ok());
            let hostname = lease
                .get("hostname")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            Some(Present { mac, ip, hostname })
        })
        .collect();

    let vlans: HashMap<String, u16> = sections(stations)
        .flat_map(|station| {
            let vlan = station
                .get("vid")
                .and_then(Value::as_str)
                .and_then(|vid| vid.parse::<u16>().ok())
                .filter(|vid| (1..=4094).contains(vid));
            macs(station.get("mac"))
                .into_iter()
                .filter_map(move |mac| Some((mac, vlan?)))
        })
        .collect();

    let mut entries: Vec<Assigned> = Vec::new();
    for host in sections(hosts) {
        let name = host.get("name").and_then(Value::as_str).unwrap_or_default();
        let ip = host
            .get("ip")
            .and_then(Value::as_str)
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok());
        for mac in macs(host.get("mac")) {
            if entries.iter().all(|entry| entry.mac != mac) {
                entries.push(Assigned {
                    vlan: vlans.get(&mac).copied(),
                    mac,
                    name: name.to_owned(),
                    ip,
                });
            }
        }
    }
    for (mac, vlan) in &vlans {
        if entries.iter().all(|entry| &entry.mac != mac) {
            entries.push(Assigned {
                mac: mac.clone(),
                name: String::new(),
                ip: None,
                vlan: Some(*vlan),
            });
        }
    }
    entries.sort_by(|left, right| left.mac.cmp(&right.mac));
    Observation {
        present: seen,
        assigned: Some(entries),
        ..Observation::default()
    }
}

fn text(section: &Value, key: &str) -> String {
    section
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The `host` sections of the `dhcp` configuration.
fn host_sections(dhcp: &Value) -> Vec<HostSection> {
    sections(dhcp)
        .filter(|section| text(section, ".type") == "host")
        .map(|section| HostSection {
            id: text(section, ".name"),
            name: text(section, "name"),
            macs: macs(section.get("mac")),
            ip: text(section, "ip"),
            dns: text(section, "dns"),
        })
        .collect()
}

/// The DNS names lanlord owns.
fn name_sections(dhcp: &Value) -> Vec<NameSection> {
    sections(dhcp)
        .filter(|section| text(section, ".type") == "domain")
        .filter(|section| text(section, ".name").starts_with(leases::NAME_PREFIX))
        .map(|section| NameSection {
            id: text(section, ".name"),
            name: text(section, "name"),
            ip: text(section, "ip"),
        })
        .collect()
}

/// The interfaces with a DHCP pool that is not ignored.
fn served_interfaces(dhcp: &Value) -> Vec<String> {
    sections(dhcp)
        .filter(|section| text(section, ".type") == "dhcp" && text(section, "ignore") != "1")
        .map(|section| text(section, "interface"))
        .collect()
}

/// The IPv4 networks of these interfaces.
fn served_networks(served: &[String], dump: &Value) -> Vec<Network> {
    dump.get("interface")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|interface| served.contains(&text(interface, "interface")))
        .flat_map(|interface| {
            interface
                .get("ipv4-address")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|address| {
            Some(Network {
                address: address.get("address")?.as_str()?.parse().ok()?,
                prefix: u8::try_from(address.get("mask")?.as_u64()?)
                    .ok()
                    .filter(|prefix| *prefix <= 32)?,
            })
        })
        .collect()
}

/// The MAC addresses of the clients of one Wi-Fi interface.
fn wifi(associated: &Value) -> Vec<String> {
    associated
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|client| normalize_mac(client.get("mac")?.as_str()?))
        .collect()
}

/// Every MAC address ever seen per bridge port.
type PortHistory = std::collections::BTreeMap<String, std::collections::BTreeSet<String>>;

/// Reads `<port> <mac>` lines.
fn read_port_history(text: &str) -> PortHistory {
    let mut history = PortHistory::new();
    for (port, mac) in text.lines().filter_map(|line| line.split_once(' ')) {
        if let Some(mac) = normalize_mac(mac) {
            history.entry(port.to_owned()).or_default().insert(mac);
        }
    }
    history
}

/// Whether a bridge member is a Wi-Fi interface. Its clients come from iwinfo.
fn is_wifi(member: &str) -> bool {
    member.starts_with("phy") || member.starts_with("wlan")
}

/// Reads a port number from sysfs, like `0x4`.
fn port_number(text: &str) -> Option<u16> {
    u16::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok()
}

/// Reads the kernel's `__fdb_entry` records: the learned MAC addresses and their port numbers.
fn forwarding_table(bytes: &[u8]) -> Vec<(String, u16)> {
    bytes
        .as_chunks::<FDB_ENTRY_BYTES>()
        .0
        .iter()
        .filter(|entry| entry[7] == 0 && entry[0] & 1 == 0)
        .map(|entry| {
            let mac: Vec<String> = entry[..6].iter().map(|byte| format!("{byte:02x}")).collect();
            (mac.join(":"), u16::from_le_bytes([entry[6], entry[12]]))
        })
        .collect()
}

/// Adds the Wi-Fi clients; one without a DHCP lease, for example with a fixed address on the device, is present too.
fn add_wifi(observation: &mut Observation, clients: Vec<String>) {
    for mac in clients {
        if observation.present.iter().all(|present| present.mac != mac) {
            observation.present.push(Present {
                mac,
                ip: None,
                hostname: String::new(),
            });
        }
    }
}

/// Parses a SHA-256 fingerprint: 64 hex digits, with or without colons.
pub(super) fn parse_fingerprint(text: &str) -> Option<[u8; 32]> {
    let digits: String = text.chars().filter(|c| *c != ':').collect();
    if digits.len() != 64 {
        return None;
    }
    let mut fingerprint = [0; 32];
    for (index, byte) in fingerprint.iter_mut().enumerate() {
        *byte = u8::from_str_radix(digits.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(fingerprint)
}

/// HTTP client that trusts exactly the certificate with this fingerprint, whatever its name or issuer.
pub(super) fn client(fingerprint: [u8; 32]) -> Result<Client, String> {
    Client::builder()
        .use_preconfigured_tls(pinned_tls(fingerprint)?)
        .connect_timeout(Duration::from_secs(5))
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())
}

/// TLS settings that trust exactly the certificate with this fingerprint, whatever its name or issuer.
pub(super) fn pinned_tls(fingerprint: [u8; 32]) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedCertificate {
        fingerprint,
        provider: provider.clone(),
    };
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

/// Accepts the server certificate only if its SHA-256 fingerprint is the pinned one. The signatures of the
/// handshake are still checked, so the server must hold the key of that certificate.
#[derive(Debug)]
struct PinnedCertificate {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if digest.as_ref() == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the certificate does not match the pinned fingerprint".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests;
