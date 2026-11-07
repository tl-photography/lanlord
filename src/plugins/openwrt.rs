//! Plugin `openwrt`: reads an `OpenWrt` router or access point through its ubus JSON-RPC API, the API `LuCI` uses.
//! lanlord logs in as its own rpcd user, whose rights an ACL on the device limits, and trusts only the pinned TLS
//! certificate of the device.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, Url};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{BoxFuture, Field, FieldKind, Plugin, PluginType, settings};
use crate::compare::{Entry, Observation, Seen, WifiClient};
use crate::devices::{DeviceList, Error, normalize_mac};
use crate::leases::{self, Change, HostSection, Network, Plan};
use crate::preview::Preview;

/// The kernel's table of IPv4 neighbours on the device.
const NEIGHBOURS: &str = "/proc/net/arp";

/// Longest time for one request to the device.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest answer that is read.
pub(super) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Lifetime of the rpcd session in seconds; one scan needs only a few.
const SESSION_TIMEOUT: u64 = 60;
/// Session id for the login call.
const NO_SESSION: &str = "00000000000000000000000000000000";
/// Seconds after which the router undoes applied changes that lanlord has not confirmed.
const ROLLBACK_SECONDS: u64 = 30;

/// The type description for `lanlord.toml` and the web interface.
pub(super) const TYPE: PluginType = PluginType {
    kind: "openwrt",
    title: "OpenWrt",
    description: "Reads the DHCP leases, static leases and Wi-Fi VLANs of an OpenWrt router or access point \
                  through its ubus API, as its own rpcd user, and applies the static leases of a router that serves \
                  DHCP.",
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
    device: String,
}

/// One `OpenWrt` device.
pub struct OpenWrt {
    name: String,
    /// The linked device's name, or the plugin's; names the access point of Wi-Fi clients.
    label: String,
    endpoint: Url,
    user: String,
    password_file: PathBuf,
    client: Client,
}

impl OpenWrt {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let Settings {
            url,
            user,
            password_file,
            certificate,
            device,
        } = settings(&name, table)?;
        let invalid = |message: &str| Error::Invalid(format!("{name}: {message}"));
        let mut endpoint = secure_url(&name, &url)?;
        endpoint.set_path("/ubus");
        endpoint.set_query(None);
        let fingerprint =
            parse_fingerprint(&certificate).ok_or_else(|| invalid("invalid certificate fingerprint"))?;
        let client = client(fingerprint).map_err(|error| invalid(&error))?;
        Ok(Self {
            label: if device.is_empty() { name.clone() } else { device },
            name,
            endpoint,
            user,
            password_file: data_dir.join(password_file),
            client,
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
        let mut observation = observation(&leases, &hosts, &stations);
        match self.wifi_clients(&session).await {
            Ok(clients) => add_wifi(&mut observation, clients),
            // No Wi-Fi hardware, no iwinfo.
            Err(error) if error.ends_with("not found") => {}
            Err(error) => observation.notes.push(format!("Wi-Fi clients not read: {error}")),
        }
        let arguments = json!({ "path": NEIGHBOURS });
        match self.call(&session, "file", "read", &arguments).await {
            Ok(table) => {
                let text = table.get("data").and_then(Value::as_str).unwrap_or_default();
                observation.neighbours = Some(neighbours(text));
            }
            // Without rpcd's file module the method does not exist.
            Err(error) if error.ends_with("not found") || error.ends_with("ubus error 3") => {}
            Err(error) => observation.notes.push(format!("Neighbours not read: {error}")),
        }
        Ok(observation)
    }

    /// The devices connected to each Wi-Fi interface of the device.
    async fn wifi_clients(&self, session: &str) -> Result<Vec<WifiClient>, String> {
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
            let info = self.call(session, "iwinfo", "info", &arguments).await?;
            let associated = self.call(session, "iwinfo", "assoclist", &arguments).await?;
            clients.extend(wifi(&access_point(&self.label, device, &info), &associated));
        }
        Ok(clients)
    }

    /// The static leases and the networks the device serves with DHCP. A device without a DHCP pool, like an access
    /// point, is not asked for its interfaces: its ACL does not need to allow that.
    async fn lease_state(&self, session: &str) -> Result<(Vec<HostSection>, Vec<Network>), String> {
        let dhcp = self
            .call(session, "uci", "get", &json!({ "config": leases::CONFIG }))
            .await?;
        let served = served_interfaces(&dhcp);
        if served.is_empty() {
            return Ok((host_sections(&dhcp), Vec::new()));
        }
        let dump = self
            .call(session, "network.interface", "dump", &json!({}))
            .await?;
        Ok((host_sections(&dhcp), served_networks(&served, &dump)))
    }

    async fn plan_in(&self, session: &str, devices: &DeviceList) -> Result<Option<Plan>, String> {
        let (hosts, networks) = self.lease_state(session).await?;
        Ok((!networks.is_empty()).then(|| leases::plan(devices, &hosts, &networks)))
    }

    async fn preview(&self, devices: DeviceList) -> Result<Option<Preview>, String> {
        let password = read_password(&self.password_file).await?;
        let session = self.login(&password).await?;
        Ok(self.plan_in(&session, &devices).await?.map(|plan| plan.preview()))
    }

    /// Stages the changes, applies them with rollback, reads the device again and confirms only if nothing is
    /// left to change. Without the confirmation, the device undoes the changes after [`ROLLBACK_SECONDS`].
    async fn write(&self, devices: DeviceList, digest: String) -> Result<Vec<String>, String> {
        let password = read_password(&self.password_file).await?;
        let session = self.login(&password).await?;
        let plan = self
            .plan_in(&session, &devices)
            .await?
            .ok_or_else(|| format!("{}: serves no DHCP, there is nothing to apply", self.name))?;
        if plan.digest() != digest {
            return Err(format!(
                "{}: the device or the list changed since the preview, check the changes again",
                self.name
            ));
        }
        if plan.changes.is_empty() {
            return Ok(Vec::new());
        }
        for change in &plan.changes {
            if let Err(error) = self.stage(&session, change).await {
                let _ = self
                    .call(&session, "uci", "revert", &json!({ "config": leases::CONFIG }))
                    .await;
                return Err(error);
            }
        }
        self.call(
            &session,
            "uci",
            "apply",
            &json!({ "rollback": true, "timeout": ROLLBACK_SECONDS }),
        )
        .await?;
        let left = self.plan_in(&session, &devices).await;
        if !matches!(&left, Ok(Some(after)) if after.changes.is_empty()) {
            let _ = self.call(&session, "uci", "rollback", &json!({})).await;
            return Err(format!(
                "{}: the device does not show the changes after applying, they were rolled back",
                self.name
            ));
        }
        self.call(&session, "uci", "confirm", &json!({})).await?;
        Ok(plan
            .changes
            .iter()
            .map(|change| change.description().to_owned())
            .collect())
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
                json!({ "config": leases::CONFIG, "type": "host", "name": section, "values": values(options) }),
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

    fn plan(&self, devices: DeviceList) -> BoxFuture<'_, Result<Option<Preview>, String>> {
        Box::pin(self.preview(devices))
    }

    fn apply(&self, devices: DeviceList, digest: String) -> BoxFuture<'_, Result<Vec<String>, String>> {
        Box::pin(self.write(devices, digest))
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
            Some(Seen { mac, ip, hostname })
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

    let mut entries: Vec<Entry> = Vec::new();
    for host in sections(hosts) {
        let name = host.get("name").and_then(Value::as_str).unwrap_or_default();
        let ip = host
            .get("ip")
            .and_then(Value::as_str)
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok());
        for mac in macs(host.get("mac")) {
            if entries.iter().all(|entry| entry.mac != mac) {
                entries.push(Entry {
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
            entries.push(Entry {
                mac: mac.clone(),
                name: String::new(),
                ip: None,
                vlan: Some(*vlan),
            });
        }
    }
    entries.sort_by(|left, right| left.mac.cmp(&right.mac));
    Observation {
        seen,
        entries: Some(entries),
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

/// Where a client is connected: the plugin name, the network name and the band.
fn access_point(plugin: &str, device: &str, info: &Value) -> String {
    let ssid = info.get("ssid").and_then(Value::as_str).unwrap_or(device);
    let band = match info.get("frequency").and_then(Value::as_u64) {
        Some(frequency) if frequency < 3000 => " (2.4 GHz)",
        Some(frequency) if frequency < 5925 => " (5 GHz)",
        Some(_) => " (6 GHz)",
        None => "",
    };
    format!("{plugin}: {ssid}{band}")
}

/// The clients of one Wi-Fi interface.
fn wifi(access_point: &str, associated: &Value) -> Vec<WifiClient> {
    associated
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|client| {
            Some(WifiClient {
                mac: normalize_mac(client.get("mac")?.as_str()?)?,
                access_point: access_point.to_owned(),
                signal: client.get("signal").and_then(Value::as_i64),
            })
        })
        .collect()
}

/// Reads the kernel's table of neighbours: flags 0 means no answer. A link-local address says nothing about the device.
fn neighbours(table: &str) -> Vec<Seen> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (&address, &flags, &mac) = (fields.first()?, fields.get(2)?, fields.get(3)?);
            (flags != "0x0").then(|| Seen {
                mac: mac.to_ascii_lowercase(),
                ip: address.parse::<Ipv4Addr>().ok().filter(|ip| !ip.is_link_local()),
                hostname: String::new(),
            })
        })
        .collect()
}

/// Adds the Wi-Fi clients; one without a DHCP lease, for example with a fixed address on the device, is seen too.
fn add_wifi(observation: &mut Observation, clients: Vec<WifiClient>) {
    for client in &clients {
        if observation.seen.iter().all(|seen| seen.mac != client.mac) {
            observation.seen.push(Seen {
                mac: client.mac.clone(),
                ip: None,
                hostname: String::new(),
            });
        }
    }
    observation.wifi = clients;
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
