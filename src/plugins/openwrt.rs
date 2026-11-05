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
use crate::compare::{Entry, Observation, Seen};
use crate::devices::{DeviceList, Error, normalize_mac};
use crate::leases::{self, Change, HostSection, Network, Plan};
use crate::preview::Preview;

/// Longest time for one request to the device.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest answer that is read.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
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
        },
        Field {
            key: "user",
            label: "rpcd user",
            kind: FieldKind::Word,
            placeholder: "lanlord",
        },
        Field {
            key: "password_file",
            label: "Password file",
            kind: FieldKind::DataFile,
            placeholder: "router.password",
        },
        Field {
            key: "certificate",
            label: "Certificate fingerprint (SHA-256)",
            kind: FieldKind::Fingerprint,
            placeholder: "AB:CD:...",
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
}

/// One `OpenWrt` device.
pub struct OpenWrt {
    name: String,
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
        } = settings(&name, table)?;
        let invalid = |message: &str| Error::Invalid(format!("{name}: {message}"));
        let mut endpoint = Url::parse(&url).map_err(|_| invalid("invalid address"))?;
        let local = matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost"));
        // Plain HTTP would send the password readable over the network; only the own host may use it.
        if endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && local) {
            return Err(invalid("the address must use https://"));
        }
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
        Ok(observation(&leases, &hosts, &stations))
    }

    /// The static leases and the networks the device serves with DHCP.
    async fn lease_state(&self, session: &str) -> Result<(Vec<HostSection>, Vec<Network>), String> {
        let dhcp = self
            .call(session, "uci", "get", &json!({ "config": leases::CONFIG }))
            .await?;
        let dump = self
            .call(session, "network.interface", "dump", &json!({}))
            .await?;
        Ok((host_sections(&dhcp), served_networks(&dhcp, &dump)))
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

/// Reads the password file; it must be readable for the owner only.
async fn read_password(path: &Path) -> Result<String, String> {
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

/// The IPv4 networks of the interfaces with a DHCP pool that is not ignored.
fn served_networks(dhcp: &Value, dump: &Value) -> Vec<Network> {
    let served: Vec<String> = sections(dhcp)
        .filter(|section| text(section, ".type") == "dhcp" && text(section, "ignore") != "1")
        .map(|section| text(section, "interface"))
        .collect();
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

/// Parses a SHA-256 fingerprint: 64 hex digits, with or without colons.
fn parse_fingerprint(text: &str) -> Option<[u8; 32]> {
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
fn client(fingerprint: [u8; 32]) -> Result<Client, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedCertificate {
        fingerprint,
        provider: provider.clone(),
    };
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Client::builder()
        .use_preconfigured_tls(tls)
        .connect_timeout(Duration::from_secs(5))
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())
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
mod tests {
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

    /// A small ubus API like `OpenWrt`'s: one password and the three calls lanlord makes.
    async fn fake_router(stations: Value) -> String {
        use axum::{Json, Router, routing::post};
        let handler = move |Json(request): Json<Value>| {
            let stations = stations.clone();
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
}
