//! Read-only `OpenWrt` source over SSH. The restricted helper returns tab-separated `lease` and `entry` records.
use std::collections::HashMap;
use std::fs;

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, AuthResult, Handler};
use russh::keys::{
    PublicKey, PublicKeyOrCertificate, key::PrivateKeyWithHashAlg, load_public_key, load_secret_key,
};
use russh::{ChannelMsg, Disconnect};
use serde::Deserialize;

use super::{BoxFuture, Plugin, settings};
use crate::compare::{Entry, Observation, Seen};
use crate::devices::{Error, normalize_mac};

const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    user: String,
    key_file: PathBuf,
    host_key_file: PathBuf,
}

fn default_port() -> u16 {
    22
}

/// A read-only connection to one `OpenWrt` router or access point.
pub struct OpenWrt {
    name: String,
    host: String,
    port: u16,
    user: String,
    key_file: PathBuf,
    host_key_file: PathBuf,
}

impl OpenWrt {
    pub(super) fn new(name: String, table: toml::Table) -> Result<Self, Error> {
        let Settings {
            host,
            port,
            user,
            key_file,
            host_key_file,
        } = settings(&name, table)?;
        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err(Error::Invalid(format!("{name}: invalid host")));
        }
        if port == 0 {
            return Err(Error::Invalid(format!("{name}: port must be 1 to 65535")));
        }
        if user.is_empty() || user.chars().any(char::is_whitespace) {
            return Err(Error::Invalid(format!("{name}: invalid SSH user")));
        }
        if key_file.as_os_str().is_empty() || host_key_file.as_os_str().is_empty() {
            return Err(Error::Invalid(format!(
                "{name}: SSH key and pinned host key paths are required"
            )));
        }
        Ok(Self {
            name,
            host,
            port,
            user,
            key_file,
            host_key_file,
        })
    }

    async fn read(&self) -> Result<Observation, String> {
        let key_metadata =
            fs::metadata(&self.key_file).map_err(|error| format!("{}: {error}", self.key_file.display()))?;
        if key_metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{}: SSH key permissions must be 0600",
                self.key_file.display()
            ));
        }
        let host_key = load_public_key(&self.host_key_file)
            .map_err(|error| format!("{}: {error}", self.host_key_file.display()))?;
        let private_key = load_secret_key(&self.key_file, None)
            .map_err(|error| format!("{}: {error}", self.key_file.display()))?;
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(15)),
            ..Default::default()
        };
        let mut handle = client::connect(
            Arc::new(config),
            (self.host.as_str(), self.port),
            PinnedHostKey { expected: host_key },
        )
        .await
        .map_err(|error| format!("{}: SSH connection failed: {error}", self.name))?;
        let auth = handle
            .authenticate_publickey(
                self.user.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(private_key), None),
            )
            .await
            .map_err(|error| format!("{}: SSH authentication failed: {error}", self.name))?;
        if !matches!(auth, AuthResult::Success) {
            return Err(format!(
                "{}: SSH public-key authentication was rejected",
                self.name
            ));
        }
        let result = read_channel(&handle).await;
        let _ = handle
            .disconnect(Disconnect::ByApplication, "read complete", "en")
            .await;
        result
    }
}

struct PinnedHostKey {
    expected: PublicKey,
}

impl Handler for PinnedHostKey {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        std::future::ready(Ok(server_public_key.public_key() == self.expected))
    }
}

async fn read_channel<H: Handler>(handle: &client::Handle<H>) -> Result<Observation, String> {
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|error| format!("cannot open SSH channel: {error}"))?;
    channel
        .exec(true, "read")
        .await
        .map_err(|error| format!("cannot request OpenWrt read: {error}"))?;

    let mut stdout = Vec::new();
    let mut exit_status = None;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                if stdout.len() + data.len() > MAX_OUTPUT_BYTES {
                    return Err("OpenWrt read output exceeds 1 MiB".to_owned());
                }
                stdout.extend_from_slice(&data);
            }
            ChannelMsg::ExtendedData { .. } => return Err("OpenWrt read returned stderr".to_owned()),
            ChannelMsg::ExitStatus { exit_status: status } => exit_status = Some(status),
            ChannelMsg::ExitSignal { .. } => return Err("OpenWrt read exited by signal".to_owned()),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    if exit_status != Some(0) {
        return Err(format!("OpenWrt read exited with status {exit_status:?}"));
    }
    let output =
        String::from_utf8(stdout).map_err(|error| format!("OpenWrt read output is not UTF-8: {error}"))?;
    parse(&output)
}

/// Parses the helper protocol: `lease<TAB>mac<TAB>ip<TAB>hostname` and
/// `entry<TAB>mac<TAB>name<TAB>ip-or--<TAB>vlan-or--`.
fn parse(output: &str) -> Result<Observation, String> {
    let mut seen = Vec::new();
    let mut entries = HashMap::new();
    for (index, line) in output.lines().enumerate() {
        let fields: Vec<&str> = line.trim_end_matches('\r').split('\t').collect();
        match fields.as_slice() {
            ["lease", mac, ip, hostname] => {
                let mac = normalize_mac(mac).ok_or_else(|| format!("line {}: invalid MAC", index + 1))?;
                let ip = ip
                    .parse::<Ipv4Addr>()
                    .map_err(|_| format!("line {}: invalid IPv4 address", index + 1))?;
                seen.push(Seen {
                    mac,
                    ip: Some(ip),
                    hostname: if *hostname == "-" {
                        String::new()
                    } else {
                        (*hostname).to_owned()
                    },
                });
            }
            ["entry", mac, name, ip, vlan] => {
                let mac = normalize_mac(mac).ok_or_else(|| format!("line {}: invalid MAC", index + 1))?;
                let ip = if *ip == "-" {
                    None
                } else {
                    Some(
                        ip.parse::<Ipv4Addr>()
                            .map_err(|_| format!("line {}: invalid IPv4 address", index + 1))?,
                    )
                };
                let vlan = if *vlan == "-" {
                    None
                } else {
                    let value = vlan
                        .parse::<u16>()
                        .map_err(|_| format!("line {}: invalid VLAN", index + 1))?;
                    if !(1..=4094).contains(&value) {
                        return Err(format!("line {}: VLAN must be 1 to 4094", index + 1));
                    }
                    Some(value)
                };
                let entry = Entry {
                    mac: mac.clone(),
                    name: (*name).to_owned(),
                    ip,
                    vlan,
                };
                if entries.insert(mac, entry).is_some() {
                    return Err(format!("line {}: duplicate entry", index + 1));
                }
            }
            _ => return Err(format!("line {}: invalid OpenWrt read record", index + 1)),
        }
    }
    let mut entries: Vec<Entry> = entries.into_values().collect();
    entries.sort_by(|left, right| left.mac.cmp(&right.mac));
    Ok(Observation {
        seen,
        entries: Some(entries),
    })
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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_leases_and_entries() {
        let observation = parse(
            "lease\tAA-BB-CC-00-11-22\t192.0.2.10\tphone\nentry\taa:bb:cc:00:11:33\tplug\t192.0.2.11\t20\n",
        )
        .unwrap();
        assert_eq!(observation.seen[0].mac, "aa:bb:cc:00:11:22");
        assert_eq!(observation.seen[0].hostname, "phone");
        let entries = observation.entries.unwrap();
        assert_eq!(entries[0].name, "plug");
        assert_eq!(entries[0].vlan, Some(20));
    }

    #[test]
    fn rejects_invalid_and_duplicate_records() {
        for output in [
            "lease\tnot-a-mac\t192.0.2.1\tphone\n",
            "lease\t00:00:00:00:00:01\t2001:db8::1\tphone\n",
            "entry\t00:00:00:00:00:01\tdevice\t-\t4095\n",
            "entry\t00:00:00:00:00:01\tdevice\t-\t-\nentry\t00:00:00:00:00:01\tdevice\t-\t-\n",
            "unknown\tvalue\n",
        ] {
            assert!(parse(output).is_err(), "{output}");
        }
    }
}
