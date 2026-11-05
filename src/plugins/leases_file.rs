//! Plugin `leases-file`: reads a dnsmasq lease file, as `OpenWrt` (`/tmp/dhcp.leases`) and Pi-hole write it, and
//! reports the devices in it as seen.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;

use super::{BoxFuture, Field, FieldKind, Plugin, PluginType, settings};
use crate::compare::{Observation, Seen};
use crate::devices::{Error, normalize_mac};

/// The type description for `lanlord.toml` and the web interface.
pub(super) const TYPE: PluginType = PluginType {
    kind: "leases-file",
    title: "DHCP lease file",
    description: "Reports the devices in a dnsmasq lease file in the data directory, for example a copy of /tmp/dhcp.leases.",
    fields: &[Field {
        key: "path",
        label: "Lease file",
        kind: FieldKind::DataFile,
        placeholder: "dhcp.leases",
    }],
    build: |name, table, data_dir| Ok(Arc::new(LeasesFile::new(name, table, data_dir)?)),
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// File name of the lease file in the data directory.
    path: String,
}

/// A lease file as source of seen devices.
pub struct LeasesFile {
    name: String,
    path: PathBuf,
}

impl LeasesFile {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let Settings { path } = settings(&name, table)?;
        Ok(Self {
            name,
            path: data_dir.join(path),
        })
    }
}

impl Plugin for LeasesFile {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "leases-file"
    }

    fn observe(&self) -> BoxFuture<'_, Result<Observation, String>> {
        Box::pin(async move {
            let content = tokio::fs::read_to_string(&self.path)
                .await
                .map_err(|error| format!("{}: {error}", self.path.display()))?;
            Ok(Observation {
                seen: parse(&content),
                ..Observation::default()
            })
        })
    }
}

/// Parses dnsmasq lease lines: `<expiry> <mac> <ip> <hostname> <client id>`. Lines that do not fit, IPv6 leases
/// and unusual MACs are skipped; `*` as host name means none.
fn parse(content: &str) -> Vec<Seen> {
    content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _expiry = fields.next()?;
            let mac = normalize_mac(fields.next()?)?;
            let ip = fields.next()?.parse::<Ipv4Addr>().ok()?;
            let hostname = match fields.next() {
                Some("*") | None => String::new(),
                Some(name) => name.to_owned(),
            };
            Some(Seen {
                mac,
                ip: Some(ip),
                hostname,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
