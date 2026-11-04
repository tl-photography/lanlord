//! Plugin `leases-file`: reads a dnsmasq lease file, as OpenWrt (`/tmp/dhcp.leases`) and Pi-hole write it, and
//! reports the devices in it as seen.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::Deserialize;

use super::{BoxFuture, Plugin, settings};
use crate::compare::{Observation, Seen};
use crate::devices::{Error, normalize_mac};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Path of the lease file, inside the container.
    path: PathBuf,
}

/// A lease file as source of seen devices.
pub struct LeasesFile {
    name: String,
    path: PathBuf,
}

impl LeasesFile {
    pub(super) fn new(name: String, table: toml::Table) -> Result<Self, Error> {
        let Settings { path } = settings(&name, table)?;
        Ok(Self { name, path })
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
                entries: None,
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
mod tests {
    use super::*;

    #[test]
    fn dnsmasq_lines_are_parsed() {
        let content = "\
1793900000 AA:BB:CC:00:11:22 192.0.2.10 phone 01:aa:bb:cc:00:11:22
1793900000 aa:bb:cc:00:11:33 192.0.2.11 * *
duid 00:01:00:01:2c:4f:8f:aa:bb:cc:dd:ee:ff
1793900000 1234 2001:db8::5 laptop 00:01
broken line
";
        assert_eq!(
            parse(content),
            [
                Seen {
                    mac: "aa:bb:cc:00:11:22".to_owned(),
                    ip: Some(Ipv4Addr::new(192, 0, 2, 10)),
                    hostname: "phone".to_owned(),
                },
                Seen {
                    mac: "aa:bb:cc:00:11:33".to_owned(),
                    ip: Some(Ipv4Addr::new(192, 0, 2, 11)),
                    hostname: String::new(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn missing_file_is_an_error() {
        let plugin = LeasesFile {
            name: "router".to_owned(),
            path: PathBuf::from("/nonexistent/dhcp.leases"),
        };
        assert!(plugin.observe().await.is_err());
    }
}
