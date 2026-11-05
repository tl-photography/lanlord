//! Read-only Pi-hole v6 source using its network-devices API.

use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::Value;

use super::{BoxFuture, Plugin, settings};
use crate::compare::{Observation, Seen};
use crate::devices::{Error, normalize_mac};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    url: String,
    password_file: PathBuf,
}

/// A read-only Pi-hole API source.
pub struct PiHole {
    name: String,
    url: Url,
    password_file: PathBuf,
}

impl PiHole {
    pub(super) fn new(name: String, table: toml::Table) -> Result<Self, Error> {
        let Settings { url, password_file } = settings(&name, table)?;
        let url =
            Url::parse(&url).map_err(|error| Error::Invalid(format!("{name}: invalid API URL: {error}")))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(Error::Invalid(format!("{name}: API URL must use HTTP or HTTPS")));
        }
        if password_file.as_os_str().is_empty() {
            return Err(Error::Invalid(format!("{name}: password file path is required")));
        }
        Ok(Self {
            name,
            url,
            password_file,
        })
    }

    async fn read(&self) -> Result<Observation, String> {
        let metadata = fs::metadata(&self.password_file)
            .map_err(|error| format!("{}: {error}", self.password_file.display()))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{}: password file permissions must be 0600",
                self.password_file.display()
            ));
        }
        let password = tokio::fs::read_to_string(&self.password_file)
            .await
            .map_err(|error| format!("{}: {error}", self.password_file.display()))?;
        let password = password.trim();
        if password.is_empty() {
            return Err("Pi-hole API password file is empty".to_owned());
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| format!("Pi-hole HTTP client: {error}"))?;
        let auth_url = endpoint(&self.url, "auth");
        let response = client
            .post(auth_url.clone())
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await
            .map_err(|error| format!("Pi-hole authentication request failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "Pi-hole authentication returned HTTP {}",
                response.status()
            ));
        }
        let session: Value = response
            .json()
            .await
            .map_err(|error| format!("Pi-hole authentication response is invalid: {error}"))?;
        let sid = session
            .pointer("/session/sid")
            .and_then(Value::as_str)
            .ok_or_else(|| "Pi-hole authentication response has no session ID".to_owned())?;

        let result = read_devices(&client, &self.url, sid).await;
        let _ = client.delete(auth_url).header("X-FTL-SID", sid).send().await;
        result
    }
}

fn endpoint(base: &Url, path: &str) -> Url {
    let mut url = base.clone();
    url.set_path(&format!("/api/{path}"));
    url.set_query(None);
    url
}

async fn read_devices(client: &Client, base: &Url, sid: &str) -> Result<Observation, String> {
    let response = client
        .get(endpoint(base, "network/devices"))
        .header("X-FTL-SID", sid)
        .query(&[("max_devices", "1000"), ("max_addresses", "10")])
        .send()
        .await
        .map_err(|error| format!("Pi-hole network-devices request failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Pi-hole network-devices returned HTTP {}",
            response.status()
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("Pi-hole network-devices response failed: {error}"))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err("Pi-hole network-devices response exceeds 1 MiB".to_owned());
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Pi-hole network-devices response is invalid JSON: {error}"))?;
    parse_devices(&value)
}

fn parse_devices(value: &Value) -> Result<Observation, String> {
    let devices = value
        .get("devices")
        .and_then(Value::as_array)
        .ok_or_else(|| "Pi-hole network-devices response has no devices array".to_owned())?;
    let mut seen = Vec::new();
    for device in devices {
        let mac = device
            .get("hwaddr")
            .and_then(Value::as_str)
            .and_then(normalize_mac);
        let Some(mac) = mac else {
            continue;
        };
        let top_level_name = device.get("name").and_then(Value::as_str).unwrap_or_default();
        if let Some(addresses) = device.get("ips").and_then(Value::as_array) {
            for address in addresses {
                let Some(ip) = address
                    .get("ip")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<Ipv4Addr>().ok())
                else {
                    continue;
                };
                let hostname = address
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .unwrap_or(top_level_name)
                    .to_owned();
                seen.push(Seen {
                    mac: mac.clone(),
                    ip: Some(ip),
                    hostname,
                });
            }
        } else if let Some(ip) = device
            .get("ip")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<Ipv4Addr>().ok())
        {
            seen.push(Seen {
                mac,
                ip: Some(ip),
                hostname: top_level_name.to_owned(),
            });
        }
    }
    seen.sort_by(|left, right| (left.mac.as_str(), left.ip).cmp(&(right.mac.as_str(), right.ip)));
    Ok(Observation { seen, entries: None })
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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_network_devices_and_skips_ipv6_and_missing_macs() {
        let value = serde_json::json!({
            "devices": [
                {
                    "hwaddr": "AA:BB:CC:00:11:22",
                    "ips": [
                        {"ip": "192.0.2.10", "name": "phone"},
                        {"ip": "2001:db8::1", "name": "phone"}
                    ]
                },
                {"hwaddr": "", "ips": [{"ip": "192.0.2.20", "name": "unknown"}]}
            ]
        });
        let observation = parse_devices(&value).unwrap();
        assert_eq!(observation.seen.len(), 1);
        assert_eq!(observation.seen[0].mac, "aa:bb:cc:00:11:22");
        assert_eq!(observation.seen[0].ip, Some(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(observation.seen[0].hostname, "phone");
        assert!(observation.entries.is_none());
    }

    #[test]
    fn malformed_network_device_response_is_rejected() {
        assert!(parse_devices(&serde_json::json!({})).is_err());
    }
}
