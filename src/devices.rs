//! The device list: one entry per device, stored as TOML.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One connection of the network: a device with one MAC address, or one interface of a machine. Leases, DNS names
/// and clients work per connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// DNS name of the device, without domain.
    pub name: String,
    /// MAC address, lowercase with colons.
    pub mac: String,
    /// Group of the device, decides the VLAN.
    pub group: String,
    /// Fixed address; it gets a static lease unless `self_assigned`.
    pub ip: Option<Ipv4Addr>,
    /// The address is set on the device itself, so it gets no static lease.
    pub self_assigned: bool,
    /// Found by a scan and not looked at yet.
    pub unreviewed: bool,
    /// Free text.
    pub note: String,
    /// The machine this connection is an interface of, for example `ThinkPad` for its dock, Wi-Fi and cable; empty
    /// for a device with one connection.
    pub machine: String,
}

/// All connections, in the order of the file. In the file, the interfaces of a machine are nested under it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "FileList", into = "FileList")]
pub struct DeviceList {
    /// The connections.
    pub devices: Vec<Device>,
}

/// `devices.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileList {
    #[serde(default, rename = "device", skip_serializing_if = "Vec::is_empty")]
    devices: Vec<FileDevice>,
}

/// A `[[device]]`: a device with one connection, or a machine with `[[device.interface]]` tables.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDevice {
    name: String,
    /// Older files have `machine` on every connection instead of the nested tables.
    #[serde(default, skip_serializing)]
    machine: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    mac: String,
    group: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    self_assigned: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unreviewed: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    note: String,
    #[serde(default, rename = "interface", skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<FileInterface>,
}

/// A `[[device.interface]]`; without a group it is in the group of its machine.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInterface {
    name: String,
    mac: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    self_assigned: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unreviewed: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    note: String,
}

impl TryFrom<FileList> for DeviceList {
    type Error = String;

    fn try_from(file: FileList) -> Result<Self, String> {
        let mut devices = Vec::new();
        for entry in file.devices {
            if entry.interfaces.is_empty() {
                if entry.mac.is_empty() {
                    return Err(format!("{}: a device needs a mac or interfaces", entry.name));
                }
                devices.push(Device {
                    name: entry.name,
                    mac: entry.mac,
                    group: entry.group,
                    ip: entry.ip,
                    self_assigned: entry.self_assigned,
                    unreviewed: entry.unreviewed,
                    note: entry.note,
                    machine: entry.machine,
                });
                continue;
            }
            if !entry.mac.is_empty() || entry.ip.is_some() {
                return Err(format!("{}: mac and ip belong to its interfaces", entry.name));
            }
            for interface in entry.interfaces {
                devices.push(Device {
                    name: interface.name,
                    mac: interface.mac,
                    group: interface.group.unwrap_or_else(|| entry.group.clone()),
                    ip: interface.ip,
                    self_assigned: interface.self_assigned,
                    unreviewed: interface.unreviewed,
                    note: interface.note,
                    machine: entry.name.clone(),
                });
            }
        }
        Ok(Self { devices })
    }
}

impl From<DeviceList> for FileList {
    fn from(list: DeviceList) -> Self {
        let mut devices: Vec<FileDevice> = Vec::new();
        for device in list.devices {
            if device.machine.is_empty() {
                devices.push(FileDevice {
                    name: device.name,
                    mac: device.mac,
                    group: device.group,
                    ip: device.ip,
                    self_assigned: device.self_assigned,
                    unreviewed: device.unreviewed,
                    note: device.note,
                    ..FileDevice::default()
                });
                continue;
            }
            let position = devices
                .iter()
                .position(|entry| entry.name == device.machine && !entry.interfaces.is_empty());
            let index = position.unwrap_or_else(|| {
                devices.push(FileDevice {
                    name: device.machine.clone(),
                    group: device.group.clone(),
                    ..FileDevice::default()
                });
                devices.len() - 1
            });
            let own_group = (device.group != devices[index].group).then_some(device.group);
            devices[index].interfaces.push(FileInterface {
                name: device.name,
                mac: device.mac,
                group: own_group,
                ip: device.ip,
                self_assigned: device.self_assigned,
                unreviewed: device.unreviewed,
                note: device.note,
            });
        }
        Self { devices }
    }
}

/// Errors when reading, checking or writing the device list.
#[derive(Debug)]
pub enum Error {
    /// The file could not be read or written.
    Io(std::io::Error),
    /// The file is not valid TOML or has unknown fields.
    Parse(String),
    /// A device is invalid or not unique.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Parse(message) | Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Normalizes a MAC address to lowercase with colons. Accepts `:` or `-` as separator.
#[must_use]
pub fn normalize_mac(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.trim().split([':', '-']).collect();
    let valid = parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()));
    valid.then(|| parts.join(":").to_ascii_lowercase())
}

/// Checks that a name can be used as DNS name: letters, digits and `-`, at most 63 characters, no `-` at the
/// start or end.
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// Writes a file readable for the owner only: first to a temporary file next to it, then renames it, so the
/// file is never half written.
///
/// # Errors
///
/// If the file cannot be written.
pub fn write_private(path: &Path, content: &str) -> Result<(), Error> {
    let temporary = path.with_extension("toml.tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

impl DeviceList {
    /// Reads the device list. A missing file is an empty list.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, is not valid TOML, or a device is invalid.
    pub fn load(path: &Path, groups: &[String]) -> Result<Self, Error> {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        let list: Self =
            toml::from_str(&content).map_err(|error| Error::Parse(format!("{}: {error}", path.display())))?;
        list.validate(groups)?;
        Ok(list)
    }

    /// Checks and writes the device list, readable for the owner only.
    ///
    /// # Errors
    ///
    /// If a device is invalid or the file cannot be written.
    pub fn save(&self, path: &Path, groups: &[String]) -> Result<(), Error> {
        self.validate(groups)?;
        let content =
            toml::to_string_pretty(self).map_err(|error| Error::Invalid(format!("cannot write: {error}")))?;
        write_private(path, &content)
    }

    /// Checks every device and that names, MAC addresses and IP addresses are unique.
    ///
    /// # Errors
    ///
    /// The first problem found.
    pub fn validate(&self, groups: &[String]) -> Result<(), Error> {
        let mut names = HashSet::new();
        let mut macs = HashSet::new();
        let mut ips = HashSet::new();
        for device in &self.devices {
            let name = &device.name;
            if !is_valid_name(name) {
                return Err(Error::Invalid(format!("invalid name: {name}")));
            }
            if normalize_mac(&device.mac).as_deref() != Some(device.mac.as_str()) {
                return Err(Error::Invalid(format!(
                    "{name}: invalid MAC address {}",
                    device.mac
                )));
            }
            if !device.machine.is_empty() && !is_valid_name(&device.machine) {
                return Err(Error::Invalid(format!(
                    "{name}: invalid device name {}",
                    device.machine
                )));
            }
            if !groups.contains(&device.group) {
                return Err(Error::Invalid(format!("{name}: unknown group {}", device.group)));
            }
            if !names.insert(name.to_ascii_lowercase()) {
                return Err(Error::Invalid(format!("duplicate name: {name}")));
            }
            if !macs.insert(&device.mac) {
                return Err(Error::Invalid(format!(
                    "{name}: duplicate MAC address {}",
                    device.mac
                )));
            }
            if let Some(ip) = device.ip
                && !ips.insert(ip)
            {
                return Err(Error::Invalid(format!("{name}: duplicate IP address {ip}")));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
