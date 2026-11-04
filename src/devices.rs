//! The device list: one entry per device, stored as TOML.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A device of the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// DNS name of the device, without domain.
    pub name: String,
    /// MAC address, lowercase with colons.
    pub mac: String,
    /// Group of the device, decides the VLAN.
    pub group: String,
    /// Fixed address, if the device gets a static lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<Ipv4Addr>,
    /// Free text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// All devices, in the order of the file.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceList {
    /// The devices.
    #[serde(default, rename = "device")]
    pub devices: Vec<Device>,
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
mod tests {
    use super::*;

    fn groups() -> Vec<String> {
        vec!["lan".to_owned(), "iot".to_owned()]
    }

    fn device(name: &str, mac: &str) -> Device {
        Device {
            name: name.to_owned(),
            mac: mac.to_owned(),
            group: "lan".to_owned(),
            ip: None,
            note: String::new(),
        }
    }

    #[test]
    fn mac_addresses_are_normalized() {
        assert_eq!(
            normalize_mac("AA-BB-CC-00-11-22").as_deref(),
            Some("aa:bb:cc:00:11:22")
        );
        assert_eq!(
            normalize_mac(" aa:bb:cc:00:11:22 ").as_deref(),
            Some("aa:bb:cc:00:11:22")
        );
        for invalid in [
            "",
            "aa:bb:cc:00:11",
            "aa:bb:cc:00:11:2g",
            "aabbcc001122",
            "aa:bb:cc:00:11:223",
        ] {
            assert_eq!(normalize_mac(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn names_must_be_dns_names() {
        for valid in ["OMV", "HueBridge", "living-room-1", "a"] {
            assert!(is_valid_name(valid), "{valid}");
        }
        for invalid in ["", "-a", "a-", "a_b", "a.b", "a b", &"x".repeat(64)] {
            assert!(!is_valid_name(invalid), "{invalid}");
        }
    }

    #[test]
    fn duplicates_and_unknown_groups_are_rejected() {
        let mut list = DeviceList {
            devices: vec![device("a", "00:00:00:00:00:01"), device("A", "00:00:00:00:00:02")],
        };
        assert!(list.validate(&groups()).is_err(), "names differ only in case");

        list.devices[1].name = "b".to_owned();
        list.devices[1].mac = "00:00:00:00:00:01".to_owned();
        assert!(list.validate(&groups()).is_err(), "same MAC");

        list.devices[1].mac = "00:00:00:00:00:02".to_owned();
        list.devices[0].ip = Some(Ipv4Addr::new(192, 0, 2, 10));
        list.devices[1].ip = Some(Ipv4Addr::new(192, 0, 2, 10));
        assert!(list.validate(&groups()).is_err(), "same IP");

        list.devices[1].ip = None;
        list.devices[1].group = "guest".to_owned();
        assert!(list.validate(&groups()).is_err(), "unknown group");

        list.devices[1].group = "iot".to_owned();
        assert!(list.validate(&groups()).is_ok());
    }

    #[test]
    fn save_and_load_keep_the_list() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("devices.toml");
        let mut list = DeviceList {
            devices: vec![device("OMV", "00:00:00:00:00:01")],
        };
        list.devices[0].ip = Some(Ipv4Addr::new(192, 0, 2, 2));
        list.devices[0].note = "server".to_owned();

        list.save(&path, &groups()).unwrap();
        assert_eq!(DeviceList::load(&path, &groups()).unwrap(), list);

        let mode = fs::metadata(&path).unwrap().permissions();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777, 0o600);
        assert!(!path.with_extension("toml.tmp").exists());
    }

    #[test]
    fn missing_file_is_an_empty_list_and_unknown_fields_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("devices.toml");
        assert_eq!(DeviceList::load(&path, &groups()).unwrap(), DeviceList::default());

        fs::write(
            &path,
            "[[device]]\nname = \"a\"\nmac = \"00:00:00:00:00:01\"\ngroup = \"lan\"\nvlan = 5\n",
        )
        .unwrap();
        assert!(matches!(DeviceList::load(&path, &groups()), Err(Error::Parse(_))));
    }
}
