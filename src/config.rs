//! The groups and their VLANs in `groups.toml`, set up in the interface and saved by lanlord.

use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::devices::{Error, is_valid_name, write_private};
use crate::leases::Network;

/// A group of devices, mapped to a VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Short name, used in the device list.
    pub name: String,
    /// VLAN id, 1 to 4094.
    pub vlan: u16,
    /// The network of the VLAN, like `192.0.2.0/24`; empty if it is not set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subnet: String,
    /// Text shown in the interface.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
}

/// Reads `192.0.2.0/24`.
#[must_use]
pub fn parse_subnet(text: &str) -> Option<Network> {
    let (address, prefix) = text.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= 32).then_some(Network {
        address: address.parse().ok()?,
        prefix,
    })
}

impl Group {
    /// The network, if one is set.
    #[must_use]
    pub fn network(&self) -> Option<Network> {
        parse_subnet(&self.subnet)
    }

    /// A warning if a fixed address is outside the network of this group.
    #[must_use]
    pub fn address_warning(&self, ip: Ipv4Addr) -> Option<String> {
        self.network()
            .filter(|network| !network.contains(ip))
            .map(|_| format!("{ip} is outside {} ({})", self.title(), self.subnet))
    }

    /// The label, or the name if there is no label.
    #[must_use]
    pub fn title(&self) -> &str {
        if self.label.is_empty() {
            &self.name
        } else {
            &self.label
        }
    }
}

/// The groups. Empty until they are set up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Group for devices that are not in the list; empty while there are no groups.
    #[serde(default)]
    pub default_group: String,
    /// All groups.
    #[serde(default, rename = "group")]
    pub groups: Vec<Group>,
}

impl Config {
    /// Reads and checks the groups. A missing file means no groups yet.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, is not valid TOML, or the groups are invalid.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(Error::Parse(format!("{}: {error}", path.display()))),
        };
        let config: Self =
            toml::from_str(&content).map_err(|error| Error::Parse(format!("{}: {error}", path.display())))?;
        config.validate()?;
        Ok(config)
    }

    /// Checks and writes the groups, readable for the owner only.
    ///
    /// # Errors
    ///
    /// If the groups are invalid or the file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        self.validate()?;
        let content =
            toml::to_string_pretty(self).map_err(|error| Error::Invalid(format!("cannot write: {error}")))?;
        write_private(path, &content)
    }

    /// Names of all groups, in the order of the file.
    #[must_use]
    pub fn group_names(&self) -> Vec<String> {
        self.groups.iter().map(|group| group.name.clone()).collect()
    }

    /// Checks names, VLANs and the default group.
    ///
    /// # Errors
    ///
    /// The first problem found.
    pub fn validate(&self) -> Result<(), Error> {
        let mut names = HashSet::new();
        let mut vlans = HashSet::new();
        for group in &self.groups {
            if !is_valid_name(&group.name) {
                return Err(Error::Invalid(format!("invalid group name: {}", group.name)));
            }
            if !group.subnet.is_empty() && group.network().is_none() {
                return Err(Error::Invalid(format!(
                    "{}: the subnet must look like 192.0.2.0/24",
                    group.name
                )));
            }
            if !(1..=4094).contains(&group.vlan) {
                return Err(Error::Invalid(format!("{}: VLAN must be 1 to 4094", group.name)));
            }
            if !names.insert(&group.name) {
                return Err(Error::Invalid(format!("duplicate group: {}", group.name)));
            }
            if !vlans.insert(group.vlan) {
                return Err(Error::Invalid(format!(
                    "{}: duplicate VLAN {}",
                    group.name, group.vlan
                )));
            }
        }
        let networks: Vec<(&Group, Network)> = self
            .groups
            .iter()
            .filter_map(|group| group.network().map(|network| (group, network)))
            .collect();
        for (index, (group, network)) in networks.iter().enumerate() {
            for (other, other_network) in &networks[index + 1..] {
                if network.contains(other_network.address) || other_network.contains(network.address) {
                    return Err(Error::Invalid(format!(
                        "the subnets of {} and {} overlap",
                        group.name, other.name
                    )));
                }
            }
        }
        if !self.groups.is_empty() && !names.contains(&self.default_group) {
            return Err(Error::Invalid(format!(
                "unknown default group: {}",
                self.default_group
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
