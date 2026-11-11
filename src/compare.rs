//! Compares the device list with what a plugin reports, and lists the discrepancies.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use crate::config::Group;
use crate::devices::DeviceList;

/// A device on the network, for example from the DHCP leases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Present {
    /// MAC address, lowercase with colons.
    pub mac: String,
    /// Address it uses, if known.
    pub ip: Option<Ipv4Addr>,
    /// Host name it sent, if any.
    pub hostname: String,
}

/// What a system has configured for a device, for example a static lease or a DNS record.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Assigned {
    /// MAC address, lowercase with colons.
    pub mac: String,
    /// Name in the entry.
    pub name: String,
    /// Address in the entry, if it has one.
    pub ip: Option<Ipv4Addr>,
    /// VLAN in the entry, if the plugin assigns VLANs.
    pub vlan: Option<u16>,
}

/// What a plugin reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// Devices on the network now.
    pub present: Vec<Present>,
    /// What a system has configured for devices; `None` for a plugin that only reports.
    pub assigned: Option<Vec<Assigned>>,
    /// The entries only cover some devices and only say their VLAN, like the ports of one switch.
    pub partial: bool,
    /// Remarks of the plugin, for example data it could not read.
    pub notes: Vec<String>,
}

/// One discrepancy between the device list and a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A device on the network that is not in the list.
    Unknown {
        /// MAC address.
        mac: String,
        /// Address it uses.
        ip: Option<Ipv4Addr>,
        /// Host name it sent.
        hostname: String,
    },
    /// A device of the list without an entry in the plugin.
    Missing {
        /// Name in the list.
        device: String,
    },
    /// The entry has another name than the list.
    WrongName {
        /// Name in the list.
        device: String,
        /// Name in the entry.
        actual: String,
    },
    /// The entry has another address than the list.
    WrongIp {
        /// Name in the list.
        device: String,
        /// Address in the list.
        expected: Option<Ipv4Addr>,
        /// Address in the entry.
        actual: Option<Ipv4Addr>,
    },
    /// The entry puts the device in another VLAN than its group.
    WrongVlan {
        /// Name in the list.
        device: String,
        /// VLAN of the group.
        expected: u16,
        /// VLAN in the entry.
        actual: u16,
    },
    /// The device should set its address itself but has a DHCP lease.
    UnexpectedLease {
        /// Name in the list.
        device: String,
    },
    /// An entry for a MAC address that is not in the list.
    Foreign {
        /// MAC address.
        mac: String,
        /// Name in the entry.
        name: String,
    },
}

/// Compares the list with the observation of one plugin. The findings are sorted: unknown devices first, then
/// differences per device, then foreign entries.
#[must_use]
pub fn compare(list: &DeviceList, groups: &[Group], observation: &Observation) -> Vec<Finding> {
    let known: HashSet<&str> = list.interfaces.iter().map(|device| device.mac.as_str()).collect();
    let vlans: HashMap<&str, u16> = groups
        .iter()
        .map(|group| (group.name.as_str(), group.vlan))
        .collect();
    let mut findings = Vec::new();

    let mut reported = HashSet::new();
    for seen in &observation.present {
        if !known.contains(seen.mac.as_str()) && reported.insert(seen.mac.as_str()) {
            findings.push(Finding::Unknown {
                mac: seen.mac.clone(),
                ip: seen.ip,
                hostname: seen.hostname.clone(),
            });
        }
    }

    let Some(entries) = &observation.assigned else {
        return findings;
    };
    let by_mac: HashMap<&str, &Assigned> = entries.iter().map(|entry| (entry.mac.as_str(), entry)).collect();
    for device in &list.interfaces {
        let Some(entry) = by_mac.get(device.mac.as_str()) else {
            // Without a fixed address there is nothing the system should have configured.
            if !observation.partial && device.ip.is_some() && !device.self_assigned {
                findings.push(Finding::Missing {
                    device: device.name.clone(),
                });
            }
            continue;
        };
        // Entries without a name, like a Wi-Fi station without a static lease, have no name to compare.
        if !observation.partial && !entry.name.is_empty() && !entry.name.eq_ignore_ascii_case(&device.name) {
            findings.push(Finding::WrongName {
                device: device.name.clone(),
                actual: entry.name.clone(),
            });
        }
        if !observation.partial {
            if device.self_assigned {
                if entry.ip.is_some() {
                    findings.push(Finding::UnexpectedLease {
                        device: device.name.clone(),
                    });
                }
            } else if entry.ip != device.ip {
                findings.push(Finding::WrongIp {
                    device: device.name.clone(),
                    expected: device.ip,
                    actual: entry.ip,
                });
            }
        }
        if let (Some(actual), Some(&expected)) = (entry.vlan, vlans.get(device.group.as_str()))
            && actual != expected
        {
            findings.push(Finding::WrongVlan {
                device: device.name.clone(),
                expected,
                actual,
            });
        }
    }
    for entry in entries {
        if !observation.partial && !known.contains(entry.mac.as_str()) {
            findings.push(Finding::Foreign {
                mac: entry.mac.clone(),
                name: entry.name.clone(),
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests;
