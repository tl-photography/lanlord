//! Compares the device list with what a plugin reports, and lists the discrepancies.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use crate::config::Group;
use crate::devices::DeviceList;

/// A device a plugin has seen on the network, for example in the DHCP leases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// MAC address, lowercase with colons.
    pub mac: String,
    /// Address it uses, if known.
    pub ip: Option<Ipv4Addr>,
    /// Host name it sent, if any.
    pub hostname: String,
}

/// An entry a plugin keeps for a device, for example a static lease or a DNS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// MAC address, lowercase with colons.
    pub mac: String,
    /// Name in the entry.
    pub name: String,
    /// Address in the entry, if it has one.
    pub ip: Option<Ipv4Addr>,
    /// VLAN in the entry, if the plugin assigns VLANs.
    pub vlan: Option<u16>,
}

/// A device connected to a Wi-Fi interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiClient {
    /// MAC address, lowercase with colons.
    pub mac: String,
    /// Where it is connected, for example `router: Home (5 GHz)`.
    pub access_point: String,
    /// Signal in dBm, if known.
    pub signal: Option<i64>,
}

/// What a plugin reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// Devices seen on the network.
    pub seen: Vec<Seen>,
    /// Entries of a plugin that configures devices; `None` for plugins that only report.
    pub entries: Option<Vec<Entry>>,
    /// Devices connected to the plugin's Wi-Fi.
    pub wifi: Vec<WifiClient>,
    /// Devices the plugin talked to lately, whatever their address comes from; `None` if it cannot tell. Not for
    /// finding unknown devices: this also holds neighbours outside the network, like the provider's gateway.
    pub neighbours: Option<Vec<Seen>>,
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
    /// The device has a static lease but talks without one: its address is set on the device.
    LeaseUnused {
        /// Name in the list.
        device: String,
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

/// Devices that do not get their address the way the list says. Only a plugin that hands out leases can tell.
fn address_source(list: &DeviceList, observation: &Observation) -> Vec<Finding> {
    let leases: HashSet<&str> = observation
        .seen
        .iter()
        .filter(|seen| seen.ip.is_some())
        .map(|seen| seen.mac.as_str())
        .collect();
    let Some(neighbours) = observation.neighbours.as_ref().filter(|_| !leases.is_empty()) else {
        return Vec::new();
    };
    list.devices
        .iter()
        .filter(|device| device.ip.is_some())
        .filter_map(|device| {
            let has_lease = leases.contains(device.mac.as_str());
            let device_name = device.name.clone();
            if device.self_assigned {
                return has_lease.then_some(Finding::UnexpectedLease { device: device_name });
            }
            (!has_lease && neighbours.iter().any(|seen| seen.mac == device.mac))
                .then_some(Finding::LeaseUnused { device: device_name })
        })
        .collect()
}

/// Compares the list with the observation of one plugin. The findings are sorted: unknown devices first, then
/// differences per device, then foreign entries.
#[must_use]
pub fn compare(list: &DeviceList, groups: &[Group], observation: &Observation) -> Vec<Finding> {
    let known: HashSet<&str> = list.devices.iter().map(|device| device.mac.as_str()).collect();
    let vlans: HashMap<&str, u16> = groups
        .iter()
        .map(|group| (group.name.as_str(), group.vlan))
        .collect();
    let mut findings = Vec::new();

    let mut reported = HashSet::new();
    for seen in &observation.seen {
        if !known.contains(seen.mac.as_str()) && reported.insert(seen.mac.as_str()) {
            findings.push(Finding::Unknown {
                mac: seen.mac.clone(),
                ip: seen.ip,
                hostname: seen.hostname.clone(),
            });
        }
    }

    findings.extend(address_source(list, observation));

    let Some(entries) = &observation.entries else {
        return findings;
    };
    let by_mac: HashMap<&str, &Entry> = entries.iter().map(|entry| (entry.mac.as_str(), entry)).collect();
    for device in &list.devices {
        let Some(entry) = by_mac.get(device.mac.as_str()) else {
            if !device.self_assigned {
                findings.push(Finding::Missing {
                    device: device.name.clone(),
                });
            }
            continue;
        };
        // Entries without a name, like a Wi-Fi station without a static lease, have no name to compare.
        if !entry.name.is_empty() && !entry.name.eq_ignore_ascii_case(&device.name) {
            findings.push(Finding::WrongName {
                device: device.name.clone(),
                actual: entry.name.clone(),
            });
        }
        if !device.self_assigned && entry.ip != device.ip {
            findings.push(Finding::WrongIp {
                device: device.name.clone(),
                expected: device.ip,
                actual: entry.ip,
            });
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
        if !known.contains(entry.mac.as_str()) {
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
