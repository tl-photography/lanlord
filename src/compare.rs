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

/// What a plugin reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// Devices seen on the network.
    pub seen: Vec<Seen>,
    /// Entries of a plugin that configures devices; `None` for plugins that only report.
    pub entries: Option<Vec<Entry>>,
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

    let Some(entries) = &observation.entries else {
        return findings;
    };
    let by_mac: HashMap<&str, &Entry> = entries.iter().map(|entry| (entry.mac.as_str(), entry)).collect();
    for device in &list.devices {
        let Some(entry) = by_mac.get(device.mac.as_str()) else {
            findings.push(Finding::Missing {
                device: device.name.clone(),
            });
            continue;
        };
        // Entries without a name, like a Wi-Fi station without a static lease, have no name to compare.
        if !entry.name.is_empty() && !entry.name.eq_ignore_ascii_case(&device.name) {
            findings.push(Finding::WrongName {
                device: device.name.clone(),
                actual: entry.name.clone(),
            });
        }
        if entry.ip != device.ip {
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
mod tests {
    use super::*;
    use crate::devices::Device;

    fn groups() -> Vec<Group> {
        vec![
            Group {
                name: "lan".to_owned(),
                vlan: 1,
                label: String::new(),
            },
            Group {
                name: "iot".to_owned(),
                vlan: 20,
                label: String::new(),
            },
        ]
    }

    fn list() -> DeviceList {
        DeviceList {
            devices: vec![
                Device {
                    name: "omv".to_owned(),
                    mac: "00:00:00:00:00:01".to_owned(),
                    group: "lan".to_owned(),
                    ip: Some(Ipv4Addr::new(192, 0, 2, 2)),
                    note: String::new(),
                },
                Device {
                    name: "plug".to_owned(),
                    mac: "00:00:00:00:00:02".to_owned(),
                    group: "iot".to_owned(),
                    ip: None,
                    note: String::new(),
                },
            ],
        }
    }

    fn entry(mac: &str, name: &str, ip: Option<Ipv4Addr>, vlan: Option<u16>) -> Entry {
        Entry {
            mac: mac.to_owned(),
            name: name.to_owned(),
            ip,
            vlan,
        }
    }

    #[test]
    fn matching_entries_give_no_findings() {
        let observation = Observation {
            seen: vec![Seen {
                mac: "00:00:00:00:00:01".to_owned(),
                ip: Some(Ipv4Addr::new(192, 0, 2, 2)),
                hostname: "omv".to_owned(),
            }],
            entries: Some(vec![
                entry(
                    "00:00:00:00:00:01",
                    "OMV",
                    Some(Ipv4Addr::new(192, 0, 2, 2)),
                    Some(1),
                ),
                entry("00:00:00:00:00:02", "plug", None, Some(20)),
            ]),
        };
        assert_eq!(compare(&list(), &groups(), &observation), []);
    }

    #[test]
    fn unknown_devices_are_reported_once() {
        let stranger = Seen {
            mac: "00:00:00:00:00:99".to_owned(),
            ip: Some(Ipv4Addr::new(192, 0, 2, 99)),
            hostname: "phone".to_owned(),
        };
        let observation = Observation {
            seen: vec![stranger.clone(), stranger],
            entries: None,
        };
        assert_eq!(
            compare(&list(), &groups(), &observation),
            [Finding::Unknown {
                mac: "00:00:00:00:00:99".to_owned(),
                ip: Some(Ipv4Addr::new(192, 0, 2, 99)),
                hostname: "phone".to_owned(),
            }]
        );
    }

    #[test]
    fn plugins_that_only_report_have_no_missing_entries() {
        let observation = Observation::default();
        assert_eq!(compare(&list(), &groups(), &observation), []);
    }

    #[test]
    fn differences_per_device_and_foreign_entries_are_found() {
        let observation = Observation {
            seen: vec![],
            entries: Some(vec![
                entry(
                    "00:00:00:00:00:01",
                    "server",
                    Some(Ipv4Addr::new(192, 0, 2, 3)),
                    Some(20),
                ),
                entry("00:00:00:00:00:77", "old-tv", None, None),
            ]),
        };
        assert_eq!(
            compare(&list(), &groups(), &observation),
            [
                Finding::WrongName {
                    device: "omv".to_owned(),
                    actual: "server".to_owned(),
                },
                Finding::WrongIp {
                    device: "omv".to_owned(),
                    expected: Some(Ipv4Addr::new(192, 0, 2, 2)),
                    actual: Some(Ipv4Addr::new(192, 0, 2, 3)),
                },
                Finding::WrongVlan {
                    device: "omv".to_owned(),
                    expected: 1,
                    actual: 20,
                },
                Finding::Missing {
                    device: "plug".to_owned(),
                },
                Finding::Foreign {
                    mac: "00:00:00:00:00:77".to_owned(),
                    name: "old-tv".to_owned(),
                },
            ]
        );
    }
}
