//! Plans the static DHCP leases of an `OpenWrt` router (uci `dhcp` `host` sections) from the device list.
//!
//! lanlord owns the sections it names `lanlord_<device>`. It takes over an unnamed entry of a device's MAC address
//! when it sets that device's lease, and leaves every other entry alone. A device whose address is not in a
//! network the router serves is waiting: its entry stays as it is until that network exists.

use std::net::Ipv4Addr;

use crate::devices::DeviceList;
use crate::preview::{Preview, Step};

/// The uci configuration of the static leases.
pub const CONFIG: &str = "dhcp";
/// Prefix of the sections lanlord owns.
const OWN_PREFIX: &str = "lanlord_";

/// A `host` section as the router has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSection {
    /// Section id, for example `cfg0a1b2c` or `lanlord_omv`.
    pub id: String,
    /// Name option.
    pub name: String,
    /// MAC addresses, lowercase with colons.
    pub macs: Vec<String>,
    /// Address option, as text.
    pub ip: String,
    /// `dns` option.
    pub dns: String,
}

/// A network the router serves with DHCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    /// Address of the router in the network.
    pub address: Ipv4Addr,
    /// Prefix length.
    pub prefix: u8,
}

impl Network {
    /// Whether the address is in this network.
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::MAX
            .checked_shl(32 - u32::from(self.prefix.min(32)))
            .unwrap_or(0);
        u32::from(ip) & mask == u32::from(self.address) & mask
    }
}

/// One change of a uci section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A new named `host` section.
    Add {
        /// Section id.
        section: String,
        /// Options.
        values: Vec<(String, String)>,
        /// What it does, for people.
        why: String,
    },
    /// Options of an existing section.
    Set {
        /// Section id.
        section: String,
        /// Options that change.
        values: Vec<(String, String)>,
        /// What it does, for people.
        why: String,
    },
    /// A section that goes away.
    Delete {
        /// Section id.
        section: String,
        /// What it does, for people.
        why: String,
    },
}

impl Change {
    /// What the change does.
    #[must_use]
    pub fn description(&self) -> &str {
        match self {
            Self::Add { why, .. } | Self::Set { why, .. } | Self::Delete { why, .. } => why,
        }
    }

    /// The change as `uci` commands, like `LuCI` shows them.
    #[must_use]
    pub fn commands(&self) -> Vec<String> {
        let option = |section: &str, (key, value): &(String, String)| {
            format!("uci set {CONFIG}.{section}.{key}='{value}'")
        };
        match self {
            Self::Add { section, values, .. } => std::iter::once(format!("uci set {CONFIG}.{section}=host"))
                .chain(values.iter().map(|value| option(section, value)))
                .collect(),
            Self::Set { section, values, .. } => values.iter().map(|value| option(section, value)).collect(),
            Self::Delete { section, .. } => vec![format!("uci delete {CONFIG}.{section}")],
        }
    }
}

/// The changes for one router and what is left as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Changes, in the order they are made.
    pub changes: Vec<Change>,
    /// Devices that are left as they are, and why.
    pub notes: Vec<String>,
}

impl Plan {
    /// The plan as steps for the apply page.
    #[must_use]
    pub fn preview(&self) -> Preview {
        Preview {
            steps: self
                .changes
                .iter()
                .map(|change| Step {
                    description: change.description().to_owned(),
                    details: change.commands(),
                })
                .collect(),
            notes: self.notes.clone(),
        }
    }

    /// The digest of [`Plan::preview`].
    #[must_use]
    pub fn digest(&self) -> String {
        self.preview().digest()
    }
}

/// Section id of a device's lease: `lanlord_` and the name in lowercase, `-` as `_`.
#[must_use]
pub fn section_id(name: &str) -> String {
    format!("{OWN_PREFIX}{}", name.to_ascii_lowercase().replace('-', "_"))
}

fn wanted_values(name: &str, mac: &str, ip: Ipv4Addr) -> Vec<(String, String)> {
    [
        ("name", name.to_owned()),
        ("mac", mac.to_owned()),
        ("ip", ip.to_string()),
        ("dns", "1".to_owned()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

fn label(host: &HostSection) -> String {
    if host.name.is_empty() {
        host.id.clone()
    } else {
        format!("{} ({})", host.name, host.id)
    }
}

/// Why a device cannot get its lease now: a shared entry with its MAC, or its address in another entry.
fn left_out(
    others: &[&HostSection],
    hosts: &[HostSection],
    id: &str,
    mac: &str,
    ip: Ipv4Addr,
    deleted: &[&str],
) -> Option<String> {
    if let Some(shared) = others.iter().find(|host| host.macs.len() > 1) {
        return Some(format!(
            "entry {} holds several MAC addresses, split it on the router",
            label(shared)
        ));
    }
    hosts
        .iter()
        .find(|host| {
            host.id != id
                && !host.macs.iter().any(|other| other == mac)
                && host.ip.parse::<Ipv4Addr>().ok() == Some(ip)
                && !deleted.contains(&host.id.as_str())
        })
        .map(|taken| format!("{ip} is already the address of entry {}", label(taken)))
}

/// The options of an own section that differ from the wanted ones.
fn update(device: &str, own: &HostSection, wanted: Vec<(String, String)>) -> Option<Change> {
    let current = |key: &str| match key {
        "name" => own.name.clone(),
        "mac" => own.macs.join(" "),
        "ip" => own.ip.clone(),
        _ => own.dns.clone(),
    };
    let values: Vec<(String, String)> = wanted
        .into_iter()
        .filter(|(key, value)| current(key) != *value)
        .collect();
    if values.is_empty() {
        return None;
    }
    let keys: Vec<&str> = values.iter().map(|(key, _)| key.as_str()).collect();
    Some(Change::Set {
        section: own.id.clone(),
        why: format!("{device}: change {}", keys.join(", ")),
        values,
    })
}

/// Plans the static leases: devices with an address in a served network get a `lanlord_` section, sections of
/// devices without an address or of removed devices go away.
#[must_use]
pub fn plan(list: &DeviceList, hosts: &[HostSection], networks: &[Network]) -> Plan {
    let mut plan = Plan::default();
    let mut kept_own: Vec<String> = Vec::new();
    let mut deleted: Vec<&str> = Vec::new();

    for device in &list.devices {
        let id = section_id(&device.name);
        let own = hosts.iter().find(|host| host.id == id);
        let Some(ip) = device.ip.filter(|_| !device.self_assigned) else {
            if let Some(own) = own {
                let reason = if device.self_assigned {
                    "sets its address itself"
                } else {
                    "has no fixed address any more"
                };
                plan.changes.push(Change::Delete {
                    section: own.id.clone(),
                    why: format!("{} {reason}: remove its static lease", device.name),
                });
                deleted.push(&own.id);
            }
            continue;
        };
        if !networks.iter().any(|network| network.contains(ip)) {
            plan.notes.push(format!(
                "{} waits: {ip} is not in a network this router serves, its entry stays as it is",
                device.name
            ));
            kept_own.push(id);
            continue;
        }
        let others: Vec<&HostSection> = hosts
            .iter()
            .filter(|host| host.id != id && host.macs.contains(&device.mac))
            .collect();
        if let Some(reason) = left_out(&others, hosts, &id, &device.mac, ip, &deleted) {
            plan.notes.push(format!("{} is left out: {reason}", device.name));
            kept_own.push(id);
            continue;
        }
        for other in others {
            // Another device's own section with this MAC is that device's business; it is fixed with that device.
            if other.id.starts_with(OWN_PREFIX) {
                continue;
            }
            plan.changes.push(Change::Delete {
                section: other.id.clone(),
                why: format!("{}: replace entry {} by lanlord's own", device.name, label(other)),
            });
            deleted.push(&other.id);
        }
        let wanted = wanted_values(&device.name, &device.mac, ip);
        match own {
            None => plan.changes.push(Change::Add {
                section: id.clone(),
                values: wanted,
                why: format!("{}: static lease {ip}", device.name),
            }),
            Some(own) => plan.changes.extend(update(&device.name, own, wanted)),
        }
        kept_own.push(id);
    }

    for host in hosts {
        if host.id.starts_with(OWN_PREFIX)
            && !kept_own.contains(&host.id)
            && !deleted.contains(&host.id.as_str())
        {
            let renamed = list
                .devices
                .iter()
                .find(|device| host.macs.contains(&device.mac) && device.name != host.name);
            let why = match renamed {
                Some(device) => {
                    plan.notes.push(format!(
                        "{} is now {}: its DNS name changes, update what still uses the old name",
                        host.name, device.name
                    ));
                    format!("Rename {} to {}: remove the old lease", label(host), device.name)
                }
                None => format!("Remove {}: no device in the list", label(host)),
            };
            plan.changes.push(Change::Delete {
                section: host.id.clone(),
                why,
            });
        }
    }
    plan
}

#[cfg(test)]
mod tests;
