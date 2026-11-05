//! Plans the static DHCP leases of an `OpenWrt` router (uci `dhcp` `host` sections) from the device list.
//!
//! lanlord owns the sections it names `lanlord_<device>`. It takes over an unnamed entry of a device's MAC address
//! when it sets that device's lease, and leaves every other entry alone. A device whose address is not in a
//! network the router serves is waiting: its entry stays as it is until that network exists.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::devices::DeviceList;

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
    /// A short fingerprint of the changes: apply only goes ahead if the changes are still the ones shown.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut text = String::new();
        for change in &self.changes {
            for command in change.commands() {
                text.push_str(&command);
                text.push('\n');
            }
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
        digest.as_ref()[..16].iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
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
        let Some(ip) = device.ip else {
            if let Some(own) = own {
                plan.changes.push(Change::Delete {
                    section: own.id.clone(),
                    why: format!(
                        "{} has no fixed address any more: remove its static lease",
                        device.name
                    ),
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
            plan.changes.push(Change::Delete {
                section: host.id.clone(),
                why: format!("Remove {}: no device in the list", label(host)),
            });
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::Device;

    fn device(name: &str, mac: &str, ip: Option<[u8; 4]>) -> Device {
        Device {
            name: name.to_owned(),
            mac: mac.to_owned(),
            group: "lan".to_owned(),
            ip: ip.map(Ipv4Addr::from),
            note: String::new(),
        }
    }

    fn host(id: &str, name: &str, macs: &[&str], ip: &str) -> HostSection {
        HostSection {
            id: id.to_owned(),
            name: name.to_owned(),
            macs: macs.iter().map(|mac| (*mac).to_owned()).collect(),
            ip: ip.to_owned(),
            dns: "1".to_owned(),
        }
    }

    const LAN: Network = Network {
        address: Ipv4Addr::new(192, 0, 2, 1),
        prefix: 24,
    };

    fn list(devices: Vec<Device>) -> DeviceList {
        DeviceList { devices }
    }

    #[test]
    fn networks_contain_their_addresses() {
        assert!(LAN.contains(Ipv4Addr::new(192, 0, 2, 200)));
        assert!(!LAN.contains(Ipv4Addr::new(192, 0, 3, 2)));
        let all = Network {
            address: Ipv4Addr::new(10, 0, 0, 1),
            prefix: 0,
        };
        assert!(all.contains(Ipv4Addr::new(198, 51, 100, 1)));
    }

    #[test]
    fn section_ids_are_uci_names() {
        assert_eq!(section_id("Living-Room-TV"), "lanlord_living_room_tv");
    }

    #[test]
    fn an_unnamed_entry_is_taken_over() {
        let devices = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
        let hosts = [host("cfg01", "OMV", &["00:00:00:00:00:01"], "192.0.2.2")];
        let plan = plan(&devices, &hosts, &[LAN]);
        assert_eq!(plan.changes.len(), 2);
        assert_eq!(plan.changes[0].commands(), ["uci delete dhcp.cfg01"]);
        assert_eq!(
            plan.changes[1].commands(),
            [
                "uci set dhcp.lanlord_omv=host",
                "uci set dhcp.lanlord_omv.name='OMV'",
                "uci set dhcp.lanlord_omv.mac='00:00:00:00:00:01'",
                "uci set dhcp.lanlord_omv.ip='192.0.2.2'",
                "uci set dhcp.lanlord_omv.dns='1'",
            ]
        );
        assert!(plan.changes[1].description().contains("static lease"));
    }

    #[test]
    fn own_sections_only_change_what_differs() {
        let devices = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 3]))]);
        let hosts = [host("lanlord_omv", "OMV", &["00:00:00:00:00:01"], "192.0.2.2")];
        let plan = plan(&devices, &hosts, &[LAN]);
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(
            plan.changes[0].commands(),
            ["uci set dhcp.lanlord_omv.ip='192.0.2.3'"]
        );
        assert_eq!(plan.changes[0].description(), "OMV: change ip");

        let same = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
        assert_eq!(super::plan(&same, &hosts, &[LAN]), Plan::default());
    }

    #[test]
    fn devices_outside_the_served_networks_wait() {
        let devices = list(vec![device(
            "plug",
            "00:00:00:00:00:02",
            Some([198, 51, 100, 20]),
        )]);
        let hosts = [
            host("cfg02", "plug", &["00:00:00:00:00:02"], "192.0.2.20"),
            host("lanlord_plug", "plug", &["00:00:00:00:00:02"], "192.0.2.20"),
        ];
        let plan = plan(&devices, &hosts, &[LAN]);
        assert_eq!(plan.changes, []);
        assert!(plan.notes[0].starts_with("plug waits"));
    }

    #[test]
    fn leases_of_removed_devices_and_devices_without_address_go() {
        let devices = list(vec![device("tv", "00:00:00:00:00:03", None)]);
        let hosts = [
            host("lanlord_tv", "tv", &["00:00:00:00:00:03"], "192.0.2.30"),
            host("lanlord_old", "old", &["00:00:00:00:00:09"], "192.0.2.90"),
            host("cfg09", "foreign", &["00:00:00:00:00:08"], "192.0.2.80"),
        ];
        let plan = plan(&devices, &hosts, &[LAN]);
        let commands: Vec<String> = plan.changes.iter().flat_map(Change::commands).collect();
        assert_eq!(
            commands,
            ["uci delete dhcp.lanlord_tv", "uci delete dhcp.lanlord_old"]
        );
        assert!(plan.changes[1].description().contains("old (lanlord_old)"));
    }

    #[test]
    fn shared_entries_and_taken_addresses_are_left_out() {
        let devices = list(vec![
            device("a", "00:00:00:00:00:01", Some([192, 0, 2, 10])),
            device("b", "00:00:00:00:00:02", Some([192, 0, 2, 11])),
        ]);
        let hosts = [
            host(
                "cfg01",
                "",
                &["00:00:00:00:00:01", "00:00:00:00:00:05"],
                "192.0.2.10",
            ),
            host("cfg02", "printer", &["00:00:00:00:00:06"], "192.0.2.11"),
        ];
        let plan = plan(&devices, &hosts, &[LAN]);
        assert_eq!(plan.changes, []);
        assert!(plan.notes[0].contains("entry cfg01 holds several"));
        assert!(plan.notes[1].contains("address of entry printer (cfg02)"));
    }

    #[test]
    fn a_mac_moved_to_another_device_is_fixed_with_that_device() {
        let devices = list(vec![
            device("new", "00:00:00:00:00:01", Some([192, 0, 2, 10])),
            device("old", "00:00:00:00:00:02", Some([192, 0, 2, 11])),
        ]);
        let hosts = [host("lanlord_old", "old", &["00:00:00:00:00:01"], "192.0.2.11")];
        let plan = plan(&devices, &hosts, &[LAN]);
        let commands: Vec<String> = plan.changes.iter().flat_map(Change::commands).collect();
        assert_eq!(commands[0], "uci set dhcp.lanlord_new=host");
        assert!(commands.contains(&"uci set dhcp.lanlord_old.mac='00:00:00:00:00:02'".to_owned()));
    }

    #[test]
    fn the_digest_follows_the_changes() {
        let devices = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 2]))]);
        let first = plan(&devices, &[], &[LAN]);
        assert_eq!(first.digest().len(), 32);
        assert_eq!(first.digest(), plan(&devices, &[], &[LAN]).digest());
        let other = list(vec![device("OMV", "00:00:00:00:00:01", Some([192, 0, 2, 3]))]);
        assert_ne!(first.digest(), plan(&other, &[], &[LAN]).digest());
    }
}
