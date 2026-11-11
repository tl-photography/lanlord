//! The networks of the groups, worked out once for every target that builds them: which groups become networks, the
//! router's address and DHCP pool in each, the Wi-Fi of a group, where the DNS service is, which groups may reach a
//! network and which single ports it may reach elsewhere. Nothing here knows a system: a target turns it into its own
//! configuration.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::BuildHasher;
use std::net::Ipv4Addr;

use crate::config::Group;
use crate::devices::Interface;
use crate::plan::Plan;

/// The VLAN of the LAN. Its group is the network the router has already, never one lanlord builds.
pub const LAN_VLAN: u16 = 1;
/// First host of a DHCP pool, counted from the network address.
pub const POOL_START: u32 = 100;
/// Number of addresses in a DHCP pool.
pub const POOL_LIMIT: u32 = 150;

/// The netmask of a prefix length.
#[must_use]
pub fn netmask(prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(prefix.min(32))).unwrap_or(0))
}

/// The router's own address in the network of a group, the first host, with the prefix length. `None` without a
/// subnet, or with one too small for hosts.
#[must_use]
pub fn gateway(group: &Group) -> Option<(Ipv4Addr, u8)> {
    let network = group.network()?;
    let base = u32::from(network.address) & u32::from(netmask(network.prefix));
    (network.prefix <= 30).then(|| (Ipv4Addr::from(base + 1), network.prefix))
}

/// The groups that can become networks of their own: every group but the LAN, in the order of the list.
#[must_use]
pub fn candidates(plan: &Plan) -> Vec<&Group> {
    plan.groups
        .iter()
        .filter(|group| group.vlan != LAN_VLAN)
        .collect()
}

/// The Wi-Fi network of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wifi<'a> {
    /// The SSID.
    pub ssid: &'a str,
    /// The password.
    pub key: &'a str,
    /// The bands it runs on; empty for all.
    pub bands: &'a [String],
}

impl Wifi<'_> {
    /// Whether it runs on a radio of this band.
    #[must_use]
    pub fn on(&self, band: &str) -> bool {
        self.bands.is_empty() || self.bands.iter().any(|own| own == band)
    }
}

/// The Wi-Fi of a group, if it has an SSID of its own. `passwords` holds the password per group name; without one
/// the Wi-Fi is left out and a note says why.
pub fn wifi<'a, S: BuildHasher>(
    group: &'a Group,
    passwords: &'a HashMap<String, String, S>,
    notes: &mut Vec<String>,
) -> Option<Wifi<'a>> {
    if group.ssid.is_empty() {
        return None;
    }
    let Some(key) = passwords.get(&group.name) else {
        notes.push(format!(
            "{}: the password file {} cannot be read, its Wi-Fi is left out",
            group.title(),
            group.ssid_password_file
        ));
        return None;
    };
    Some(Wifi {
        ssid: &group.ssid,
        key,
        bands: &group.ssid_bands,
    })
}

/// The groups a group may be reached from, as far as they exist.
#[must_use]
pub fn sources<'a>(plan: &'a Plan, group: &Group) -> Vec<&'a Group> {
    group
        .reachable_from
        .iter()
        .filter_map(|source| plan.groups.iter().find(|other| &other.name == source))
        .collect()
}

/// A single port on a device elsewhere that a network may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port<'a> {
    /// The interface of the device.
    pub interface: &'a Interface,
    /// Its fixed address.
    pub ip: Ipv4Addr,
    /// The group of the interface; `None` if that group does not exist.
    pub group: Option<&'a Group>,
    /// The port.
    pub port: u16,
    /// `tcp` or `udp`.
    pub proto: String,
}

/// The single ports a group may reach, on every interface of the named device or the named interface. One without a
/// fixed address is left out and a note says why.
pub fn ports<'a>(plan: &'a Plan, group: &Group, notes: &mut Vec<String>) -> Vec<Port<'a>> {
    let mut found = Vec::new();
    for reach in group.reaches() {
        let before = found.len();
        found.extend(
            plan.devices
                .interfaces
                .iter()
                .filter(|interface| {
                    interface.name.eq_ignore_ascii_case(&reach.device)
                        || interface.device.eq_ignore_ascii_case(&reach.device)
                })
                .filter_map(|interface| {
                    Some(Port {
                        interface,
                        ip: interface.ip?,
                        group: plan.groups.iter().find(|other| other.name == interface.group),
                        port: reach.port,
                        proto: reach.proto.clone(),
                    })
                }),
        );
        if found.len() == before {
            notes.push(format!(
                "{}: {} has no fixed address, {}/{} is left out",
                group.title(),
                reach.device,
                reach.port,
                reach.proto
            ));
        }
    }
    found
}

/// The address of the DNS service of all networks, with the group whose network holds it. `None` for the router.
#[must_use]
pub fn dns_service(plan: &Plan) -> Option<(Ipv4Addr, Option<&Group>)> {
    let address = plan.dns()?;
    let group = plan
        .groups
        .iter()
        .find(|group| group.network().is_some_and(|network| network.contains(address)));
    Some((address, group))
}

/// The ports that lead to exactly one known device, ever, with the VLAN of its group: they carry that VLAN untagged
/// and nothing else. `seen` holds every MAC address ever seen per port. Only VLANs in `built` count, so a port never
/// ends up in a network that does not exist.
#[must_use]
pub fn access_ports(
    plan: &Plan,
    ports: &[String],
    seen: &BTreeMap<String, BTreeSet<String>>,
    built: &[u16],
) -> BTreeMap<String, u16> {
    ports
        .iter()
        .filter_map(|port| {
            let macs = seen.get(port)?;
            let [mac] = macs.iter().collect::<Vec<_>>()[..] else {
                return None;
            };
            let interface = plan
                .devices
                .interfaces
                .iter()
                .find(|interface| interface.mac == *mac)?;
            let vlan = plan
                .groups
                .iter()
                .find(|group| group.name == interface.group)?
                .vlan;
            built.contains(&vlan).then(|| (port.clone(), vlan))
        })
        .collect()
}

#[cfg(test)]
mod tests;
