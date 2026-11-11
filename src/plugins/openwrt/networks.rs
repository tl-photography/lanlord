//! Plans the networks of an `OpenWrt` router or access point from the groups: a VLAN on the bridge, an interface, and
//! on a router a DHCP pool and a firewall zone that reaches only the internet and the DNS service. The groups it is
//! reachable from may open connections into it, and it may open the single ports it reaches elsewhere. A group with
//! an SSID of its own also gets a Wi-Fi network on every radio.
//!
//! lanlord owns the sections it names `lanlordnet_`. The first network turns the bridge into a VLAN bridge: VLAN 1
//! stays untagged on every port and the LAN interface moves to `<bridge>.1`. That is the one section outside its own
//! that lanlord changes. A bridge with VLANs set up outside lanlord is left alone.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::BuildHasher;
use std::net::Ipv4Addr;

use serde_json::Value;

use crate::config::Group;
use crate::plan::Plan;
use crate::preview::Step;

/// Prefix of the sections lanlord owns.
pub const PREFIX: &str = "lanlordnet_";
/// The configurations lanlord reads and changes, in the order changes are made.
pub const CONFIGS: [&str; 4] = ["network", "dhcp", "firewall", "wireless"];
/// The VLAN of the LAN, untagged on every port.
const LAN_VLAN: u16 = 1;
/// First and last host of a DHCP pool.
const POOL_START: u32 = 100;
const POOL_LIMIT: u32 = 150;
/// Options whose value is a secret and is not shown.
const SECRETS: [&str; 1] = ["key"];

/// The value of an option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opt {
    /// A single value.
    One(String),
    /// A list.
    List(Vec<String>),
}

impl Opt {
    fn one(value: impl Into<String>) -> Self {
        Self::One(value.into())
    }

    fn list(values: &[&str]) -> Self {
        Self::List(values.iter().map(|value| (*value).to_owned()).collect())
    }

    fn text(&self) -> String {
        match self {
            Self::One(value) => value.clone(),
            Self::List(values) => values.join(" "),
        }
    }

    /// The value for a ubus `uci` call.
    #[must_use]
    pub fn json(&self) -> Value {
        match self {
            Self::One(value) => Value::String(value.clone()),
            Self::List(values) => Value::Array(values.iter().cloned().map(Value::String).collect()),
        }
    }
}

/// A uci section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Configuration, like `network`.
    pub config: String,
    /// Section id.
    pub id: String,
    /// Section type, like `interface`.
    pub kind: String,
    /// Options, without the `.name`, `.type` and `.anonymous` keys.
    pub options: BTreeMap<String, Opt>,
}

impl Section {
    fn new(config: &str, id: String, kind: &str, options: &[(&str, Opt)]) -> Self {
        Self {
            config: config.to_owned(),
            id,
            kind: kind.to_owned(),
            options: options
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        }
    }

    fn get(&self, key: &str) -> Option<&Opt> {
        self.options.get(key)
    }

    fn text(&self, key: &str) -> String {
        self.get(key).map(Opt::text).unwrap_or_default()
    }
}

/// Reads the answer of `uci get` for a whole configuration.
#[must_use]
pub fn sections(config: &str, answer: &Value) -> Vec<Section> {
    let Some(values) = answer.get("values").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut sections: Vec<(i64, Section)> = values
        .iter()
        .map(|(id, section)| {
            let options = section
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(key, _)| !key.starts_with('.'))
                .filter_map(|(key, value)| {
                    let value = match value {
                        Value::String(text) => Opt::One(text.clone()),
                        Value::Array(items) => Opt::List(
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect(),
                        ),
                        _ => return None,
                    };
                    Some((key.clone(), value))
                })
                .collect();
            let index = section.get(".index").and_then(Value::as_i64).unwrap_or(i64::MAX);
            let kind = section.get(".type").and_then(Value::as_str).unwrap_or_default();
            (
                index,
                Section {
                    config: config.to_owned(),
                    id: id.clone(),
                    kind: kind.to_owned(),
                    options,
                },
            )
        })
        .collect();
    sections.sort_by_key(|(index, _)| *index);
    sections.into_iter().map(|(_, section)| section).collect()
}

/// What the device does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Routes and serves DHCP: gets interfaces with addresses, DHCP pools and firewall zones.
    Router,
    /// Only bridges into the networks: gets VLANs, interfaces without addresses and Wi-Fi.
    AccessPoint,
}

/// One change of a uci section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A new section with its options.
    Add(Section, String),
    /// Options of an existing section.
    Set {
        /// Configuration.
        config: String,
        /// Section id.
        id: String,
        /// Options that change.
        options: BTreeMap<String, Opt>,
        /// What it does, for people.
        why: String,
    },
    /// A section that goes away.
    Delete {
        /// Configuration.
        config: String,
        /// Section id.
        id: String,
        /// What it does, for people.
        why: String,
    },
}

fn shown(key: &str, value: &Opt) -> String {
    if SECRETS.contains(&key) {
        return "'***'".to_owned();
    }
    match value {
        Opt::One(value) => format!("'{value}'"),
        Opt::List(values) => values
            .iter()
            .map(|value| format!("'{value}'"))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

impl Change {
    /// What the change does.
    #[must_use]
    pub fn description(&self) -> &str {
        match self {
            Self::Add(_, why) | Self::Set { why, .. } | Self::Delete { why, .. } => why,
        }
    }

    /// The change as `uci` commands; secrets are not shown.
    #[must_use]
    pub fn commands(&self) -> Vec<String> {
        let options = |config: &str, id: &str, options: &BTreeMap<String, Opt>| {
            options
                .iter()
                .map(|(key, value)| format!("uci set {config}.{id}.{key}={}", shown(key, value)))
                .collect::<Vec<_>>()
        };
        match self {
            Self::Add(section, _) => std::iter::once(format!(
                "uci set {}.{}={}",
                section.config, section.id, section.kind
            ))
            .chain(options(&section.config, &section.id, &section.options))
            .collect(),
            Self::Set {
                config,
                id,
                options: values,
                ..
            } => options(config, id, values),
            Self::Delete { config, id, .. } => vec![format!("uci delete {config}.{id}")],
        }
    }
}

/// The changes for one device and what is left as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPlan {
    /// Changes, in the order they are made.
    pub changes: Vec<Change>,
    /// Groups that are left out, and why.
    pub notes: Vec<String>,
}

impl NetworkPlan {
    /// The plan as steps for the apply page.
    #[must_use]
    pub fn steps(&self) -> Vec<Step> {
        self.changes
            .iter()
            .map(|change| Step {
                description: change.description().to_owned(),
                details: change.commands(),
            })
            .collect()
    }
}

/// A section id from a name: lowercase, `-` as `_`.
fn id(name: &str) -> String {
    format!("{PREFIX}{}", name.to_ascii_lowercase().replace('-', "_"))
}

fn netmask(prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(prefix.min(32))).unwrap_or(0))
}

/// The router's own address in a network: the first host.
fn router_address(group: &Group) -> Option<(Ipv4Addr, u8)> {
    let network = group.network()?;
    let base = u32::from(network.address) & u32::from(netmask(network.prefix));
    (network.prefix <= 30).then(|| (Ipv4Addr::from(base + 1), network.prefix))
}

/// The firewall zone a group gets: its name, which must not be one the device already uses.
fn zone_name(group: &Group) -> String {
    group.name.to_ascii_lowercase().replace('-', "_")
}

/// The bridge with the LAN, its ports, and the LAN interface.
struct Bridge<'a> {
    name: String,
    ports: Vec<String>,
    lan: &'a Section,
}

fn bridge(current: &[Section]) -> Option<Bridge<'_>> {
    let lan = current
        .iter()
        .find(|section| section.config == "network" && section.kind == "interface" && section.id == "lan")?;
    let device = lan.text("device");
    let name = device
        .split_once('.')
        .map_or(device.as_str(), |(bridge, _)| bridge)
        .to_owned();
    let ports = current
        .iter()
        .find(|section| {
            section.config == "network"
                && section.kind == "device"
                && section.text("type") == "bridge"
                && section.text("name") == name
        })
        .and_then(|section| match section.get("ports") {
            Some(Opt::List(ports)) => Some(ports.clone()),
            Some(Opt::One(port)) => Some(port.split_whitespace().map(str::to_owned).collect()),
            None => None,
        })?;
    Some(Bridge { name, ports, lan })
}

/// The firewall zone that holds an interface.
fn zone_of(current: &[Section], interface: &str) -> Option<String> {
    current
        .iter()
        .filter(|section| section.config == "firewall" && section.kind == "zone")
        .find(|section| match section.get("network") {
            Some(Opt::List(networks)) => networks.iter().any(|network| network == interface),
            Some(Opt::One(networks)) => networks.split_whitespace().any(|network| network == interface),
            None => false,
        })
        .map(|section| section.text("name"))
}

/// The interface, DHCP pool and firewall of a group on a router; `None` without a subnet.
fn router_sections(
    group: &Group,
    base: &str,
    device: &str,
    dns: Option<&(Ipv4Addr, String)>,
) -> Option<Vec<Section>> {
    let (address, prefix) = router_address(group)?;
    let zone = zone_name(group);
    let (dns_address, dns_zone) = dns.cloned().unwrap_or((address, String::new()));
    let both = Opt::list(&["tcp", "udp"]);
    let mut dns_rule = vec![
        ("name", Opt::one(format!("{zone} DNS"))),
        ("src", Opt::one(&zone)),
        ("proto", both.clone()),
        ("dest_port", Opt::one("53")),
        ("target", Opt::one("ACCEPT")),
    ];
    if !dns_zone.is_empty() {
        dns_rule.push(("dest", Opt::one(&dns_zone)));
        dns_rule.push(("dest_ip", Opt::one(dns_address.to_string())));
    }
    Some(vec![
        Section::new(
            "network",
            base.to_owned(),
            "interface",
            &[
                ("device", Opt::one(device)),
                ("proto", Opt::one("static")),
                ("ipaddr", Opt::one(address.to_string())),
                ("netmask", Opt::one(netmask(prefix).to_string())),
            ],
        ),
        Section::new(
            "dhcp",
            base.to_owned(),
            "dhcp",
            &[
                ("interface", Opt::one(base)),
                ("start", Opt::one(POOL_START.to_string())),
                ("limit", Opt::one(POOL_LIMIT.to_string())),
                ("leasetime", Opt::one("12h")),
                ("dhcpv4", Opt::one("server")),
                ("dhcp_option", Opt::List(vec![format!("6,{dns_address}")])),
            ],
        ),
        Section::new(
            "firewall",
            format!("{base}_zone"),
            "zone",
            &[
                ("name", Opt::one(&zone)),
                ("network", Opt::List(vec![base.to_owned()])),
                ("input", Opt::one("REJECT")),
                ("output", Opt::one("ACCEPT")),
                ("forward", Opt::one("REJECT")),
            ],
        ),
        Section::new(
            "firewall",
            format!("{base}_wan"),
            "forwarding",
            &[("src", Opt::one(&zone)), ("dest", Opt::one("wan"))],
        ),
        Section::new(
            "firewall",
            format!("{base}_dhcp"),
            "rule",
            &[
                ("name", Opt::one(format!("{zone} DHCP"))),
                ("src", Opt::one(&zone)),
                ("proto", Opt::one("udp")),
                ("dest_port", Opt::one("67")),
                ("family", Opt::one("ipv4")),
                ("target", Opt::one("ACCEPT")),
            ],
        ),
        Section::new("firewall", format!("{base}_dns"), "rule", &dns_rule),
        Section::new(
            "firewall",
            format!("{base}_dnsredirect"),
            "redirect",
            &[
                ("name", Opt::one(format!("{zone} DNS to {dns_address}"))),
                ("src", Opt::one(&zone)),
                ("proto", both),
                ("src_dport", Opt::one("53")),
                ("dest_ip", Opt::one(dns_address.to_string())),
                ("dest_port", Opt::one("53")),
                ("target", Opt::one("DNAT")),
            ],
        ),
    ])
}

/// The Wi-Fi network of a group on every radio.
fn wifi_sections(group: &Group, base: &str, radios: &[String], key: &str) -> Vec<Section> {
    radios
        .iter()
        .map(|radio| {
            Section::new(
                "wireless",
                format!("{base}_{radio}"),
                "wifi-iface",
                &[
                    ("device", Opt::one(radio)),
                    ("mode", Opt::one("ap")),
                    ("network", Opt::one(base)),
                    ("ssid", Opt::one(&group.ssid)),
                    ("encryption", Opt::one("psk2")),
                    ("key", Opt::one(key)),
                ],
            )
        })
        .collect()
}

/// What a device already has around the networks.
struct Device<'a> {
    bridge: Bridge<'a>,
    /// The id and band of each radio.
    radios: Vec<(String, String)>,
    dns: Option<(Ipv4Addr, String)>,
    /// Ports that lead to one device, with its VLAN.
    access: HashMap<String, u16>,
}

/// The sections a group needs on this device.
fn group_sections<S: BuildHasher>(
    group: &Group,
    device: &Device<'_>,
    role: Role,
    passwords: &HashMap<String, String, S>,
    notes: &mut Vec<String>,
) -> Vec<Section> {
    let base = id(&group.name);
    let vlan = group.vlan.to_string();
    let bridge = &device.bridge;
    let interface = format!("{}.{vlan}", bridge.name);
    let mut wanted = vec![Section::new(
        "network",
        format!("{base}_vlan"),
        "bridge-vlan",
        &[
            ("device", Opt::one(&bridge.name)),
            ("vlan", Opt::one(&vlan)),
            ("ports", vlan_ports(bridge, &device.access, group.vlan)),
        ],
    )];
    match role {
        Role::AccessPoint => wanted.push(Section::new(
            "network",
            base.clone(),
            "interface",
            &[("device", Opt::one(&interface)), ("proto", Opt::one("none"))],
        )),
        Role::Router => {
            wanted.extend(router_sections(group, &base, &interface, device.dns.as_ref()).unwrap_or_default());
        }
    }
    if !group.ssid.is_empty() {
        match passwords.get(&group.name) {
            Some(key) => {
                let radios: Vec<String> = device
                    .radios
                    .iter()
                    .filter(|(_, band)| group.ssid_bands.is_empty() || group.ssid_bands.contains(band))
                    .map(|(radio, _)| radio.clone())
                    .collect();
                if radios.is_empty() {
                    notes.push(format!("{}: no radio for its Wi-Fi", group.title()));
                }
                wanted.extend(wifi_sections(group, &base, &radios, key));
            }
            None => notes.push(format!(
                "{}: the password file {} cannot be read, its Wi-Fi is left out",
                group.title(),
                group.ssid_password_file
            )),
        }
    }
    wanted
}

/// The firewall zone of a group on this router, if it is a network here.
fn zone_here(group: &Group, built: &[&Group], current: &[Section]) -> Option<String> {
    if group.vlan == LAN_VLAN {
        Some(zone_of(current, "lan").unwrap_or_else(|| "lan".to_owned()))
    } else {
        built
            .iter()
            .any(|other| other.name == group.name)
            .then(|| zone_name(group))
    }
}

/// A forwarding into every network from each group it is reachable from.
fn reach_sections(
    plan: &Plan,
    built: &[&Group],
    current: &[Section],
    notes: &mut Vec<String>,
) -> Vec<Section> {
    let mut wanted = Vec::new();
    for group in built {
        for source in &group.reachable_from {
            let Some(from) = plan.groups.iter().find(|other| &other.name == source) else {
                continue;
            };
            let Some(zone) = zone_here(from, built, current) else {
                notes.push(format!(
                    "{}: {} is not a network yet and cannot reach it",
                    group.title(),
                    from.title()
                ));
                continue;
            };
            wanted.push(Section::new(
                "firewall",
                format!("{}_from_{}", id(&group.name), zone_name(from)),
                "forwarding",
                &[("src", Opt::one(zone)), ("dest", Opt::one(zone_name(group)))],
            ));
        }
        wanted.extend(port_sections(plan, group, built, current, notes));
    }
    wanted
}

/// A rule for each single port a network may reach on a device elsewhere.
fn port_sections(
    plan: &Plan,
    group: &Group,
    built: &[&Group],
    current: &[Section],
    notes: &mut Vec<String>,
) -> Vec<Section> {
    let src = zone_name(group);
    let mut wanted = Vec::new();
    for reach in group.reaches() {
        let targets: Vec<_> = plan
            .devices
            .interfaces
            .iter()
            .filter(|interface| {
                interface.name.eq_ignore_ascii_case(&reach.device)
                    || interface.device.eq_ignore_ascii_case(&reach.device)
            })
            .filter_map(|interface| Some((interface, interface.ip?)))
            .collect();
        if targets.is_empty() {
            notes.push(format!(
                "{}: {} has no fixed address, {}/{} is left out",
                group.title(),
                reach.device,
                reach.port,
                reach.proto
            ));
        }
        for (interface, ip) in targets {
            let Some(dest) = plan
                .groups
                .iter()
                .find(|other| other.name == interface.group)
                .and_then(|other| zone_here(other, built, current))
            else {
                notes.push(format!(
                    "{}: {} is not in a network yet, {}/{} is left out",
                    group.title(),
                    interface.name,
                    reach.port,
                    reach.proto
                ));
                continue;
            };
            if dest == src {
                continue;
            }
            wanted.push(Section::new(
                "firewall",
                format!(
                    "{}_to_{}_{}_{}",
                    id(&group.name),
                    interface.name.to_ascii_lowercase().replace('-', "_"),
                    reach.port,
                    reach.proto
                ),
                "rule",
                &[
                    (
                        "name",
                        Opt::one(format!(
                            "{src} to {} {}/{}",
                            interface.name, reach.port, reach.proto
                        )),
                    ),
                    ("src", Opt::one(&src)),
                    ("dest", Opt::one(dest)),
                    ("dest_ip", Opt::one(ip.to_string())),
                    ("dest_port", Opt::one(reach.port.to_string())),
                    ("proto", Opt::one(&reach.proto)),
                    ("family", Opt::one("ipv4")),
                    ("target", Opt::one("ACCEPT")),
                ],
            ));
        }
    }
    wanted
}

/// Where the DNS service is: its address and the firewall zone it is in.
fn dns_target(plan: &Plan, current: &[Section]) -> Option<(Ipv4Addr, String)> {
    let address = plan.dns()?;
    let lan_zone = || zone_of(current, "lan").unwrap_or_else(|| "lan".to_owned());
    let zone = plan
        .groups
        .iter()
        .find(|group| group.network().is_some_and(|network| network.contains(address)))
        .map_or_else(lan_zone, |group| {
            if group.vlan == LAN_VLAN {
                lan_zone()
            } else {
                zone_name(group)
            }
        });
    Some((address, zone))
}

fn find<'a>(current: &'a [Section], config: &str, id: &str) -> Option<&'a Section> {
    current
        .iter()
        .find(|section| section.config == config && section.id == id)
}

/// The change that makes one owned section as wanted, if it differs.
fn change_for(section: &Section, existing: Option<&Section>) -> Vec<Change> {
    let Some(existing) = existing else {
        return vec![Change::Add(section.clone(), describe(section, "new"))];
    };
    if existing.kind == section.kind && existing.options == section.options {
        return Vec::new();
    }
    let options: BTreeMap<String, Opt> = section
        .options
        .iter()
        .filter(|(key, value)| existing.get(key) != Some(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if existing.kind != section.kind || options.is_empty() {
        return vec![
            Change::Delete {
                config: section.config.clone(),
                id: section.id.clone(),
                why: describe(existing, "replaced"),
            },
            Change::Add(section.clone(), describe(section, "new")),
        ];
    }
    vec![Change::Set {
        config: section.config.clone(),
        id: section.id.clone(),
        options,
        why: describe(section, "changed"),
    }]
}

/// The changes from what the device has to what is wanted. `move_lan` moves the LAN to VLAN 1 first.
fn changes(wanted: &[Section], current: &[Section], bridge: &Bridge<'_>, move_lan: bool) -> Vec<Change> {
    let vlan1 = format!("{PREFIX}vlan1");
    let lan_device = format!("{}.{LAN_VLAN}", bridge.name);
    let mut changes = Vec::new();
    for config in CONFIGS {
        if config == "network" && move_lan {
            if let Some(section) = wanted.iter().find(|section| section.id == vlan1)
                && find(current, "network", &vlan1).is_none()
            {
                changes.push(Change::Add(
                    section.clone(),
                    format!(
                        "{}: VLAN bridge, LAN as VLAN 1 untagged on every port",
                        bridge.name
                    ),
                ));
            }
            changes.push(Change::Set {
                config: "network".to_owned(),
                id: bridge.lan.id.clone(),
                options: BTreeMap::from([("device".to_owned(), Opt::one(&lan_device))]),
                why: format!("LAN moves to {lan_device}"),
            });
        }
        for section in wanted.iter().filter(|section| section.config == config) {
            if !(move_lan && section.id == vlan1) {
                changes.extend(change_for(section, find(current, config, &section.id)));
            }
        }
    }
    for config in CONFIGS.iter().rev() {
        for section in current.iter().filter(|section| {
            section.config == *config
                && section.id.starts_with(PREFIX)
                && !wanted
                    .iter()
                    .any(|want| want.config == section.config && want.id == section.id)
        }) {
            changes.push(Change::Delete {
                config: section.config.clone(),
                id: section.id.clone(),
                why: describe(section, "removed"),
            });
        }
    }
    changes
}

/// The ports that lead to exactly one known device, ever: they carry that device's VLAN untagged and nothing else.
/// Only VLANs in `built` count, so a port never ends up in a network that does not exist.
fn access_ports(
    plan: &Plan,
    bridge: &Bridge<'_>,
    ports: &BTreeMap<String, BTreeSet<String>>,
    built: &[u16],
) -> HashMap<String, u16> {
    bridge
        .ports
        .iter()
        .filter_map(|port| {
            let macs = ports.get(port)?;
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

/// The ports of a VLAN on the bridge: untagged on its access ports, tagged on the shared ones. VLAN 1 is untagged
/// on every port that is not an access port of another VLAN.
fn vlan_ports(bridge: &Bridge<'_>, access: &HashMap<String, u16>, vlan: u16) -> Opt {
    Opt::List(
        bridge
            .ports
            .iter()
            .filter_map(|port| match access.get(port) {
                Some(own) if *own == vlan => Some(format!("{port}:u*")),
                Some(_) => None,
                None if vlan == LAN_VLAN => Some(format!("{port}:u*")),
                None => Some(format!("{port}:t")),
            })
            .collect(),
    )
}

/// Plans the networks of one device. `passwords` holds the Wi-Fi password per group name, `ports` every MAC address
/// ever seen per bridge port.
#[must_use]
pub fn plan<S: BuildHasher>(
    plan: &Plan,
    current: &[Section],
    role: Role,
    passwords: &HashMap<String, String, S>,
    ports: &BTreeMap<String, BTreeSet<String>>,
) -> NetworkPlan {
    let mut result = NetworkPlan::default();
    let networks: Vec<&Group> = plan
        .groups
        .iter()
        .filter(|group| group.vlan != LAN_VLAN)
        .collect();
    let Some(bridge) = bridge(current) else {
        if !networks.is_empty() {
            result
                .notes
                .push("No LAN bridge found, the networks are left out".to_owned());
        }
        return result;
    };
    let foreign_vlans = current.iter().any(|section| {
        section.config == "network" && section.kind == "bridge-vlan" && !section.id.starts_with(PREFIX)
    });
    if foreign_vlans {
        result.notes.push(format!(
            "{} has VLANs set up outside lanlord, the networks are left out",
            bridge.name
        ));
        return result;
    }
    let taken: Vec<String> = current
        .iter()
        .filter(|section| {
            section.config == "firewall" && section.kind == "zone" && !section.id.starts_with(PREFIX)
        })
        .map(|section| section.text("name"))
        .collect();
    let built: Vec<&Group> = networks
        .into_iter()
        .filter(|group| {
            if role == Role::AccessPoint {
                return true;
            }
            if router_address(group).is_none() {
                result
                    .notes
                    .push(format!("{} needs a subnet to become a network", group.title()));
                return false;
            }
            if taken.contains(&zone_name(group)) {
                result.notes.push(format!(
                    "{}: the firewall zone {} exists already, the network is left out",
                    group.title(),
                    zone_name(group)
                ));
                return false;
            }
            true
        })
        .collect();
    let vlans: Vec<u16> = built.iter().map(|group| group.vlan).collect();
    let access = access_ports(plan, &bridge, ports, &vlans);
    let mut wanted = Vec::new();
    if find(current, "network", &format!("{PREFIX}vlan1")).is_some() || !built.is_empty() {
        wanted.push(Section::new(
            "network",
            format!("{PREFIX}vlan1"),
            "bridge-vlan",
            &[
                ("device", Opt::one(&bridge.name)),
                ("vlan", Opt::one(LAN_VLAN.to_string())),
                ("ports", vlan_ports(&bridge, &access, LAN_VLAN)),
            ],
        ));
    }
    let move_lan = !wanted.is_empty() && bridge.lan.text("device") != format!("{}.{LAN_VLAN}", bridge.name);
    let device = Device {
        radios: current
            .iter()
            .filter(|section| section.config == "wireless" && section.kind == "wifi-device")
            .map(|section| (section.id.clone(), section.text("band")))
            .collect(),
        dns: dns_target(plan, current),
        bridge,
        access,
    };
    for group in &built {
        wanted.extend(group_sections(group, &device, role, passwords, &mut result.notes));
    }
    if role == Role::Router {
        wanted.extend(reach_sections(plan, &built, current, &mut result.notes));
    }
    result.changes = changes(&wanted, current, &device.bridge, move_lan);
    result
}

/// A line for people about a section.
fn describe(section: &Section, what: &str) -> String {
    let name = section.id.trim_start_matches(PREFIX);
    let thing = match (section.config.as_str(), section.kind.as_str()) {
        ("network", "bridge-vlan") => format!("VLAN {} on {}", section.text("vlan"), section.text("ports")),
        ("network", "interface") => format!("interface {name}"),
        ("dhcp", _) => format!("DHCP pool {name}"),
        ("firewall", "zone") => format!("firewall zone {}", section.text("name")),
        ("firewall", "forwarding") => match section.text("dest").as_str() {
            "wan" => format!("{} may reach the internet", section.text("src")),
            dest => format!("{} may reach {dest}", section.text("src")),
        },
        ("firewall", _) => format!("firewall {}", section.text("name")),
        ("wireless", _) => format!("Wi-Fi {} on {}", section.text("ssid"), section.text("device")),
        _ => format!("{} {name}", section.kind),
    };
    format!("{thing}: {what}")
}

#[cfg(test)]
mod tests;
