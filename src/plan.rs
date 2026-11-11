//! The plan: what should be, as the user set it. Targets get it whole and work out their changes from it.

use std::net::Ipv4Addr;

use crate::config::Group;
use crate::devices::DeviceList;

/// Everything a target needs to know about what should be.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// The devices with their interfaces.
    pub devices: DeviceList,
    /// The groups, each one network.
    pub groups: Vec<Group>,
    /// What the plugins offer to the network.
    pub services: Vec<Service>,
    /// The plugin whose DNS service all networks use; empty for the router.
    pub dns_service: String,
    /// The plugin whose DHCP service keeps the static leases; empty for the router.
    pub dhcp_service: String,
}

/// Something a plugin offers to the network, at the address of the device it is linked to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// What it is, for example `dns`.
    pub kind: &'static str,
    /// Where devices reach it.
    pub address: Ipv4Addr,
    /// The plugin that offers it.
    pub source: String,
}

impl Plan {
    /// The address of the chosen DNS service; `None` for the router.
    #[must_use]
    pub fn dns(&self) -> Option<Ipv4Addr> {
        self.offered("dns", &self.dns_service)
    }

    /// The address of the chosen DHCP service; `None` for the router.
    #[must_use]
    pub fn dhcp(&self) -> Option<Ipv4Addr> {
        self.offered("dhcp", &self.dhcp_service)
    }

    fn offered(&self, kind: &str, source: &str) -> Option<Ipv4Addr> {
        self.services
            .iter()
            .find(|service| service.kind == kind && service.source == source)
            .map(|service| service.address)
    }
}

impl From<DeviceList> for Plan {
    fn from(devices: DeviceList) -> Self {
        Self {
            devices,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A service kind, the field that chooses it and the method that gives its address.
    type Choice = (
        &'static str,
        fn(&mut Plan) -> &mut String,
        fn(&Plan) -> Option<Ipv4Addr>,
    );

    #[test]
    fn the_chosen_service_gives_the_address() {
        let address = Ipv4Addr::new(192, 0, 2, 53);
        let choices: [Choice; 2] = [
            ("dns", |plan| &mut plan.dns_service, Plan::dns),
            ("dhcp", |plan| &mut plan.dhcp_service, Plan::dhcp),
        ];
        for (kind, choice, chosen) in choices {
            let mut plan = Plan {
                services: vec![Service {
                    kind,
                    address,
                    source: "filter".to_owned(),
                }],
                ..Plan::default()
            };
            assert_eq!(chosen(&plan), None, "{kind}: nothing chosen is the router");
            "filter".clone_into(choice(&mut plan));
            assert_eq!(chosen(&plan), Some(address), "{kind}");
            "gone".clone_into(choice(&mut plan));
            assert_eq!(chosen(&plan), None, "{kind}: a plugin that offers nothing");
        }
        let plan = Plan {
            services: vec![Service {
                kind: "dns",
                address,
                source: "filter".to_owned(),
            }],
            dhcp_service: "filter".to_owned(),
            ..Plan::default()
        };
        assert_eq!(plan.dhcp(), None, "a DNS service is no DHCP service");
    }
}
