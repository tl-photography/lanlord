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
        self.services
            .iter()
            .find(|service| service.kind == "dns" && service.source == self.dns_service)
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

    #[test]
    fn the_chosen_dns_service_gives_the_address() {
        let mut plan = Plan {
            services: vec![Service {
                kind: "dns",
                address: Ipv4Addr::new(192, 0, 2, 53),
                source: "filter".to_owned(),
            }],
            ..Plan::default()
        };
        assert_eq!(plan.dns(), None, "nothing chosen is the router");
        "filter".clone_into(&mut plan.dns_service);
        assert_eq!(plan.dns(), Some(Ipv4Addr::new(192, 0, 2, 53)));
        "gone".clone_into(&mut plan.dns_service);
        assert_eq!(plan.dns(), None);
    }
}
