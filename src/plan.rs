//! The plan: what should be, as the user set it. Targets get it whole and work out their changes from it.

use crate::config::Group;
use crate::devices::DeviceList;

/// Everything a target needs to know about what should be.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// The devices with their interfaces.
    pub devices: DeviceList,
    /// The groups, each one network.
    pub groups: Vec<Group>,
}

impl From<DeviceList> for Plan {
    fn from(devices: DeviceList) -> Self {
        Self {
            devices,
            groups: Vec::new(),
        }
    }
}
