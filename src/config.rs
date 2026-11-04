//! Settings in `lanlord.toml`: the groups and their VLANs.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::devices::{Error, is_valid_name};

/// A group of devices, mapped to a VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Short name, used in the device list.
    pub name: String,
    /// VLAN id, 1 to 4094.
    pub vlan: u16,
    /// Text shown in the interface.
    #[serde(default)]
    pub label: String,
}

/// The settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Group for devices that are not in the list.
    pub default_group: String,
    /// All groups.
    #[serde(rename = "group")]
    pub groups: Vec<Group>,
}

impl Config {
    /// Reads and checks the settings.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, is not valid TOML, or the groups are invalid.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let content =
            fs::read_to_string(path).map_err(|error| Error::Parse(format!("{}: {error}", path.display())))?;
        let config: Self =
            toml::from_str(&content).map_err(|error| Error::Parse(format!("{}: {error}", path.display())))?;
        config.validate()?;
        Ok(config)
    }

    /// Names of all groups, in the order of the file.
    #[must_use]
    pub fn group_names(&self) -> Vec<String> {
        self.groups.iter().map(|group| group.name.clone()).collect()
    }

    fn validate(&self) -> Result<(), Error> {
        if self.groups.is_empty() {
            return Err(Error::Invalid("no groups configured".to_owned()));
        }
        let mut names = HashSet::new();
        let mut vlans = HashSet::new();
        for group in &self.groups {
            if !is_valid_name(&group.name) {
                return Err(Error::Invalid(format!("invalid group name: {}", group.name)));
            }
            if !(1..=4094).contains(&group.vlan) {
                return Err(Error::Invalid(format!("{}: VLAN must be 1 to 4094", group.name)));
            }
            if !names.insert(&group.name) {
                return Err(Error::Invalid(format!("duplicate group: {}", group.name)));
            }
            if !vlans.insert(group.vlan) {
                return Err(Error::Invalid(format!(
                    "{}: duplicate VLAN {}",
                    group.name, group.vlan
                )));
            }
        }
        if !names.contains(&self.default_group) {
            return Err(Error::Invalid(format!(
                "unknown default group: {}",
                self.default_group
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
default_group = "guest"

[[group]]
name = "lan"
vlan = 1
label = "LAN"

[[group]]
name = "guest"
vlan = 30
"#;

    fn parse(text: &str) -> Result<Config, Error> {
        let config: Config = toml::from_str(text).map_err(|error| Error::Parse(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn example_is_valid() {
        let config = parse(EXAMPLE).unwrap();
        assert_eq!(config.group_names(), ["lan", "guest"]);
        assert_eq!(config.groups[1].vlan, 30);
    }

    #[test]
    fn example_file_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/lanlord.toml");
        let config = Config::load(&path).unwrap();
        assert_eq!(config.default_group, "guest");
    }

    #[test]
    fn invalid_groups_are_rejected() {
        for (change, reason) in [
            (EXAMPLE.replace("vlan = 30", "vlan = 1"), "duplicate VLAN"),
            (EXAMPLE.replace("vlan = 30", "vlan = 4095"), "VLAN out of range"),
            (
                EXAMPLE.replace("name = \"guest\"", "name = \"lan\""),
                "duplicate name",
            ),
            (
                EXAMPLE.replace("default_group = \"guest\"", "default_group = \"iot\""),
                "unknown default",
            ),
            (
                EXAMPLE.replace("name = \"guest\"", "name = \"gu est\""),
                "invalid name",
            ),
        ] {
            assert!(parse(&change).is_err(), "{reason}");
        }
    }
}
