//! The groups and their VLANs in `groups.toml`, set up in the interface and saved by lanlord.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::devices::{Error, is_valid_name, write_private};

/// A group of devices, mapped to a VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Short name, used in the device list.
    pub name: String,
    /// VLAN id, 1 to 4094.
    pub vlan: u16,
    /// Text shown in the interface.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
}

impl Group {
    /// The label, or the name if there is no label.
    #[must_use]
    pub fn title(&self) -> &str {
        if self.label.is_empty() {
            &self.name
        } else {
            &self.label
        }
    }
}

/// The groups. Empty until they are set up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Group for devices that are not in the list; empty while there are no groups.
    #[serde(default)]
    pub default_group: String,
    /// All groups.
    #[serde(default, rename = "group")]
    pub groups: Vec<Group>,
}

impl Config {
    /// Reads and checks the groups. A missing file means no groups yet.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, is not valid TOML, or the groups are invalid.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(Error::Parse(format!("{}: {error}", path.display()))),
        };
        let config: Self =
            toml::from_str(&content).map_err(|error| Error::Parse(format!("{}: {error}", path.display())))?;
        config.validate()?;
        Ok(config)
    }

    /// Checks and writes the groups, readable for the owner only.
    ///
    /// # Errors
    ///
    /// If the groups are invalid or the file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        self.validate()?;
        let content =
            toml::to_string_pretty(self).map_err(|error| Error::Invalid(format!("cannot write: {error}")))?;
        write_private(path, &content)
    }

    /// Names of all groups, in the order of the file.
    #[must_use]
    pub fn group_names(&self) -> Vec<String> {
        self.groups.iter().map(|group| group.name.clone()).collect()
    }

    /// Checks names, VLANs and the default group.
    ///
    /// # Errors
    ///
    /// The first problem found.
    pub fn validate(&self) -> Result<(), Error> {
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
        if !self.groups.is_empty() && !names.contains(&self.default_group) {
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
        assert_eq!(config.groups[0].title(), "LAN");
        assert_eq!(config.groups[1].title(), "guest");
    }

    #[test]
    fn example_file_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/groups.toml");
        let config = Config::load(&path).unwrap();
        assert_eq!(config.default_group, "guest");
    }

    #[test]
    fn missing_or_empty_file_means_no_groups() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("groups.toml");
        assert_eq!(Config::load(&path).unwrap(), Config::default());
        fs::write(&path, "").unwrap();
        assert_eq!(Config::load(&path).unwrap(), Config::default());
    }

    #[test]
    fn save_and_load_keep_the_groups() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("groups.toml");
        let config = parse(EXAMPLE).unwrap();
        config.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), config);
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
