//! Unit tests of `config`.

#![allow(clippy::unwrap_used)]

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
