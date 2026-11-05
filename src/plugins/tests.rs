//! Unit tests of `plugins`.

#![allow(clippy::unwrap_used)]

use super::*;

fn load_text(text: &str) -> Result<Vec<Arc<dyn Plugin>>, String> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lanlord.toml");
    fs::write(&path, text).unwrap();
    let loaded = load(&path);
    match loaded.all_problems().into_iter().next() {
        Some(problem) => Err(problem),
        None => Ok(loaded.plugins),
    }
}

#[test]
fn missing_file_means_no_plugins() {
    let directory = tempfile::tempdir().unwrap();
    assert!(load(&directory.path().join("lanlord.toml")).plugins.is_empty());
}

#[test]
fn plugins_are_built_by_type() {
    let plugins =
        load_text("[[plugin]]\ntype = \"leases-file\"\nname = \"router\"\npath = \"dhcp.leases\"\n").unwrap();
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "router");
    assert_eq!(plugins[0].kind(), "leases-file");
}

#[test]
fn disabled_plugins_are_not_loaded() {
    let plugins = load_text(
        "[[plugin]]\ntype = \"leases-file\"\nname = \"router\"\nenabled = false\npath = \"dhcp.leases\"\n",
    )
    .unwrap();
    assert!(plugins.is_empty());
}

#[test]
fn settings_round_trip_with_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lanlord.toml");
    let settings = Settings {
        plugins: vec![
            toml::from_str(
                "type = \"leases-file\"\nname = \"router\"\nenabled = false\npath = \"dhcp.leases\"\n",
            )
            .unwrap(),
        ],
    };

    save_settings(&path, &settings).unwrap();

    assert_eq!(read_settings(&path).unwrap().plugins, settings.plugins);
    assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn file_settings_stay_inside_the_data_directory() {
    for path in ["/etc/passwd", "../lanlord.toml", "..", "keys/router", "a b"] {
        let text = format!("[[plugin]]\ntype = \"leases-file\"\nname = \"a\"\npath = \"{path}\"\n");
        assert!(load_text(&text).is_err(), "{path}");
    }
    assert!(is_data_file("dhcp.leases"));
    assert!(is_data_file("router_key-1"));
}

#[test]
fn every_type_describes_its_fields() {
    for described in TYPES {
        assert!(!described.fields.is_empty(), "{}", described.kind);
        assert!(plugin_type(described.kind).is_some());
    }
    assert!(plugin_type("telepathy").is_none());
}

#[test]
fn invalid_plugin_settings_are_rejected() {
    for (text, reason) in [
        ("[[plugin]]\ntype = \"telepathy\"\nname = \"a\"\n", "unknown type"),
        ("[[plugin]]\nname = \"a\"\npath = \"x\"\n", "no type"),
        ("[[plugin]]\ntype = \"leases-file\"\npath = \"x\"\n", "no name"),
        (
            "[[plugin]]\ntype = \"leases-file\"\nname = \"a b\"\npath = \"x\"\n",
            "invalid name",
        ),
        (
            "[[plugin]]\ntype = \"leases-file\"\nname = \"a\"\n",
            "missing path",
        ),
        (
            "[[plugin]]\ntype = \"leases-file\"\nname = \"a\"\npath = \"x\"\nport = 1\n",
            "unknown field",
        ),
        (
            "[[plugin]]\ntype = \"openwrt\"\nname = \"router\"\nurl = \"https://router.lan\"\nuser = \"lanlord\"\npassword_file = \"router.password\"\ncertificate = \"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\"\nunknown = true\n",
            "unknown field",
        ),
        (
            "[[plugin]]\ntype = \"leases-file\"\nname = \"a\"\nenabled = \"no\"\npath = \"x\"\n",
            "enabled must be boolean",
        ),
        (
            "[[plugin]]\ntype = \"leases-file\"\nname = \"a\"\npath = \"x\"\n\
                 [[plugin]]\ntype = \"leases-file\"\nname = \"a\"\npath = \"y\"\n",
            "duplicate name",
        ),
        ("color = \"red\"\n", "unknown top-level field"),
    ] {
        assert!(load_text(text).is_err(), "{reason}");
    }
}
