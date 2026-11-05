//! Plugins report what they see and keep (sources) and configure devices (targets). They are built into
//! lanlord and enabled per instance in `lanlord.toml`.

mod leases_file;
mod openwrt;
mod pihole;

use std::collections::HashSet;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::compare::Observation;
use crate::devices::{Error, is_valid_name};

/// A future that a plugin returns; boxed, so plugins can be stored as trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One plugin instance.
pub trait Plugin: Send + Sync {
    /// Name of the instance, from the configuration.
    fn name(&self) -> &str;
    /// Type of the plugin, for example `leases-file`.
    fn kind(&self) -> &'static str;
    /// Reads what the plugin sees and keeps.
    fn observe(&self) -> BoxFuture<'_, Result<Observation, String>>;
    /// Whether the plugin writes changes to the network (a target), not only reports them.
    fn is_target(&self) -> bool {
        false
    }
}

/// The `[[plugin]]` tables of `lanlord.toml`; their fields depend on the type.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Configured plugin instances.
    #[serde(default, rename = "plugin")]
    pub plugins: Vec<toml::Table>,
}

/// Reads the plugins from `lanlord.toml`. A missing file means no plugins.
///
/// # Errors
///
/// If the file is invalid, a type is unknown, a plugin's settings are wrong or a name is used twice.
pub fn load(path: &Path) -> Result<Vec<Arc<dyn Plugin>>, Error> {
    build(read_settings(path)?.plugins)
}

/// Reads the configured plugin tables. A missing file means no plugins.
///
/// # Errors
///
/// If the file cannot be read or is not valid TOML.
pub fn read_settings(path: &Path) -> Result<Settings, Error> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(error) => return Err(Error::Io(error)),
    };
    toml::from_str(&content).map_err(|error| Error::Parse(format!("{}: {error}", path.display())))
}

/// Validates and atomically saves plugin settings with owner-only permissions.
///
/// # Errors
///
/// If a plugin is invalid or the file cannot be written.
pub fn save_settings(path: &Path, settings: &Settings) -> Result<(), Error> {
    build(settings.plugins.clone())?;
    let content = toml::to_string_pretty(settings).map_err(|error| Error::Invalid(error.to_string()))?;
    crate::devices::write_private(path, &content)
}

fn build(tables: Vec<toml::Table>) -> Result<Vec<Arc<dyn Plugin>>, Error> {
    let mut names = HashSet::new();
    let mut plugins = Vec::new();
    for mut table in tables {
        let kind = take_string(&mut table, "type")?;
        let name = take_string(&mut table, "name")?;
        if !is_valid_name(&name) {
            return Err(Error::Invalid(format!("invalid plugin name: {name}")));
        }
        if !names.insert(name.clone()) {
            return Err(Error::Invalid(format!("duplicate plugin name: {name}")));
        }
        let enabled = take_bool(&mut table, "enabled")?;
        let plugin: Arc<dyn Plugin> = match kind.as_str() {
            "leases-file" => Arc::new(leases_file::LeasesFile::new(name, table)?),
            "openwrt" => Arc::new(openwrt::OpenWrt::new(name, table)?),
            "pihole" => Arc::new(pihole::PiHole::new(name, table)?),
            other => return Err(Error::Invalid(format!("{name}: unknown plugin type {other}"))),
        };
        if enabled {
            plugins.push(plugin);
        }
    }
    Ok(plugins)
}

fn take_string(table: &mut toml::Table, key: &str) -> Result<String, Error> {
    match table.remove(key) {
        Some(toml::Value::String(value)) => Ok(value),
        Some(_) => Err(Error::Invalid(format!("plugin field {key} must be text"))),
        None => Err(Error::Invalid(format!("plugin without {key}"))),
    }
}

fn take_bool(table: &mut toml::Table, key: &str) -> Result<bool, Error> {
    match table.remove(key) {
        Some(toml::Value::Boolean(value)) => Ok(value),
        Some(_) => Err(Error::Invalid(format!("plugin field {key} must be a boolean"))),
        None => Ok(true),
    }
}

/// Turns the remaining fields of a plugin table into the plugin's own settings.
fn settings<T: serde::de::DeserializeOwned>(name: &str, table: toml::Table) -> Result<T, Error> {
    toml::Value::Table(table)
        .try_into()
        .map_err(|error| Error::Invalid(format!("{name}: {error}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn load_text(text: &str) -> Result<Vec<Arc<dyn Plugin>>, Error> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lanlord.toml");
        fs::write(&path, text).unwrap();
        load(&path)
    }

    #[test]
    fn missing_file_means_no_plugins() {
        let directory = tempfile::tempdir().unwrap();
        assert!(load(&directory.path().join("lanlord.toml")).unwrap().is_empty());
    }

    #[test]
    fn plugins_are_built_by_type() {
        let plugins = load_text(
            "[[plugin]]\ntype = \"leases-file\"\nname = \"router\"\npath = \"/data/dhcp.leases\"\n",
        )
        .unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name(), "router");
        assert_eq!(plugins[0].kind(), "leases-file");
    }

    #[test]
    fn disabled_plugins_are_not_loaded() {
        let plugins = load_text(
            "[[plugin]]\ntype = \"leases-file\"\nname = \"router\"\nenabled = false\npath = \"/data/dhcp.leases\"\n",
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
            plugins: vec![toml::from_str(
                "type = \"leases-file\"\nname = \"router\"\nenabled = false\npath = \"/data/dhcp.leases\"\n",
            )
            .unwrap()],
        };

        save_settings(&path, &settings).unwrap();

        assert_eq!(read_settings(&path).unwrap().plugins, settings.plugins);
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
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
                "[[plugin]]\ntype = \"openwrt\"\nname = \"router\"\nhost = \"router.lan\"\nuser = \"root\"\nkey_file = \"/data/key\"\nhost_key_file = \"/data/host.pub\"\nunknown = true\n",
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
}
