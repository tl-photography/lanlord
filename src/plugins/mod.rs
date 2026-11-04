//! Plugins report what they see and keep (sources) and configure devices (targets). They are built into
//! lanlord and enabled per instance in `lanlord.toml`.

mod leases_file;

use std::collections::HashSet;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use serde::Deserialize;

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
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(default, rename = "plugin")]
    plugins: Vec<toml::Table>,
}

/// Reads the plugins from `lanlord.toml`. A missing file means no plugins.
///
/// # Errors
///
/// If the file is invalid, a type is unknown, a plugin's settings are wrong or a name is used twice.
pub fn load(path: &Path) -> Result<Vec<Arc<dyn Plugin>>, Error> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Error::Parse(format!("{}: {error}", path.display()))),
    };
    let settings: Settings =
        toml::from_str(&content).map_err(|error| Error::Parse(format!("{}: {error}", path.display())))?;
    let mut names = HashSet::new();
    let mut plugins = Vec::new();
    for mut table in settings.plugins {
        let kind = take_string(&mut table, "type")?;
        let name = take_string(&mut table, "name")?;
        if !is_valid_name(&name) {
            return Err(Error::Invalid(format!("invalid plugin name: {name}")));
        }
        if !names.insert(name.clone()) {
            return Err(Error::Invalid(format!("duplicate plugin name: {name}")));
        }
        let plugin: Arc<dyn Plugin> = match kind.as_str() {
            "leases-file" => Arc::new(leases_file::LeasesFile::new(name, table)?),
            other => return Err(Error::Invalid(format!("{name}: unknown plugin type {other}"))),
        };
        plugins.push(plugin);
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
