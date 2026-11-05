//! Plugins report what they see and keep (sources) and configure devices (targets). They are built into
//! lanlord and enabled per instance in `lanlord.toml`. Every type describes its own settings, so the web interface
//! and the validation need no code per type.

mod leases_file;
mod openwrt;

use std::collections::HashSet;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::compare::Observation;
use crate::devices::{DeviceList, Error, is_valid_name};
use crate::leases::Plan;

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
    /// The changes a target would make for this device list; `None` if it has nothing to manage.
    fn plan(&self, _devices: DeviceList) -> BoxFuture<'_, Result<Option<Plan>, String>> {
        Box::pin(async { Ok(None) })
    }
    /// Makes the changes, if they are still the ones with this digest; returns how many were made.
    fn apply(&self, _devices: DeviceList, _digest: String) -> BoxFuture<'_, Result<usize, String>> {
        Box::pin(async { Err("this plugin does not change anything".to_owned()) })
    }
}

/// What kind of value a setting holds; decides the input field and the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Text without spaces or control characters, for example a host or user name.
    Word,
    /// An `http` or `https` URL.
    Url,
    /// A TCP port, 1 to 65535.
    Port,
    /// A file name inside the data directory; no paths, so plugins cannot read files elsewhere.
    DataFile,
    /// A SHA-256 fingerprint: 64 hex digits, with or without colons.
    Fingerprint,
}

/// One setting of a plugin type.
#[derive(Debug)]
pub struct Field {
    /// Key in `lanlord.toml`.
    pub key: &'static str,
    /// Label in the web interface.
    pub label: &'static str,
    /// Kind of value.
    pub kind: FieldKind,
    /// Example shown in the empty field.
    pub placeholder: &'static str,
}

/// Builds a plugin instance from its name, its settings and the data directory.
type Constructor = fn(String, toml::Table, &Path) -> Result<Arc<dyn Plugin>, Error>;

/// A built-in plugin type.
pub struct PluginType {
    /// Value of `type` in `lanlord.toml`.
    pub kind: &'static str,
    /// Name in the web interface.
    pub title: &'static str,
    /// One sentence on what it does.
    pub description: &'static str,
    /// Its settings; all are required.
    pub fields: &'static [Field],
    build: Constructor,
}

/// All built-in plugin types.
pub const TYPES: &[PluginType] = &[leases_file::TYPE, openwrt::TYPE];

/// The plugin type with this `type` value.
#[must_use]
pub fn plugin_type(kind: &str) -> Option<&'static PluginType> {
    TYPES.iter().find(|candidate| candidate.kind == kind)
}

/// Checks one setting value and turns it into its TOML value.
///
/// # Errors
///
/// A message for the user if the value does not fit the field.
pub fn field_value(field: &Field, value: &str) -> Result<toml::Value, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{} is required", field.label));
    }
    match field.kind {
        FieldKind::Word if value.chars().any(|c| c.is_whitespace() || c.is_control()) => {
            Err(format!("{} must not contain spaces", field.label))
        }
        FieldKind::Url if !(value.starts_with("http://") || value.starts_with("https://")) => {
            Err(format!("{} must start with http:// or https://", field.label))
        }
        FieldKind::Port => match value.parse::<u16>() {
            Ok(port) if port > 0 => Ok(toml::Value::Integer(i64::from(port))),
            _ => Err(format!("{} must be a number from 1 to 65535", field.label)),
        },
        FieldKind::Fingerprint
            if value.chars().filter(|c| *c != ':').count() != 64
                || !value.chars().all(|c| c == ':' || c.is_ascii_hexdigit()) =>
        {
            Err(format!(
                "{} must be 64 hex digits, as openssl prints it",
                field.label
            ))
        }
        FieldKind::DataFile if !is_data_file(value) => Err(format!(
            "{} must be a file name in the data directory, without / or ..",
            field.label
        )),
        _ => Ok(toml::Value::String(value.to_owned())),
    }
}

/// A file name inside the data directory: letters, digits, `.`, `-` and `_`, not `.` or `..`.
#[must_use]
pub fn is_data_file(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The `[[plugin]]` tables of `lanlord.toml`; their fields depend on the type.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Configured plugin instances.
    #[serde(default, rename = "plugin")]
    pub plugins: Vec<toml::Table>,
}

/// The plugins of `lanlord.toml`: the enabled ones that work, and a problem for every entry that could not be built.
/// A broken entry never stops lanlord, it is only left out.
#[derive(Default)]
pub struct Loaded {
    /// Enabled plugins that could be built.
    pub plugins: Vec<Arc<dyn Plugin>>,
    /// One entry per `[[plugin]]` table, in file order: the problem, or `None` if it is fine.
    pub problems: Vec<Option<String>>,
    /// A problem with the whole file, for example invalid TOML.
    pub file_problem: Option<String>,
}

impl Loaded {
    /// All problems as text, the file problem first.
    #[must_use]
    pub fn all_problems(&self) -> Vec<String> {
        self.file_problem
            .iter()
            .cloned()
            .chain(self.problems.iter().flatten().cloned())
            .collect()
    }
}

/// Reads `lanlord.toml`. A missing file means no plugins. File settings are resolved in its directory.
#[must_use]
pub fn load(path: &Path) -> Loaded {
    match read_settings(path) {
        Ok(settings) => check(settings.plugins, &data_dir(path)),
        Err(error) => Loaded {
            file_problem: Some(error.to_string()),
            ..Loaded::default()
        },
    }
}

/// Builds every entry on its own, so one broken entry does not affect the others.
#[must_use]
pub fn check(tables: Vec<toml::Table>, data_dir: &Path) -> Loaded {
    let mut names = HashSet::new();
    let mut loaded = Loaded::default();
    for table in tables {
        match build_one(table, data_dir, &mut names) {
            Ok(plugin) => {
                loaded.plugins.extend(plugin);
                loaded.problems.push(None);
            }
            Err(error) => loaded.problems.push(Some(error.to_string())),
        }
    }
    loaded
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
    if let Some(problem) = check(settings.plugins.clone(), &data_dir(path))
        .problems
        .into_iter()
        .flatten()
        .next()
    {
        return Err(Error::Invalid(problem));
    }
    let content = toml::to_string_pretty(settings).map_err(|error| Error::Invalid(error.to_string()))?;
    crate::devices::write_private(path, &content)
}

/// The data directory: the directory of `lanlord.toml`.
#[must_use]
pub fn data_dir(settings_path: &Path) -> PathBuf {
    settings_path
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf)
}

/// Builds one entry; `None` if it is disabled.
fn build_one(
    mut table: toml::Table,
    data_dir: &Path,
    names: &mut HashSet<String>,
) -> Result<Option<Arc<dyn Plugin>>, Error> {
    {
        let kind = take_string(&mut table, "type")?;
        let name = take_string(&mut table, "name")?;
        if !is_valid_name(&name) {
            return Err(Error::Invalid(format!("invalid plugin name: {name}")));
        }
        if !names.insert(name.clone()) {
            return Err(Error::Invalid(format!("duplicate plugin name: {name}")));
        }
        let enabled = take_bool(&mut table, "enabled")?;
        let Some(plugin_type) = plugin_type(&kind) else {
            return Err(Error::Invalid(format!("{name}: unknown plugin type {kind}")));
        };
        for field in plugin_type.fields {
            let Some(value) = table.get(field.key) else {
                return Err(Error::Invalid(format!("{name}: {} is required", field.label)));
            };
            let text = value
                .as_str()
                .map(str::to_owned)
                .or_else(|| value.as_integer().map(|number| number.to_string()))
                .unwrap_or_default();
            field_value(field, &text).map_err(|message| Error::Invalid(format!("{name}: {message}")))?;
        }
        let plugin = (plugin_type.build)(name, table, data_dir)?;
        Ok(enabled.then_some(plugin))
    }
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
            load_text("[[plugin]]\ntype = \"leases-file\"\nname = \"router\"\npath = \"dhcp.leases\"\n")
                .unwrap();
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
        let settings =
            Settings {
                plugins: vec![toml::from_str(
                "type = \"leases-file\"\nname = \"router\"\nenabled = false\npath = \"dhcp.leases\"\n",
            )
            .unwrap()],
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
        assert!(plugin_type("pihole").is_none());
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
}
