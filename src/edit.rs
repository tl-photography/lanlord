//! Adding and changing devices.

use std::net::Ipv4Addr;

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::devices::{Device, Error, is_valid_name, normalize_mac};
use crate::{AppState, server_error};

/// Longest note that is accepted.
const MAX_NOTE: usize = 500;

/// The fields of the device form.
#[derive(Debug, Default, Deserialize)]
pub struct DeviceForm {
    name: String,
    mac: String,
    group: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    note: String,
}

impl DeviceForm {
    fn from_device(device: &Device) -> Self {
        Self {
            name: device.name.clone(),
            mac: device.mac.clone(),
            group: device.group.clone(),
            ip: device.ip.map(|ip| ip.to_string()).unwrap_or_default(),
            note: device.note.clone(),
        }
    }

    /// Checks the fields that the device list cannot check: MAC format, address and note length.
    fn to_device(&self) -> Result<Device, String> {
        let mac = normalize_mac(&self.mac).ok_or_else(|| format!("Invalid MAC address: {}", self.mac))?;
        let ip = match self.ip.trim() {
            "" => None,
            text => Some(
                text.parse::<Ipv4Addr>()
                    .map_err(|_| format!("Invalid IP address: {text}"))?,
            ),
        };
        let note = self.note.trim();
        if note.chars().count() > MAX_NOTE {
            return Err(format!("The note is longer than {MAX_NOTE} characters"));
        }
        Ok(Device {
            name: self.name.trim().to_owned(),
            mac,
            group: self.group.clone(),
            ip,
            note: note.to_owned(),
        })
    }
}

struct GroupOption {
    name: String,
    label: String,
}

#[derive(Template)]
#[template(path = "edit.html")]
struct EditPage {
    nav: &'static str,
    title: String,
    action: String,
    form: DeviceForm,
    groups: Vec<GroupOption>,
    error: String,
}

fn page(state: &AppState, original: Option<&str>, form: DeviceForm, error: String) -> Response {
    let groups = state
        .groups()
        .groups
        .iter()
        .map(|group| GroupOption {
            name: group.name.clone(),
            label: group.title().to_owned(),
        })
        .collect();
    let (title, action) = match original {
        Some(name) => (format!("Edit {name}"), format!("/devices/{name}")),
        None => ("Add device".to_owned(), "/devices".to_owned()),
    };
    let status = if error.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let page = EditPage {
        nav: "devices",
        title,
        action,
        form,
        groups,
        error,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Form for a new device, in the default group.
pub async fn new_form(State(state): State<AppState>) -> Response {
    let form = DeviceForm {
        group: state.groups().default_group,
        ..DeviceForm::default()
    };
    page(&state, None, form, String::new())
}

/// Form with the values of an existing device.
pub async fn edit_form(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    match list.devices.iter().find(|device| device.name == name) {
        Some(device) => page(
            &state,
            Some(&name),
            DeviceForm::from_device(device),
            String::new(),
        ),
        None => (StatusCode::NOT_FOUND, "No such device").into_response(),
    }
}

/// Adds a device.
pub async fn create(State(state): State<AppState>, Form(form): Form<DeviceForm>) -> Response {
    save(&state, None, form, false)
}

/// Changes a device; the name may change too.
pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<DeviceForm>,
) -> Response {
    save(&state, Some(&name), form, false)
}

/// Field of the move menu and of drag and drop.
#[derive(Debug, Deserialize)]
pub struct MoveForm {
    group: String,
}

/// A discovered device to import into an empty list.
#[derive(Debug, Deserialize)]
pub struct DiscoveredForm {
    name: String,
    mac: String,
}

fn suggested_name(hostname: &str, mac: &str) -> String {
    let mut name = String::new();
    let mut separator = false;
    for character in hostname.chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !name.is_empty() {
                name.push('-');
            }
            name.push(character.to_ascii_lowercase());
            separator = false;
        } else if !name.is_empty() {
            separator = true;
        }
    }
    if is_valid_name(&name) {
        name
    } else {
        let suffix = mac.replace(':', "");
        format!("device-{}", &suffix[suffix.len().saturating_sub(6)..])
    }
}

/// Imports one discovered device only while the device list is empty.
pub async fn add_discovered(
    State(state): State<AppState>,
    Form(discovered): Form<DiscoveredForm>,
) -> Response {
    let group = state.groups().default_group;
    if group.is_empty() {
        return (StatusCode::CONFLICT, "Create a group before importing devices").into_response();
    }
    let Some(mac) = normalize_mac(&discovered.mac) else {
        return (StatusCode::UNPROCESSABLE_ENTITY, "Invalid MAC address").into_response();
    };
    let form = DeviceForm {
        name: suggested_name(&discovered.name, &mac),
        mac,
        group,
        ..DeviceForm::default()
    };
    save(&state, None, form, true)
}

/// Moves a device to another group, keeps everything else.
pub async fn move_device(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(target): Form<MoveForm>,
) -> Response {
    let list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    let Some(device) = list.devices.iter().find(|device| device.name == name) else {
        return (StatusCode::NOT_FOUND, "No such device").into_response();
    };
    let form = DeviceForm {
        group: target.group,
        ..DeviceForm::from_device(device)
    };
    save(&state, Some(&name), form, false)
}

fn save(state: &AppState, original: Option<&str>, form: DeviceForm, require_empty: bool) -> Response {
    let device = match form.to_device() {
        Ok(device) => device,
        Err(message) => return page(state, original, form, message),
    };
    // One change at a time: read, change and write under the lock.
    let Ok(_guard) = state.inner.write_lock.lock() else {
        return server_error(&"device list lock poisoned");
    };
    let mut list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    if require_empty && !list.devices.is_empty() {
        return (StatusCode::CONFLICT, "Devices were added before this import").into_response();
    }
    match original {
        Some(name) => match list.devices.iter_mut().find(|existing| existing.name == name) {
            Some(existing) => *existing = device,
            None => return (StatusCode::NOT_FOUND, "No such device").into_response(),
        },
        None => list.devices.push(device),
    }
    match list.save(&state.inner.devices_path, &state.groups().group_names()) {
        Ok(()) => Redirect::to("/").into_response(),
        Err(Error::Invalid(message)) => page(state, original, form, message),
        Err(error) => server_error(&error),
    }
}
