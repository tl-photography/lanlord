//! The page of a machine: its interfaces, with rename, add and remove. Each interface stays a connection of its own,
//! with its lease, DNS name and group.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::devices::{Error, is_valid_name};
use crate::edit::{GroupOption, follow_links, group_options};
use crate::{AppState, history, server_error};

struct InterfaceRow {
    name: String,
    mac: String,
    ip: String,
    group: String,
}

/// A device that can be added as an interface; `machine` is where it is now.
struct AvailableDevice {
    name: String,
    machine: String,
}

#[derive(Template)]
#[template(path = "machine.html")]
struct MachinePage {
    nav: &'static str,
    name: String,
    interfaces: Vec<InterfaceRow>,
    available: Vec<AvailableDevice>,
    groups: Vec<GroupOption>,
    default_group: String,
    error: String,
}

fn page(state: &AppState, name: &str, status: StatusCode, error: String) -> Response {
    let list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    let config = state.groups();
    let label = |group: &str| {
        config
            .groups
            .iter()
            .find(|entry| entry.name == group)
            .map_or_else(|| group.to_owned(), |entry| entry.title().to_owned())
    };
    let members: Vec<_> = list
        .devices
        .iter()
        .filter(|device| device.machine == name)
        .collect();
    if members.is_empty() {
        return (StatusCode::NOT_FOUND, "No such device").into_response();
    }
    let mut interfaces: Vec<InterfaceRow> = members
        .iter()
        .map(|device| InterfaceRow {
            name: device.name.clone(),
            mac: device.mac.clone(),
            ip: device.ip.map(|ip| ip.to_string()).unwrap_or_default(),
            group: label(&device.group),
        })
        .collect();
    interfaces.sort_by_key(|row| row.name.to_ascii_lowercase());
    let mut available: Vec<AvailableDevice> = list
        .devices
        .iter()
        .filter(|device| device.machine != name)
        .map(|device| AvailableDevice {
            name: device.name.clone(),
            machine: device.machine.clone(),
        })
        .collect();
    available.sort_by_key(|device| device.name.to_ascii_lowercase());
    let page = MachinePage {
        nav: "devices",
        name: name.to_owned(),
        interfaces,
        available,
        groups: group_options(state),
        default_group: members[0].group.clone(),
        error,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// Shows a machine.
pub async fn show(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    page(&state, &name, StatusCode::OK, String::new())
}

/// The field of the rename form.
#[derive(Debug, Deserialize)]
pub struct RenameForm {
    new_name: String,
}

/// Renames a machine; its interfaces keep their names, leases and DNS names.
pub async fn rename(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<RenameForm>,
) -> Response {
    let new_name = form.new_name.trim();
    if !is_valid_name(new_name) {
        return page(
            &state,
            &name,
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Invalid name: {new_name}"),
        );
    }
    let Ok(_guard) = state.inner.write_lock.lock() else {
        return server_error(&"device list lock poisoned");
    };
    let mut list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    if list.devices.iter().all(|device| device.machine != name) {
        return (StatusCode::NOT_FOUND, "No such device").into_response();
    }
    for device in list.devices.iter_mut().filter(|device| device.machine == name) {
        new_name.clone_into(&mut device.machine);
    }
    match list.save(&state.inner.devices_path, &state.groups().group_names()) {
        Ok(()) => {
            history::record(
                &state.inner.history_path,
                &[format!("Device {name} renamed to {new_name}")],
            );
            follow_links(&state, Some(&name), new_name);
            Redirect::to(&format!("/machines/{new_name}")).into_response()
        }
        Err(Error::Invalid(message)) => (StatusCode::UNPROCESSABLE_ENTITY, message).into_response(),
        Err(error) => server_error(&error),
    }
}

/// The field of the form that adds an existing device.
#[derive(Debug, Deserialize)]
pub struct AddForm {
    device: String,
}

/// Adds an existing device as an interface; it keeps its name, lease and group.
pub async fn add_interface(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<AddForm>,
) -> Response {
    let Ok(_guard) = state.inner.write_lock.lock() else {
        return server_error(&"device list lock poisoned");
    };
    let mut list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    if list.devices.iter().all(|device| device.machine != name) {
        return (StatusCode::NOT_FOUND, "No such device").into_response();
    }
    let Some(device) = list.devices.iter_mut().find(|device| device.name == form.device) else {
        return (StatusCode::NOT_FOUND, "No such device").into_response();
    };
    name.clone_into(&mut device.machine);
    match list.save(&state.inner.devices_path, &state.groups().group_names()) {
        Ok(()) => {
            history::record(
                &state.inner.history_path,
                &[format!("Interface {} added to {name}", form.device)],
            );
            Redirect::to(&format!("/machines/{name}")).into_response()
        }
        Err(error) => server_error(&error),
    }
}

/// Takes an interface out of its machine; it stays in the list as a device of its own.
pub async fn remove_interface(
    State(state): State<AppState>,
    Path((name, device)): Path<(String, String)>,
) -> Response {
    let Ok(_guard) = state.inner.write_lock.lock() else {
        return server_error(&"device list lock poisoned");
    };
    let mut list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    let Some(entry) = list
        .devices
        .iter_mut()
        .find(|entry| entry.name == device && entry.machine == name)
    else {
        return (StatusCode::NOT_FOUND, "No such interface").into_response();
    };
    entry.machine.clear();
    let machine_left = list.devices.iter().any(|entry| entry.machine == name);
    match list.save(&state.inner.devices_path, &state.groups().group_names()) {
        Ok(()) => {
            history::record(
                &state.inner.history_path,
                &[format!("Interface {device} removed from {name}")],
            );
            let next = if machine_left {
                format!("/machines/{name}")
            } else {
                format!("/devices/{device}")
            };
            Redirect::to(&next).into_response()
        }
        Err(error) => server_error(&error),
    }
}
