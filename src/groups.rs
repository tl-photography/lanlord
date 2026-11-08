//! Setting up the groups: add, delete and choose the default group.

use std::collections::HashMap;

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::config::{Config, Group};
use crate::devices::Error;
use crate::history;
use crate::{AppState, server_error};

/// Fields of the form for a new group.
#[derive(Debug, Default, Deserialize)]
pub struct GroupForm {
    name: String,
    vlan: String,
    #[serde(default)]
    subnet: String,
    #[serde(default)]
    label: String,
}

/// Prefix of the checkbox fields for the groups a group is reachable from.
const FROM: &str = "from_";

/// Field of the form for the default group.
#[derive(Debug, Deserialize)]
pub struct DefaultForm {
    group: String,
}

/// A group another group may be reachable from, and whether it is.
struct Source {
    name: String,
    title: String,
    checked: bool,
}

struct GroupRow {
    name: String,
    band_2g: bool,
    band_5g: bool,
    reaches: String,
    sources: Vec<Source>,
    vlan: u16,
    subnet: String,
    ssid: String,
    password_file: String,
    title: String,
    devices: usize,
    is_default: bool,
}

#[derive(Template)]
#[template(path = "groups.html")]
struct GroupsPage {
    nav: &'static str,
    groups: Vec<GroupRow>,
    form: GroupForm,
    error: String,
}

fn page(state: &AppState, form: GroupForm, error: String) -> Response {
    let config = state.groups();
    let list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    let devices = list.interfaces;
    let groups = config
        .groups
        .iter()
        .map(|group| GroupRow {
            name: group.name.clone(),
            band_2g: group.ssid_bands.is_empty() || group.ssid_bands.iter().any(|band| band == "2g"),
            band_5g: group.ssid_bands.is_empty() || group.ssid_bands.iter().any(|band| band == "5g"),
            reaches: group.reaches.join(", "),
            sources: config
                .groups
                .iter()
                .filter(|other| other.name != group.name)
                .map(|other| Source {
                    name: other.name.clone(),
                    title: other.title().to_owned(),
                    checked: group.reachable_from.contains(&other.name),
                })
                .collect(),
            vlan: group.vlan,
            subnet: group.subnet.clone(),
            ssid: group.ssid.clone(),
            password_file: group.ssid_password_file.clone(),
            title: group.title().to_owned(),
            devices: devices.iter().filter(|device| device.group == group.name).count(),
            is_default: group.name == config.default_group,
        })
        .collect();
    let status = if error.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let page = GroupsPage {
        nav: "groups",
        groups,
        form,
        error,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// The groups with the form for a new one.
pub async fn list(State(state): State<AppState>) -> Response {
    page(&state, GroupForm::default(), String::new())
}

/// Changes the groups under the write lock: `change` gets the current groups and the devices, saves on success.
fn change(
    state: &AppState,
    form: GroupForm,
    change: impl FnOnce(&mut Config, &[crate::devices::Interface]) -> Result<(), String>,
) -> Response {
    let Ok(guard) = state.inner.write_lock.lock() else {
        return server_error(&"write lock poisoned");
    };
    let devices = match state.devices() {
        Ok(list) => list.interfaces,
        Err(error) => return server_error(&error),
    };
    let before = state.groups();
    let mut config = before.clone();
    if let Err(message) = change(&mut config, &devices) {
        drop(guard);
        return page(state, form, message);
    }
    match config.save(&state.inner.groups_path) {
        Ok(()) => {
            history::record(&state.inner.history_path, &history::groups(&before, &config));
            if let Ok(mut groups) = state.inner.groups.write() {
                *groups = config;
            }
            Redirect::to("/groups").into_response()
        }
        Err(Error::Invalid(message)) => {
            drop(guard);
            page(state, form, message)
        }
        Err(error) => server_error(&error),
    }
}

/// Adds a group; the first one becomes the default group.
pub async fn create(State(state): State<AppState>, Form(form): Form<GroupForm>) -> Response {
    let Ok(vlan) = form.vlan.trim().parse::<u16>() else {
        return page(
            &state,
            form,
            "The VLAN must be a number from 1 to 4094".to_owned(),
        );
    };
    let group = Group {
        name: form.name.trim().to_owned(),
        vlan,
        subnet: form.subnet.trim().to_owned(),
        label: form.label.trim().to_owned(),
        ssid: String::new(),
        ssid_password_file: String::new(),
        ssid_bands: Vec::new(),
        reachable_from: Vec::new(),
        reaches: Vec::new(),
    };
    change(&state, form, |config, _| {
        if config.groups.is_empty() {
            config.default_group.clone_from(&group.name);
        }
        config.groups.push(group);
        Ok(())
    })
}

/// Sets the subnet of a group, its own Wi-Fi and the groups it is reachable from, all from one form.
pub async fn set_network(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let field = |key: &str| form.get(key).map_or("", |value| value.trim());
    change(&state, GroupForm::default(), |config, _| {
        let names = config.group_names();
        let group = config
            .groups
            .iter_mut()
            .find(|group| group.name == name)
            .ok_or_else(|| format!("No such group: {name}"))?;
        field("subnet").clone_into(&mut group.subnet);
        field("ssid").clone_into(&mut group.ssid);
        let file = if group.ssid.is_empty() {
            ""
        } else {
            field("password_file")
        };
        file.clone_into(&mut group.ssid_password_file);
        let bands: Vec<String> = ["2g", "5g"]
            .into_iter()
            .filter(|band| form.contains_key(&format!("band_{band}")))
            .map(str::to_owned)
            .collect();
        if !group.ssid.is_empty() && bands.is_empty() {
            return Err(format!("{}: its Wi-Fi needs at least one band", group.title()));
        }
        group.ssid_bands = if bands.len() == 2 || group.ssid.is_empty() {
            Vec::new()
        } else {
            bands
        };
        group.reaches = field("reaches")
            .split([',', ' '])
            .filter(|reach| !reach.is_empty())
            .map(str::to_owned)
            .collect();
        group.reachable_from = names
            .into_iter()
            .filter(|source| *source != name && form.contains_key(&format!("{FROM}{source}")))
            .collect();
        Ok(())
    })
}

/// Deletes a group that no device belongs to.
pub async fn delete(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    change(&state, GroupForm::default(), |config, devices| {
        if devices.iter().any(|device| device.group == name) {
            return Err(format!(
                "{name} still has devices, move them to another group first"
            ));
        }
        if config.groups.len() > 1 && config.default_group == name {
            return Err(format!(
                "{name} is the default group, choose another default first"
            ));
        }
        config.groups.retain(|group| group.name != name);
        if config.groups.is_empty() {
            config.default_group.clear();
        }
        Ok(())
    })
}

/// Sets the group for devices that are not in the list.
pub async fn set_default(State(state): State<AppState>, Form(form): Form<DefaultForm>) -> Response {
    change(&state, GroupForm::default(), |config, _| {
        config.default_group = form.group;
        Ok(())
    })
}
