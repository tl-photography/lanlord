//! Setting up the groups: add, delete and choose the default group.

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

/// Fields of the form for the network of a group: its subnet and its own Wi-Fi.
#[derive(Debug, Deserialize)]
pub struct NetworkForm {
    #[serde(default)]
    subnet: String,
    #[serde(default)]
    ssid: String,
    #[serde(default)]
    password_file: String,
}

/// Field of the form for the DNS service.
#[derive(Debug, Deserialize)]
pub struct DnsForm {
    service: String,
}

/// A DNS service to choose.
struct DnsOption {
    source: String,
    label: String,
}

/// Field of the form for the default group.
#[derive(Debug, Deserialize)]
pub struct DefaultForm {
    group: String,
}

struct GroupRow {
    name: String,
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
    dns_options: Vec<DnsOption>,
    dns_service: String,
    form: GroupForm,
    error: String,
}

fn page(state: &AppState, form: GroupForm, error: String) -> Response {
    let config = state.groups();
    let list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    let dns_options = state
        .services(&list)
        .into_iter()
        .filter(|service| service.kind == "dns")
        .map(|service| DnsOption {
            label: format!("{} ({})", service.source, service.address),
            source: service.source,
        })
        .collect();
    let devices = list.interfaces;
    let groups = config
        .groups
        .iter()
        .map(|group| GroupRow {
            name: group.name.clone(),
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
        dns_options,
        dns_service: config.dns_service.clone(),
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
    };
    change(&state, form, |config, _| {
        if config.groups.is_empty() {
            config.default_group.clone_from(&group.name);
        }
        config.groups.push(group);
        Ok(())
    })
}

/// Sets the subnet of a group and its own Wi-Fi, all from one form.
pub async fn set_network(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<NetworkForm>,
) -> Response {
    change(&state, GroupForm::default(), |config, _| {
        let group = config
            .groups
            .iter_mut()
            .find(|group| group.name == name)
            .ok_or_else(|| format!("No such group: {name}"))?;
        form.subnet.trim().clone_into(&mut group.subnet);
        form.ssid.trim().clone_into(&mut group.ssid);
        let file = if group.ssid.is_empty() {
            ""
        } else {
            form.password_file.trim()
        };
        file.clone_into(&mut group.ssid_password_file);
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

/// Chooses the DNS service of all networks; empty is the router.
pub async fn set_dns(State(state): State<AppState>, Form(form): Form<DnsForm>) -> Response {
    let offered = state
        .devices()
        .map(|list| state.services(&list))
        .unwrap_or_default();
    change(&state, GroupForm::default(), |config, _| {
        let service = form.service.trim();
        if !service.is_empty()
            && !offered
                .iter()
                .any(|offer| offer.kind == "dns" && offer.source == service)
        {
            return Err(format!("{service} offers no DNS service"));
        }
        service.clone_into(&mut config.dns_service);
        Ok(())
    })
}
