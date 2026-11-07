//! The network as a tree: who hangs on whom. Wi-Fi clients are placed by the last scan, the rest by the device list,
//! or by the port a scan found them on if the list does not say.

use std::collections::HashSet;

use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};

use crate::devices::{Device, DeviceList};
use crate::live::{self, Live};
use crate::{AppState, server_error};

/// One connection in the tree.
#[derive(Debug, PartialEq, Eq)]
struct Node {
    name: String,
    role: &'static str,
    /// How it is connected, like `lan1` or `Wi-Fi: Home`.
    link: String,
    status: live::Status,
}

/// The tree as a sequence, which a template can print without recursion.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    Open,
    Node(Node),
    EndNode,
    Close,
}

/// A connection without a place in the tree.
struct Loose {
    name: String,
    status: live::Status,
}

/// Where a device hangs and how, from the Wi-Fi it is on or from the list.
fn place(device: &Device, list: &DeviceList, live: &Live) -> Option<(String, String)> {
    let access_point = live.access_point(&device.mac);
    if let Some((name, ssid)) = access_point.split_once(": ")
        && list.devices.iter().any(|other| other.name == name)
    {
        return Some((name.to_owned(), format!("Wi-Fi: {ssid}")));
    }
    let exists = |name: &str| list.devices.iter().any(|other| other.name == name);
    if device.uplink.is_empty() {
        let (switch, port) = live.wired(&device.mac)?;
        return (switch != device.name && exists(switch))
            .then(|| (switch.to_owned(), format!("{port}, detected")));
    }
    let uplink = (device.uplink != device.name).then(|| device.uplink.clone())?;
    exists(&uplink).then(|| {
        let link = match (device.medium.label(), device.port.as_str()) {
            ("", port) => port.to_owned(),
            (medium, "") => medium.to_owned(),
            (medium, port) => format!("{medium}, {port}"),
        };
        (uplink, link)
    })
}

struct Tree<'a> {
    list: &'a DeviceList,
    live: &'a Live,
    time: u64,
    places: Vec<Option<(String, String)>>,
    visited: HashSet<usize>,
    tokens: Vec<Token>,
}

impl Tree<'_> {
    fn walk(&mut self, index: usize, link: String) {
        self.visited.insert(index);
        let device = &self.list.devices[index];
        self.tokens.push(Token::Node(Node {
            name: device.name.clone(),
            role: if device.role.is_client() {
                ""
            } else {
                device.role.label()
            },
            link,
            status: self.live.status(device, self.time),
        }));
        let mut children: Vec<(usize, String)> = self
            .places
            .iter()
            .enumerate()
            .filter(|(child, _)| !self.visited.contains(child))
            .filter_map(|(child, place)| {
                place
                    .as_ref()
                    .filter(|(parent, _)| *parent == device.name)
                    .map(|(_, link)| (child, link.clone()))
            })
            .collect();
        children.sort_by_key(|(child, _)| {
            let other = &self.list.devices[*child];
            (other.role, other.name.to_ascii_lowercase())
        });
        if !children.is_empty() {
            self.tokens.push(Token::Open);
            for (child, link) in children {
                if !self.visited.contains(&child) {
                    self.walk(child, link);
                }
            }
            self.tokens.push(Token::Close);
        }
        self.tokens.push(Token::EndNode);
    }
}

/// The tree from the routers and from unplaced devices others hang on, and the indexes of the connections outside it.
/// A loop stays outside.
fn build(list: &DeviceList, live: &Live, time: u64) -> (Vec<Token>, Vec<usize>) {
    let mut tree = Tree {
        list,
        live,
        time,
        places: list
            .devices
            .iter()
            .map(|device| place(device, list, live))
            .collect(),
        visited: HashSet::new(),
        tokens: Vec::new(),
    };
    let has_children = |device: &Device| {
        tree.places
            .iter()
            .flatten()
            .any(|(parent, _)| *parent == device.name)
    };
    let mut roots: Vec<usize> = list
        .devices
        .iter()
        .enumerate()
        .filter(|(index, device)| {
            tree.places[*index].is_none()
                && (device.role == crate::devices::Role::Router || has_children(device))
        })
        .map(|(index, _)| index)
        .collect();
    roots.sort_by_key(|index| list.devices[*index].role);
    if !roots.is_empty() {
        tree.tokens.push(Token::Open);
        for root in roots {
            tree.walk(root, String::new());
        }
        tree.tokens.push(Token::Close);
    }
    let loose = (0..list.devices.len())
        .filter(|index| !tree.visited.contains(index))
        .collect();
    (tree.tokens, loose)
}

#[derive(Template)]
#[template(path = "connections.html")]
struct ConnectionsPage {
    nav: &'static str,
    tokens: Vec<Token>,
    loose: Vec<Loose>,
}

/// Shows the network by connection.
pub async fn show(State(state): State<AppState>) -> Response {
    let list = match state.devices() {
        Ok(list) => list,
        Err(error) => return server_error(&error),
    };
    let Ok(sightings) = state.inner.live.lock() else {
        return server_error(&"scan results lock poisoned");
    };
    let time = live::now();
    let (tokens, loose) = build(&list, &sightings, time);
    let mut loose: Vec<Loose> = loose
        .into_iter()
        .map(|index| Loose {
            name: list.devices[index].name.clone(),
            status: sightings.status(&list.devices[index], time),
        })
        .collect();
    loose.sort_by_key(|device| device.name.to_ascii_lowercase());
    let page = ConnectionsPage {
        nav: "devices",
        tokens,
        loose,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => server_error(&error),
    }
}

#[cfg(test)]
mod tests;
