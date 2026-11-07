//! What the scans saw on the network. Kept in memory, never written to `devices.toml`: the list is the plan, this is
//! what is there now.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::compare::{Observation, Seen};
use crate::devices::Device;

/// The last time a device was seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Sighting {
    ip: Option<Ipv4Addr>,
    seen_at: u64,
    access_point: String,
}

/// All sightings, by MAC address.
#[derive(Debug, Default)]
pub(crate) struct Live {
    /// The last scan that every plugin answered.
    last_scan: u64,
    sightings: HashMap<String, Sighting>,
}

/// What a card shows about a device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Status {
    /// `seen`, `away`, or empty before the first scan and for devices that are not expected to appear.
    pub(crate) state: &'static str,
    /// The tooltip of the dot.
    pub(crate) detail: String,
    /// How long ago the device was seen, if it is away.
    pub(crate) away: String,
    /// The address in use, if it is not the planned one.
    pub(crate) actual_ip: String,
}

/// Seconds since the epoch.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn ago(seconds: u64) -> String {
    match seconds {
        0..3_600 => format!("{} min", (seconds / 60).max(1)),
        3_600..172_800 => format!("{} h", seconds / 3_600),
        _ => format!("{} days", seconds / 86_400),
    }
}

impl Live {
    /// Takes in one scan. Without an answer from every plugin, devices that are missing keep their state.
    pub(crate) fn record<'a>(
        &mut self,
        time: u64,
        observations: impl Iterator<Item = &'a Observation>,
        complete: bool,
    ) {
        if complete {
            for sighting in self.sightings.values_mut() {
                sighting.access_point.clear();
            }
            self.last_scan = time;
        }
        for observation in observations {
            // A lease stays after the device left, so it only counts if the plugin knows no better.
            let leases_count = observation.neighbours.is_none();
            for seen in &observation.seen {
                self.sighted(seen, time, leases_count);
            }
            for seen in observation.neighbours.iter().flatten() {
                self.sighted(seen, time, true);
            }
            for client in &observation.wifi {
                let sighting = self.sightings.entry(client.mac.to_ascii_lowercase()).or_default();
                sighting.seen_at = time;
                sighting.access_point.clone_from(&client.access_point);
            }
        }
    }

    fn sighted(&mut self, seen: &Seen, time: u64, online: bool) {
        let sighting = self.sightings.entry(seen.mac.to_ascii_lowercase()).or_default();
        if online {
            sighting.seen_at = time;
        }
        if seen.ip.is_some() {
            sighting.ip = seen.ip;
        }
    }

    /// The Wi-Fi a device is on, empty if it is not.
    pub(crate) fn access_point(&self, mac: &str) -> &str {
        self.sightings
            .get(mac)
            .map_or("", |sighting| sighting.access_point.as_str())
    }

    /// The status of a device at `time`.
    pub(crate) fn status(&self, device: &Device, time: u64) -> Status {
        let Some(sighting) = self.sightings.get(&device.mac) else {
            // A device with its address set on itself has no lease, so a scan cannot find it.
            if self.last_scan == 0 || device.self_assigned {
                return Status::default();
            }
            return Status {
                state: "away",
                detail: "Not seen by any scan".to_owned(),
                away: "Not seen yet".to_owned(),
                actual_ip: String::new(),
            };
        };
        let actual_ip = sighting
            .ip
            .filter(|ip| !device.self_assigned && device.ip.is_some_and(|planned| planned != *ip))
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        if sighting.seen_at >= self.last_scan {
            let detail = if sighting.access_point.is_empty() {
                "Seen in the last scan".to_owned()
            } else {
                format!("Seen in the last scan, on {}", sighting.access_point)
            };
            return Status {
                state: "seen",
                detail,
                away: String::new(),
                actual_ip,
            };
        }
        let away = if sighting.seen_at == 0 {
            "Not seen yet".to_owned()
        } else {
            format!("Not seen for {}", ago(time.saturating_sub(sighting.seen_at)))
        };
        Status {
            state: "away",
            detail: away.clone(),
            away,
            actual_ip,
        }
    }
}

#[cfg(test)]
mod tests;
