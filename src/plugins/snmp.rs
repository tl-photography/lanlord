//! Plugin `snmp`: reads the VLAN of the ports of a managed switch with SNMP v2c and reports the ports with one device,
//! so a device on the wrong port shows up as drift. Read only.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::net::{UdpSocket, lookup_host};

use super::openwrt::read_password;
use super::{BoxFuture, Field, FieldKind, Plugin, PluginType, settings};
use crate::compare::{Assigned, Observation};
use crate::devices::Error;

/// `dot1qTpFdbPort`: VLAN and MAC address to port, for switches with VLANs.
const VLAN_FDB: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2];
/// `dot1dTpFdbPort`: MAC address to port.
const FDB: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
/// `dot1qPvid`: port to the VLAN of its untagged frames.
const PORT_VLAN: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1];

/// The SNMP port.
const DEFAULT_PORT: u16 = 161;
/// Waiting time for one answer.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// Tries per request: SNMP runs over UDP.
const TRIES: u32 = 3;
/// Most rows read from one table.
const MAX_ROWS: usize = 4096;
/// Largest answer that is read.
const MAX_RESPONSE_BYTES: usize = 8192;

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_GET_NEXT: u8 = 0xa1;
const TAG_RESPONSE: u8 = 0xa2;
const TAG_END_OF_MIB: u8 = 0x82;
const VERSION_2C: u32 = 1;

/// The type description for `lanlord.toml` and the web interface.
pub(super) const TYPE: PluginType = PluginType {
    kind: "snmp",
    title: "Switch (SNMP)",
    description: "Reads with SNMP v2c which VLAN the ports of a managed switch are in, and reports a device on a port \
                  of another VLAN than its group. Changes nothing on the switch.",
    fields: &[
        Field {
            key: "host",
            label: "Address",
            kind: FieldKind::Word,
            placeholder: "switch.lan",
            optional: false,
        },
        Field {
            key: "community_file",
            label: "Read community file",
            kind: FieldKind::DataFile,
            placeholder: "switch.community",
            optional: false,
        },
    ],
    build: |name, table, data_dir| Ok(Arc::new(Snmp::new(name, table, data_dir)?)),
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    host: String,
    community_file: String,
}

/// One managed switch.
pub struct Snmp {
    name: String,
    host: String,
    community_file: PathBuf,
}

impl Snmp {
    fn new(name: String, table: toml::Table, data_dir: &Path) -> Result<Self, Error> {
        let Settings { host, community_file } = settings(&name, table)?;
        Ok(Self {
            name,
            host,
            community_file: data_dir.join(community_file),
        })
    }

    async fn read(&self) -> Result<Observation, String> {
        let community = read_password(&self.community_file).await?;
        let session = Session::open(&self.host, community).await?;
        let mut table = session.walk(VLAN_FDB).await?;
        if table.is_empty() {
            table = session.walk(FDB).await?;
        }
        let vlans = numbers(session.walk(PORT_VLAN).await?);
        Ok(Observation {
            assigned: Some(single_devices(&table, &vlans)),
            partial: true,
            ..Observation::default()
        })
    }
}

impl Plugin for Snmp {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "snmp"
    }

    fn observe(&self) -> BoxFuture<'_, Result<Observation, String>> {
        Box::pin(self.read())
    }
}

/// A value of a table row.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Number(u32),
    Other,
}

impl Value {
    fn as_number(&self) -> Option<u32> {
        match self {
            Self::Number(number) => Some(*number),
            Self::Other => None,
        }
    }
}

/// The rows of a table: the end of each OID after the table, and the value.
type Rows = Vec<(Vec<u32>, Value)>;

fn numbers(rows: Rows) -> HashMap<u32, u32> {
    rows.into_iter()
        .filter_map(|(index, value)| Some((*index.last()?, value.as_number()?)))
        .collect()
}

/// The MAC address at the end of a row index.
fn mac_of(index: &[u32]) -> Option<String> {
    let start = index.len().checked_sub(6)?;
    let bytes = index[start..]
        .iter()
        .map(|&byte| u8::try_from(byte).ok().map(|byte| format!("{byte:02x}")))
        .collect::<Option<Vec<_>>>()?;
    Some(bytes.join(":"))
}

/// The ports with exactly one device, with the VLAN of the port. A port with more leads to another switch or an access
/// point and says nothing about one device.
fn single_devices(table: &Rows, vlans: &HashMap<u32, u32>) -> Vec<Assigned> {
    let mut ports: HashMap<u32, BTreeSet<String>> = HashMap::new();
    for (index, value) in table {
        // Port 0 is the switch itself.
        if let (Some(mac), Some(port)) = (mac_of(index), value.as_number().filter(|port| *port != 0)) {
            ports.entry(port).or_default().insert(mac);
        }
    }
    let mut assigned: Vec<Assigned> = ports
        .iter()
        .filter(|(_, macs)| macs.len() == 1)
        .filter_map(|(port, macs)| {
            Some(Assigned {
                mac: macs.first()?.clone(),
                name: String::new(),
                ip: None,
                vlan: vlans.get(port).and_then(|vlan| u16::try_from(*vlan).ok()),
            })
        })
        .collect();
    assigned.sort_by(|left, right| left.mac.cmp(&right.mac));
    assigned
}

/// A connection to one switch.
struct Session {
    socket: UdpSocket,
    community: String,
}

impl Session {
    async fn open(host: &str, community: String) -> Result<Self, String> {
        let target = if host.contains(':') {
            host.to_owned()
        } else {
            format!("{host}:{DEFAULT_PORT}")
        };
        let address = lookup_host(&target)
            .await
            .map_err(|error| format!("{host}: {error}"))?
            .next()
            .ok_or_else(|| format!("{host}: no address"))?;
        let local = match address {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(local).await.map_err(|error| error.to_string())?;
        socket
            .connect(address)
            .await
            .map_err(|error| format!("{host}: {error}"))?;
        Ok(Self { socket, community })
    }

    /// Reads a table row by row.
    async fn walk(&self, table: &[u32]) -> Result<Rows, String> {
        let mut rows = Vec::new();
        let mut current = table.to_vec();
        for id in 0..MAX_ROWS {
            let request = request(&self.community, u32::try_from(id).unwrap_or(0), &current);
            let (oid, value) = self.exchange(&request, u32::try_from(id).unwrap_or(0)).await?;
            let Some(index) = oid.strip_prefix(table) else {
                return Ok(rows);
            };
            // The next OID has to grow, or a broken agent would keep this loop busy.
            if value.is_none() || oid <= current {
                return Ok(rows);
            }
            rows.push((index.to_vec(), value.unwrap_or(Value::Other)));
            current = oid;
        }
        Ok(rows)
    }

    async fn exchange(&self, request: &[u8], id: u32) -> Result<(Vec<u32>, Option<Value>), String> {
        let mut buffer = vec![0; MAX_RESPONSE_BYTES];
        for _ in 0..TRIES {
            self.socket
                .send(request)
                .await
                .map_err(|error| error.to_string())?;
            let Ok(received) = tokio::time::timeout(REQUEST_TIMEOUT, self.socket.recv(&mut buffer)).await
            else {
                continue;
            };
            let size = received.map_err(|error| error.to_string())?;
            return match response(&buffer[..size]) {
                Some(answer) if answer.id == id && answer.error == 0 => Ok((answer.oid, answer.value)),
                Some(answer) if answer.id == id => Err(format!("the switch answered error {}", answer.error)),
                Some(_) => continue,
                None => Err("the switch sent an answer that cannot be read".to_owned()),
            };
        }
        Err("no answer: is SNMP on and the community right?".to_owned())
    }
}

/// Encodes a tag, its length and its content.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    match content.len() {
        size @ 0..0x80 => bytes.push(size.to_be_bytes()[7]),
        size => {
            let length = size.to_be_bytes();
            let skip = length.iter().take_while(|byte| **byte == 0).count();
            bytes.push(0x80 | length[skip..].len().to_be_bytes()[7]);
            bytes.extend_from_slice(&length[skip..]);
        }
    }
    bytes.extend_from_slice(content);
    bytes
}

fn integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes[..3].iter().take_while(|byte| **byte == 0).count();
    let mut content = bytes[skip..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(TAG_INTEGER, &content)
}

fn encode_oid(oid: &[u32]) -> Vec<u8> {
    let mut content = Vec::new();
    let first = oid.first().copied().unwrap_or(1) * 40 + oid.get(1).copied().unwrap_or(3);
    for &part in std::iter::once(&first).chain(oid.iter().skip(2)) {
        let mut groups = vec![part.to_be_bytes()[3] & 0x7f];
        let mut rest = part >> 7;
        while rest > 0 {
            groups.push(rest.to_be_bytes()[3] & 0x7f | 0x80);
            rest >>= 7;
        }
        content.extend(groups.into_iter().rev());
    }
    tlv(TAG_OID, &content)
}

fn request(community: &str, id: u32, oid: &[u32]) -> Vec<u8> {
    let binding = tlv(TAG_SEQUENCE, &[encode_oid(oid), tlv(TAG_NULL, &[])].concat());
    let bindings = tlv(TAG_SEQUENCE, &binding);
    let pdu = tlv(
        TAG_GET_NEXT,
        &[integer(id), integer(0), integer(0), bindings].concat(),
    );
    tlv(
        TAG_SEQUENCE,
        &[
            integer(VERSION_2C),
            tlv(TAG_OCTET_STRING, community.as_bytes()),
            pdu,
        ]
        .concat(),
    )
}

/// Splits off one tag with its content.
fn split(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (size, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (length, rest) = rest.split_at(count);
        let size = length.iter().fold(0, |size, byte| size << 8 | usize::from(*byte));
        (size, rest)
    };
    (rest.len() >= size).then(|| {
        let (content, rest) = rest.split_at(size);
        (tag, content, rest)
    })
}

fn expect(tag: u8, bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (found, content, rest) = split(bytes)?;
    (found == tag).then_some((content, rest))
}

fn decode_number(content: &[u8]) -> u32 {
    content
        .iter()
        .fold(0, |number, byte| number << 8 | u32::from(*byte))
}

fn decode_oid(content: &[u8]) -> Option<Vec<u32>> {
    let (&first, rest) = content.split_first()?;
    let mut oid = vec![u32::from(first / 40), u32::from(first % 40)];
    let mut part: u32 = 0;
    for byte in rest {
        part = part.checked_mul(128)?.checked_add(u32::from(byte & 0x7f))?;
        if byte & 0x80 == 0 {
            oid.push(part);
            part = 0;
        }
    }
    Some(oid)
}

/// The one row of an answer. `value` is `None` after the end of the agent's data.
struct Response {
    id: u32,
    error: u32,
    oid: Vec<u32>,
    value: Option<Value>,
}

fn response(bytes: &[u8]) -> Option<Response> {
    let (message, _) = expect(TAG_SEQUENCE, bytes)?;
    let (_, rest) = expect(TAG_INTEGER, message)?;
    let (_, rest) = expect(TAG_OCTET_STRING, rest)?;
    let (pdu, _) = expect(TAG_RESPONSE, rest)?;
    let (id, rest) = expect(TAG_INTEGER, pdu)?;
    let (error, rest) = expect(TAG_INTEGER, rest)?;
    let (_, rest) = expect(TAG_INTEGER, rest)?;
    let (bindings, _) = expect(TAG_SEQUENCE, rest)?;
    let (binding, _) = expect(TAG_SEQUENCE, bindings)?;
    let (oid, rest) = expect(TAG_OID, binding)?;
    let (tag, content, _) = split(rest)?;
    let value = match tag {
        TAG_END_OF_MIB | 0x80 | 0x81 => None,
        // Integer, counter, gauge, time ticks.
        TAG_INTEGER | 0x41..=0x43 => Some(Value::Number(decode_number(content))),
        _ => Some(Value::Other),
    };
    Some(Response {
        id: decode_number(id),
        error: decode_number(error),
        oid: decode_oid(oid)?,
        value,
    })
}

#[cfg(test)]
mod tests;
