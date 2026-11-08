# Architecture

## Purpose

lanlord manages small, mostly private networks of medium complexity. It keeps one list of devices and groups and makes
the network follow it, from a web page, without playbooks or a laptop. The list says what should be. Scans say what
is. lanlord shows the difference and closes it when asked.

Not in scope: traffic monitoring, custom firewall rules, presence, showing how devices are connected. A later plugin
may add views such as a device tree, without changing the model.

## Use cases

1. **Handle a new device.** A scan finds an unknown device. lanlord adds it to the default group, marks it as new and
   notifies. The user names it and moves it, or leaves it. It stays until it is removed.
2. **Notice drift.** The network no longer matches the list: lanlord shows it and notifies. Fixing it is up to the user.
3. **Make the network follow the list.** Static leases, DNS names, filter groups and the VLAN of every device, on
   Wi-Fi and on cable. The user sees the exact changes first, and a failed change is undone.
4. **Describe a device with several interfaces.** A laptop with Wi-Fi and cable is one device.
5. **Set an address on the device.** lanlord gives it a DNS name and no lease.
6. **Prune guests.** A device in the default group that was not seen for 30 days is removed.
7. **Create a network.** A new group becomes a network on the router and access points: VLAN, interface, DHCP pool,
   firewall zone and Wi-Fi. A group that exists in lanlord but not yet in the network is a change to apply.
   By default a new network reaches only the internet and its DNS server.
8. **Look back.** Every change, with the values before and after.

## Overview

```text
             core, knows no plugin
  +---------------------------------------------+
  |  Plan            what should be, stored     |
  |  Observations    what is, from scans        |
  |  Services        what plugins offer         |
  |  Views           findings, changes          |
  +---------------------------------------------+
     ^            ^             |               |
     | facts      | services    | plan,         | events
     |            |             | services      |
     |            |             v               v
 +--------+  +----------+  +--------+     +----------+
 | Source |  | Provider |  | Target |     | Notifier |
 +--------+  +----------+  +--------+     +----------+
        plugins: translate between the core and one system
```

Rules:

- The core has one vocabulary. No plugin concept appears in the plan or in a view.
- A plugin only translates. It reports observations in that vocabulary, or turns the plan into changes on its system.
- The core never asks which plugin something came from, except to name the source in a message.
- A new plugin needs no change in the core. If it does, the vocabulary is missing a general concept.
- Plugins never talk to each other. One offers a service to the core, the core passes it to the targets.
- A plugin can have several roles. The OpenWrt plugin is a source and a target.
- The core sets the VLAN of an interface through its group. How that reaches the network is up to each target: the
  OpenWrt plugin by a port or the group's own Wi-Fi, an SNMP plugin by a switch port.
- Wi-Fi: a group can have an SSID of its own, optionally only on the 2.4 GHz radios. A device joins the network of its
  group by using that SSID.
- A group opens only what it is told to: which groups may reach it, and which single ports it may reach elsewhere.
- A plugin instance can be linked to a device in its settings. That gives the plugin the device's address and shows
  it on the device. The plan does not know about it.

## Data model

### Plan

Stored, changed by the user, written to the history.

```text
Network    dns_service
Group      name, label, vlan, subnet, ssid, ssid_2g_only, reachable_from, reaches
Interface  device, name, mac, group, address, note, reviewed
Address    none | lease(ip) | on_device(ip)
```

- A device has one or more interfaces. A device with one interface has its name.
- The interface is what the network sees: MAC address, address, DNS name, group.
- `dns_service` chooses one of the offered DNS services for all networks, empty for the router. Devices can reach it
  from every network, and DNS to anywhere else is redirected to it.
- A group is one network: a VLAN and a subnet. Rules such as blocklists follow the group. One group is the default for
  unknown devices.
- The MAC address is the identity of an interface. A device that hides it is unknown each time and stays in the
  default group.

### Observations

Facts from one scan, each with its source. Never part of the plan, and not kept: the core is stateless. The one
exception is a last-seen date for the default group, stored apart from the plan, for pruning.

```text
Presence    mac, ip, hostname
Assigned    system, mac, name, ip, vlan
```

- `Presence`: this address is on the network now.
- `Assigned`: this system has this configured, for example a static lease.

### Services

What a plugin offers to the network, from its settings and not from a scan, so an outage changes nothing.

```text
Service  kind, address, source
```

- `kind` is general, for example `dns`.
- A plugin knows its address from the device it is linked to. Without a link it offers nothing.

### Views

Calculated from plan and observations, never stored.

- **Findings**: unknown device, missing or different assignment, address outside the subnet.
- **Changes**: per target, what `Apply` would do.

## Plugin interfaces

```text
Source    observe() -> Observations
Provider  services() -> Services
Target    assigned() -> Assigned
          changes(Plan, Services) -> Changes
          apply(Changes) -> Result
Notifier  notify(Event)
```

## Flows

**Scan:** runs in the background at an interval, or from a button. Every source is asked and the views are calculated.
Unknown devices are added to the default group, new findings become events, and the last-seen dates are updated. A
scan where a source failed removes nothing.

**Prune:** a change to the plan like any other, in the history, with a notification.

**Edit:** the user changes the plan, it is saved and logged. The network does not change.

**Service change:** a chosen service gets a new address or goes away. The core recalculates the changes of the targets,
so it appears in Apply and as a notification. The network changes only on Apply.

**Apply:** the target calculates the changes from the plan and shows them. On confirmation it applies them, reads back
and rolls back on failure.

## Later

- Fix drift automatically, as a setting.
- Quieter notifications for the default group, if devices with hidden MAC addresses get noisy.
