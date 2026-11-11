# Using lanlord

How lanlord works and what each page does. Installation and the overview are in the [README](../README.md); the
reasons behind the design are in [architecture.md](architecture.md).

## How it works

- Groups map to VLANs, for example `lan`, `iot` and `guest`. They are set up in the interface; the first one is the
  default group for unknown devices.
- A device can have several interfaces, like a laptop with Wi-Fi, dock and cable. Each has its own MAC address, lease,
  DNS name and group, the device is one card, and moving the card moves all of them. The device's page adds, removes
  and renames them. In `devices.toml` they are `[[device.interface]]` tables; a device with one interface stays a plain
  `[[device]]`.
- Devices, groups and plugin settings are TOML files in the data directory: `devices.toml`, `groups.toml` and
  `lanlord.toml`.
- Plugins report what they see. A scan adds every unknown device to the default group, marked as new, and lists
  differences: missing static leases, other addresses, names or VLANs. A device in the default group that no scan saw
  for 30 days is removed. The last-seen dates are kept in `last-seen` in the data directory; a scan where a plugin
  failed removes nobody.
- The Apply page shows what a router would change, as uci commands like LuCI. Nothing changes before the Apply
  button. lanlord applies with rollback and confirms only after reading the changes back; otherwise the router
  undoes them after 30 seconds. The top bar shows how many changes are open; "Save and review changes" in the device
  form opens that preview. With open changes on several targets, "Apply all" applies them one after the other; a
  failed target does not stop the others.
- Static leases on a router are sections `dhcp.lanlord_<name>`. When lanlord sets a device's lease, it replaces an
  unnamed entry of the same MAC address; other entries stay. A device whose address is not in a network the router
  serves waits, its entry stays as it is.
- A plugin entry that cannot be used, for example after a settings change, is left out and shown on the Plugins
  page; lanlord still starts.
- Every change and every apply is appended to `history.log` in the data directory, with the time in UTC and the
  values before and after, and shown on the History page.

## Plugins

File settings, like password files, are file names in the data directory. Paths outside it are rejected.
OpenWrt and Pi-hole plugins can be linked to the device they talk to. With a device and no address, lanlord uses
the device's fixed address. The device card then shows the plugin, Wi-Fi clients name the device as access point,
and renaming the device updates the plugin.

The [plugin table in the README](../README.md#plugins) links each plugin's README, with its setup and what it needs
on the device.

## Background scan

Set on the Settings page: every how many minutes lanlord scans on its own (10 by default, 0 is off). The notification
plugins then hear about devices added or removed, and about changes made outside lanlord, for example a
lease edited in LuCI: open changes on a target while the device list did not change since it last matched. Changes
you make in lanlord are no such thing, they wait for Apply.

With "Restore" on, lanlord undoes changes made outside it through the normal apply, with its rollback and read-back,
and says so in the history and a notification. It is off by default.

## DNS

On the Settings page: the DNS server of all networks, the router or a plugin that offers DNS, like Pi-hole. A plugin
offers it at the fixed address of the device it is linked to.

## Own Wi-Fi

A group can have an SSID of its own, for example for ESP8266 devices that fail with fast roaming. Its password is in a
file in the data directory with mode 0600, named on the Groups page. Two boxes choose whether it runs on 2.4 GHz, 5 GHz or both.

## Subnets

Every group can have a subnet on the Groups page. A device with a fixed address outside it gets a warning on its card
and page; moving it to another group stays possible, so it is not refused.

## Settings

The Settings page chooses what the device overview shows: MAC and IP addresses are both on by default (`[overview]`
in `lanlord.toml`, `show_mac` and `show_ip`).

## Login

lanlord asks for one password. Its Argon2id hash is `password.hash` in the data directory; set it with

```sh
docker exec -it lanlord /lanlord set-password
```

After failed attempts each next attempt waits longer. Sessions last 12 hours and end with a restart.
