# Plugin `openwrt`

Reports DHCP leases, static leases, Wi-Fi clients and Wi-Fi VLANs per MAC address of an OpenWrt router or access point,
and applies static leases if the device serves DHCP and no plugin is chosen as DHCP server on the Settings page.

lanlord uses the ubus JSON-RPC API that LuCI uses, as its own rpcd user. An ACL on the device decides what that
user may read and change, for example in `/usr/share/rpcd/acl.d/lanlord.json`:

```json
{
  "lanlord": {
    "description": "lanlord device list",
    "read": {
      "ubus": {
        "luci-rpc": ["getDHCPLeases"],
        "network.interface": ["dump"],
        "uci": ["get"],
        "iwinfo": ["devices", "assoclist"]
      },
      "uci": ["dhcp", "wireless"]
    },
    "write": {
      "ubus": { "uci": ["add", "set", "delete", "apply", "confirm", "rollback", "revert"] },
      "uci": ["dhcp"]
    }
  }
}
```

and the user in `/etc/config/rpcd`, with a password hash from `uhttpd -m <password>`:

```text
config login
	option username 'lanlord'
	option password '$1$...'
	list read 'lanlord'
	list write 'lanlord'
```

Without the `write` part, lanlord only reads. An access point that serves no DHCP needs only the `read` part.

The plugin needs the HTTPS address of the device, the user, the name of a file in the data directory with the
password (mode `0600`) and the SHA-256 fingerprint of the device's certificate. lanlord trusts only that
certificate, so a self-signed one works without a certificate authority. The fingerprint:

```sh
openssl s_client -connect router.lan:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

## Networks

With "Manage networks" on, the OpenWrt plugin builds a network for every group with a VLAN other than 1. On a router:
a VLAN on the bridge, an interface with the first address of the group's subnet, a DHCP pool from .100 to .249 with
the DNS service, and a firewall zone that may reach the internet, DHCP and the DNS service, with DNS to anywhere else
redirected to it. No IPv6: router advertisements and DHCPv6 are off in its DHCP pool. On an access point, a device without DHCP: the VLAN and an interface without an address. A
group with its own SSID gets a Wi-Fi network on every radio.

The first network turns the bridge into a VLAN bridge: VLAN 1 untagged on every port, the LAN interface moves to
`br-lan.1`. Every other section lanlord adds is named `lanlordnet_`. A bridge with VLANs set up outside lanlord is left
alone. Network changes are applied with a rollback after 60 seconds, so a change that cuts lanlord off undoes itself.

Cabled devices get their VLAN on the bridge port: a port where only one known device was ever seen carries that
device's VLAN untagged and nothing else, every other port carries VLAN 1 untagged and the other VLANs tagged. The
plugin keeps every MAC address ever seen per port in `<plugin>.ports` in the data directory, so a device that was quiet
for a while does not make a shared port look like it had one device.

The ACL then also needs `network`, `firewall` and `wireless` in `read.uci` and `write.uci`, `network.device`
`status` in `read.ubus`, and in `read.file` `/sys/class/net/br-lan/brforward` and
`/sys/class/net/br-lan/brif/*/port_no`.
