<p align="center"><img src="assets/lanlord.svg" alt="lanlord: every device needs a lease" width="400"></p>

<p align="center">
  <a href="https://github.com/tl-photography/lanlord/actions/workflows/ci.yml"><img src="https://github.com/tl-photography/lanlord/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/tl-photography/lanlord/releases"><img src="https://img.shields.io/github/v/release/tl-photography/lanlord" alt="Release"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue" alt="License"></a>
</p>

# lanlord

One list of the devices in a small network, and a network that follows it.

Every device gets a name and a group, and every group is a VLAN. lanlord keeps the list, compares it with what the
router, the access points and other systems report, and changes them to match, from a web page, with a preview and
a rollback.

## Features

- **One device list:** names, MAC addresses, fixed addresses, notes. A device can have several interfaces, like a
  laptop with Wi-Fi, dock and cable.
- **Groups as networks:** each group is a VLAN with its own subnet, DHCP pool, firewall zone and optional Wi-Fi. A
  group reaches only the internet, unless it is opened to other groups or single ports.
- **Scans:** new devices land in a default group, marked as new; differences such as other addresses, names or VLANs
  are listed. A background scan can notify you.
- **Apply with a preview:** every change is shown first, as the exact commands. OpenWrt changes are applied with
  rollback and confirmed only after reading them back.
- **Plugins:** OpenWrt, Pi-hole, SNMP switches and DHCP lease files; notifications by webhook, ntfy, MQTT and email.
- **History:** every change and every apply, with the values before and after.

## Quick start

```sh
docker run -d --name lanlord \
   --restart unless-stopped \
   --user "$(id -u):$(id -g)" \
   --read-only --cap-drop ALL --security-opt no-new-privileges \
   -v "$PWD/lanlord-data:/data" \
   -p 127.0.0.1:8080:8080 \
   ghcr.io/tl-photography/lanlord:latest
docker exec -it lanlord /lanlord set-password
```

Then open <http://127.0.0.1:8080>, add your groups and a plugin for your router. Run lanlord behind a reverse proxy
with HTTPS, and do not expose it to the internet.

### Docker Compose

```yaml
services:
  lanlord:
    image: ghcr.io/tl-photography/lanlord:latest
    restart: unless-stopped
    user: "${PUID}:${PGID}"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    volumes:
      - ./lanlord-data:/data
```

## Configuration

| Variable         | Default        | Meaning            |
| ---------------- | -------------- | ------------------ |
| `LANLORD_LISTEN` | `0.0.0.0:8080` | the listen address |
| `LANLORD_DATA`   | `/data`        | the data directory |

Devices, groups and plugin settings are TOML files in the data directory: `devices.toml`, `groups.toml` and
`lanlord.toml`. Passwords and tokens are files there too, readable for the owner only (mode 0600). The container
health check runs `/lanlord healthcheck`.

### User and permissions

The image runs as uid and gid 10001 by default.
Any other `uid:gid` works with `--user` or `user:`, lanlord needs no entry in `/etc/passwd`.
Use the owner of the data directory, so the password files in it can stay readable for that user only.
Root and the `PUID`/`PGID` environment variables of other images are not supported, the container never runs as root.

## Plugins

| Type                                               | Reports                                                           | Applies                                  |
| -------------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------------- |
| [`openwrt`](src/plugins/openwrt/README.md)         | DHCP leases, static leases, Wi-Fi clients and switch ports        | static leases, DNS names, group networks |
| [`pihole`](src/plugins/pihole/README.md)           | the devices in Pi-hole's network table, if switched on            | client groups per lanlord group          |
| [`snmp`](src/plugins/snmp/README.md)               | the VLAN of the ports of a managed switch, for drift              | -                                        |
| [`leases-file`](src/plugins/leases_file/README.md) | the devices in a dnsmasq lease file in the data directory         | -                                        |
| [`webhook`](src/plugins/webhook/README.md)         | -                                                                 | notifications as JSON to a URL           |
| [`ntfy`](src/plugins/ntfy/README.md)               | -                                                                 | notifications to an ntfy topic           |
| [`mqtt`](src/plugins/mqtt/README.md)               | -                                                                 | notifications to an MQTT topic           |
| [`email`](src/plugins/email/README.md)             | -                                                                 | notifications by mail                    |

Each plugin's README, linked in the table, describes its setup and what it needs on the device.

## Documentation

- [Using lanlord](docs/usage.md): how it works, scans, apply, DNS, Wi-Fi, subnets, login.
- [Architecture](docs/architecture.md): the model, the use cases and the plugin roles.
- [Testing](TESTING.md) and [Contributing](CONTRIBUTING.md).

## Security

- One static binary on an empty base image: no shell, no package manager, no libraries, about 2 MB.
- Runs with a read-only file system, without capabilities and with `no-new-privileges`.
- Strict response headers on every page (Content Security Policy, no frames, no caching).
- Base images pinned by digest, the binary carries its dependency list for scanners (cargo-auditable).
- Integer overflow checks also in release builds.

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Releases

Publishing a GitHub release builds the image and pushes it to GitHub Container Registry as
`ghcr.io/tl-photography/lanlord:<release-tag>`, with an SBOM and build provenance in the registry.
`latest` follows the most recent release that is not a prerelease.

Every release also has two SBOM files attached: the image (SPDX) and the Rust dependencies (CycloneDX).

## License

lanlord is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md): free for personal use and other
noncommercial purposes. Commercial use needs a separate commercial license from the author; ask through
[GitHub](https://github.com/tl-photography/lanlord/issues).
