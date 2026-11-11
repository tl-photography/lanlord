<p align="center"><img src="assets/lanlord.svg" alt="lanlord: every device needs a lease" width="400"></p>

# lanlord

A device list for small OpenWrt networks.
Every device gets a name and a group, and every group is a VLAN.
lanlord compares the list with what the router and the access points report, adds new devices and shows
differences.

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

### Plugins

| Type                                               | Reports                                                           | Applies                                  |
| -------------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------------- |
| [`openwrt`](src/plugins/openwrt/README.md)         | DHCP leases, static leases, Wi-Fi clients and Wi-Fi VLANs per MAC | static leases, if the device serves DHCP |
| [`pihole`](src/plugins/pihole/README.md)           | the devices in Pi-hole's network table, if switched on            | client groups per lanlord group          |
| [`snmp`](src/plugins/snmp/README.md)               | the VLAN of the ports of a managed switch, for drift              | -                                        |
| [`leases-file`](src/plugins/leases_file/README.md) | the devices in a dnsmasq lease file in the data directory         | -                                        |
| [`webhook`](src/plugins/webhook/README.md)         | -                                                                 | notifications as JSON to a URL           |
| [`ntfy`](src/plugins/ntfy/README.md)               | -                                                                 | notifications to an ntfy topic           |
| [`mqtt`](src/plugins/mqtt/README.md)               | -                                                                 | notifications to an MQTT topic           |
| [`email`](src/plugins/email/README.md)             | -                                                                 | notifications by mail                    |

File settings, like password files, are file names in the data directory. Paths outside it are rejected.
OpenWrt and Pi-hole plugins can be linked to the device they talk to. With a device and no address, lanlord uses
the device's fixed address. The device card then shows the plugin, Wi-Fi clients name the device as access point,
and renaming the device updates the plugin.

Each plugin's README, linked in the table, describes its setup and what it needs on the device.

### Background scan

Set on the Settings page: every how many minutes lanlord scans on its own (10 by default, 0 is off). The notification
plugins then hear about devices added or removed, and about changes made outside lanlord, for example a
lease edited in LuCI: open changes on a target while the device list did not change since it last matched. Changes
you make in lanlord are no such thing, they wait for Apply.

With "Restore" on, lanlord undoes changes made outside it through the normal apply, with its rollback and read-back,
and says so in the history and a notification. It is off by default.

### DNS

On the Settings page: the DNS server of all networks, the router or a plugin that offers DNS, like Pi-hole. A plugin
offers it at the fixed address of the device it is linked to.

### Own Wi-Fi

A group can have an SSID of its own, for example for ESP8266 devices that fail with fast roaming. Its password is in a
file in the data directory with mode 0600, named on the Groups page. Two boxes choose whether it runs on 2.4 GHz, 5 GHz or both.

### Subnets

Every group can have a subnet on the Groups page. A device with a fixed address outside it gets a warning on its card
and page; moving it to another group stays possible, so it is not refused.

### Settings

The Settings page chooses what the device overview shows: MAC and IP addresses are both on by default (`[overview]`
in `lanlord.toml`, `show_mac` and `show_ip`).

### Login

lanlord asks for one password. Its Argon2id hash is `password.hash` in the data directory; set it with

```sh
docker exec -it lanlord /lanlord set-password
```

After failed attempts each next attempt waits longer. Sessions last 12 hours and end with a restart.

## Container Quick Start

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

Run it behind a reverse proxy with HTTPS, and do not expose it to the internet.

`LANLORD_LISTEN` sets the listen address, the default is `0.0.0.0:8080`. `LANLORD_DATA` sets the data directory, the
default is `/data`. The container health check runs `/lanlord healthcheck`.

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

### User and permissions

The image runs as uid and gid 10001 by default.
Any other `uid:gid` works with `--user` or `user:`, lanlord needs no entry in `/etc/passwd`.
Use the owner of the data directory, so the password files in it can stay readable for that user only.
Root and the `PUID`/`PGID` environment variables of other images are not supported, the container never runs as root.

### Hardening

- One static binary on an empty base image: no shell, no package manager, no libraries, about 2 MB.
- Runs with a read-only file system, without capabilities and with `no-new-privileges`.
- Strict response headers on every page (Content Security Policy, no frames, no caching).
- Base images pinned by digest, the binary carries its dependency list for scanners (cargo-auditable).
- Integer overflow checks also in release builds.

## Docker Releases

Publishing a GitHub release builds the image and pushes it to GitHub Container Registry as
`ghcr.io/tl-photography/lanlord:<release-tag>`, with an SBOM and build provenance in the registry.
`latest` follows the most recent release that is not a prerelease.

Every release also has two SBOM files attached: the image (SPDX) and the Rust dependencies (CycloneDX).

## Running From Source

```sh
cargo run --release
```

The toolchain version is pinned in [rust-toolchain.toml](rust-toolchain.toml), rustup installs it on the first build.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Install the hooks once with `pre-commit install`.
They check formatting and lints, scan for secrets and lint the Dockerfile, the workflows and shell scripts.
Without a local Rust installation, pre-commit installs the pinned toolchain itself.

CI runs on every push and pull request, but only the checks the change needs. Releases and manual runs
check everything:

| Job                   | Checks                                                                 |
| --------------------- | ---------------------------------------------------------------------- |
| Format, lint and test | `rustfmt`, `clippy` with all warnings as errors, unit and HTTP tests   |
| Dependencies          | `cargo-deny`: known vulnerabilities, licenses, crate sources           |
| Secrets               | TruffleHog over the whole history                                      |
| Pre-commit hooks      | whitespace, YAML, TOML, private keys, actionlint, hadolint, shellcheck |
| Image                 | build, [container tests](tests/container.sh), Trivy, Dockle, ZAP       |
| Test coverage         | `cargo llvm-cov` with the targets in [TESTING.md](TESTING.md)          |
| CodeQL                | security and quality queries for the Rust code and the workflows       |

The container tests check the image from outside: no root, no shell, no package manager, no setuid files, a start
read-only, without capabilities and as an arbitrary uid, the response headers and a clean stop on SIGTERM.
Trivy scans the image for known vulnerabilities and the Dockerfile for misconfigurations, Dockle checks the image
against the CIS Docker Benchmark, and a ZAP baseline scan tests the running web interface.
Accepted ZAP findings are listed with a reason in [.zap/rules.tsv](.zap/rules.tsv).

Findings of CodeQL, clippy and Trivy go to GitHub code scanning. The coverage summary is posted as a comment on
each pull request and updated with every push.

Jobs can also run on a PC, each in a disposable VM: see [tools/runner](tools/runner/README.md).

A weekly run checks new advisories for the dependencies and the base images.
Dependabot keeps the crates, the actions, the base images and the pre-commit hooks up to date.

## License

lanlord is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md): free for personal use and other
noncommercial purposes. Commercial use needs a separate commercial license from the author; ask through
[GitHub](https://github.com/tl-photography/lanlord/issues).
