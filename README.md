<p align="center"><img src="assets/lanlord.svg" alt="lanlord: every device needs a lease" width="400"></p>

# lanlord

A device list for small OpenWrt networks.
Every device gets a name and a group, and every group is a VLAN.
lanlord compares the list with what the router and the access points report and shows unknown devices and
differences.

## How it works

- Groups map to VLANs, for example `lan`, `iot` and `guest`. They are set up in the interface; the first one is the
  default group for unknown devices.
- A machine with several connections, like a laptop with Wi-Fi, dock and cable, stays one entry per connection (each
  has its own MAC, lease and name). "Belongs to" groups them: the devices page shows one card for the machine, and
  moving the card moves all its connections.
- Devices, groups and plugin settings are TOML files in the data directory: `devices.toml`, `groups.toml` and
  `lanlord.toml`.
- Plugins report what they see. A scan lists unknown devices, which can be added to the list, and differences:
  missing static leases, other addresses, names or VLANs.
- The Apply page shows what a router would change, as uci commands like LuCI. Nothing changes before the Apply
  button. lanlord applies with rollback and confirms only after reading the changes back; otherwise the router
  undoes them after 30 seconds. The top bar shows how many changes are open; "Save and review changes" in the device
  form opens that preview.
- Static leases on a router are sections `dhcp.lanlord_<name>`. When lanlord sets a device's lease, it replaces an
  unnamed entry of the same MAC address; other entries stay. A device whose address is not in a network the router
  serves waits, its entry stays as it is.
- A plugin entry that cannot be used, for example after a settings change, is left out and shown on the Plugins
  page; lanlord still starts.
- Every change and every apply is appended to `history.log` in the data directory, with the time in UTC and the
  values before and after, and shown on the History page.

### Plugins

| Type          | Reports                                                                 | Applies                                  |
| ------------- | ----------------------------------------------------------------------- | ---------------------------------------- |
| `openwrt`     | DHCP leases, static leases, Wi-Fi clients and Wi-Fi VLANs per MAC       | static leases, if the device serves DHCP |
| `pihole`      | the devices in Pi-hole's network table, if switched on                  | client groups per lanlord group          |
| `leases-file` | the devices in a dnsmasq lease file in the data directory               | -                                        |
| `webhook`     | -                                                                       | notifications as JSON to a URL           |
| `ntfy`        | -                                                                       | notifications to an ntfy topic           |
| `mqtt`        | -                                                                       | notifications to an MQTT topic           |
| `email`       | -                                                                       | notifications by mail                    |

File settings, like password files, are file names in the data directory. Paths outside it are rejected.
OpenWrt and Pi-hole plugins can be linked to the device they talk to. With a device and no address, lanlord uses
the device's fixed address. The device card then shows the plugin, Wi-Fi clients name the device as access point,
and renaming the device updates the plugin.

### OpenWrt

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
        "iwinfo": ["devices", "info", "assoclist"]
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

Assigning VLANs per Wi-Fi device needs the full `wpad` variant (`wpad-mbedtls` or `wpad-openssl`) on every access
point; the basic variants cannot.

### Pi-hole

lanlord uses the REST API of Pi-hole v6. It adds a Pi-hole group for every lanlord group of a device with a fixed
address, and a client for that address in `Default` and that group. Blocklists assigned to a group then apply to its
devices. Clients lanlord adds have the comment `lanlord: <device>`; lanlord changes and removes only those. Groups are
never deleted, other clients never touched: a device whose address already has another client is listed as left out.

Pi-hole has no rollback: lanlord makes the changes one by one, reads Pi-hole again and reports anything missing.

"Report devices" adds the devices of Pi-hole's network table to a scan. Leave it off when Pi-hole runs in a container
behind NAT: it then sees no real MAC addresses, only its virtual interfaces.

The plugin needs the HTTPS address, the name of a file in the data directory with an app password (mode `0600`;
create it in Pi-hole under Settings, Web interface / API, "Configure app password") and the SHA-256 fingerprint of
Pi-hole's certificate:

```sh
openssl s_client -connect pi.hole:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

### Notifications

Notification plugins send lanlord's messages: `webhook` posts `{"title", "text", "source"}` as JSON to a URL, `ntfy`
posts to a topic on an ntfy server. Both take an optional token file in the data directory (mode `0600`), sent as
bearer token; with a token, the address must use `https://` (plain `http://` only to the own host).

`mqtt` publishes the same JSON with QoS 1 to a topic, optionally with a user and password file. With TLS, a broker
with a self-signed certificate needs its SHA-256 fingerprint. `email` sends through an SMTP server with `starttls`,
`tls` or `none`, optionally with a user and password file; a password is never sent with `none`.
 Public
servers are checked against the usual certificate authorities, built into lanlord. Each notification plugin has a
"Send test notification" button on the Plugins page.

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

A weekly run checks new advisories for the dependencies and the base images.
Dependabot keeps the crates, the actions, the base images and the pre-commit hooks up to date.

## License

lanlord is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md): free for personal use and other
noncommercial purposes. Commercial use needs a separate commercial license from the author; ask through
[GitHub](https://github.com/tl-photography/lanlord/issues).
