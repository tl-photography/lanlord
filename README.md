<p align="center"><img src="assets/lanlord.svg" alt="lanlord: every device needs a lease" width="400"></p>

# lanlord

A device list for small OpenWrt networks.
Every device gets a name and a group, and every group is a VLAN.
lanlord compares the list with what the router and the access points report and shows unknown devices and
differences.

## How it works

- Groups map to VLANs, for example `lan`, `iot` and `guest`. They are set up in the interface; the first one is the
  default group for unknown devices.
- Devices, groups and plugin settings are TOML files in the data directory: `devices.toml`, `groups.toml` and
  `lanlord.toml`.
- Plugins report what they see. A scan lists unknown devices, which can be added to the list, and differences:
  missing static leases, other addresses, names or VLANs.
- The Apply page shows what a router would change, as uci commands like LuCI. Nothing changes before the Apply
  button. lanlord applies with rollback and confirms only after reading the changes back; otherwise the router
  undoes them after 30 seconds.
- Static leases on a router are sections `dhcp.lanlord_<name>`. When lanlord sets a device's lease, it replaces an
  unnamed entry of the same MAC address; other entries stay. A device whose address is not in a network the router
  serves waits, its entry stays as it is.
- A plugin entry that cannot be used, for example after a settings change, is left out and shown on the Plugins
  page; lanlord still starts.

### Plugins

| Type          | Reports                                                                 | Applies                                  |
| ------------- | ----------------------------------------------------------------------- | ---------------------------------------- |
| `openwrt`     | DHCP leases, static leases and Wi-Fi VLANs per MAC of an OpenWrt device | static leases, if the device serves DHCP |
| `leases-file` | the devices in a dnsmasq lease file in the data directory               | -                                        |

File settings, like password files, are file names in the data directory. Paths outside it are rejected.

### OpenWrt

lanlord uses the ubus JSON-RPC API that LuCI uses, as its own rpcd user. An ACL on the device decides what that
user may read and change, for example in `/usr/share/rpcd/acl.d/lanlord.json`:

```json
{
  "lanlord": {
    "description": "lanlord device list",
    "read": {
      "ubus": { "luci-rpc": ["getDHCPLeases"], "network.interface": ["dump"], "uci": ["get"] },
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

The container tests check the image from outside: no root, no shell, no package manager, no setuid files, a start
read-only, without capabilities and as an arbitrary uid, the response headers and a clean stop on SIGTERM.
Trivy scans the image for known vulnerabilities and the Dockerfile for misconfigurations, Dockle checks the image
against the CIS Docker Benchmark, and a ZAP baseline scan tests the running web interface.
Accepted ZAP findings are listed with a reason in [.zap/rules.tsv](.zap/rules.tsv).

A weekly run checks new advisories for the dependencies and the base images.
Dependabot keeps the crates, the actions and the base images up to date.

## License

lanlord is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md): free for personal use and other
noncommercial purposes. Commercial use needs a separate commercial license from the author; ask through
[GitHub](https://github.com/tl-photography/lanlord/issues).
