# lanlord

A device list for small OpenWrt networks.
Give every device a name and a group, lanlord writes the static DHCP leases and the Wi-Fi VLAN of each device to
the OpenWrt router and access points.
Devices that are not in the list show up as new and stay in the default group until you assign them.

## How it works

- Groups map to VLANs, for example `lan`, `iot` and `guest`. The groups and their VLAN ids are configuration.
- Discovery reads the DHCP leases of the router. A MAC address that is not in the list is shown as new, with the
  host name it sent and the time it was first seen.
- Wi-Fi devices keep their SSID and passphrase. The VLAN is assigned per MAC address on the access point
  (`wifi-station` and `wifi-vlan` sections), so moving a device to another group needs no change on the device.
  Unknown devices get the default network of the SSID.
- Before anything is written, lanlord shows a preview of the changes per router and access point.
- lanlord changes only the sections it owns (`lanlord_*` in `dhcp` and `wireless`). The VLAN interfaces, firewall
  zones and SSIDs are set up separately, for example with Ansible or LuCI.

### Requirements on OpenWrt

- OpenWrt on the router and every access point.
- The full `wpad` variant (`wpad-mbedtls` or `wpad-openssl`) on every access point. The basic variants cannot assign
  VLANs per station.
- The VLANs configured as bridge VLANs, tagged towards the router.
- The `lanlord-apply` script and the SSH key of lanlord on every device, see below.

### Access to the routers

lanlord connects over SSH with its own key. On the router and the access points the key is restricted to one
command in `authorized_keys`:

```text
command="/usr/libexec/lanlord-apply",no-port-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... lanlord
```

`lanlord-apply read` prints the DHCP leases and the sections owned by lanlord.
`lanlord-apply write` accepts only a checked list of leases and station VLANs on standard input.
A leaked key can change these entries, but cannot run other commands.

## Container Quick Start

```sh
docker run -d --name lanlord \
   --restart unless-stopped \
   --user "$(id -u):$(id -g)" \
   --read-only --cap-drop ALL --security-opt no-new-privileges \
   -p 127.0.0.1:8080:8080 \
   ghcr.io/tl-photography/lanlord:latest
```

lanlord has no login of its own.
Run it behind a reverse proxy with authentication, and do not expose it to the internet.

`LANLORD_LISTEN` sets the listen address, the default is `0.0.0.0:8080`.
The container health check runs `/lanlord healthcheck`.

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
```

### User and permissions

The image runs as uid and gid 10001 by default.
Any other `uid:gid` works with `--user` or `user:`, lanlord needs no entry in `/etc/passwd`.
Use the owner of the data directory, so the SSH key in it can stay readable for that user only.
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

| Job                   | Checks                                                                                  |
| --------------------- | --------------------------------------------------------------------------------------- |
| Format, lint and test | `rustfmt`, `clippy` with all warnings as errors, unit and HTTP tests                    |
| Dependencies          | `cargo-deny`: known vulnerabilities, licenses, crate sources                            |
| Secrets               | TruffleHog over the whole history                                                       |
| Pre-commit hooks      | whitespace, YAML, TOML, private keys, actionlint, hadolint, shellcheck                  |
| Image                 | build, [container tests](tests/container.sh), Trivy, Dockle, ZAP                        |

The container tests check the image from outside: no root, no shell, no package manager, no setuid files, a start
read-only, without capabilities and as an arbitrary uid, the response headers and a clean stop on SIGTERM.
Trivy scans the image for known vulnerabilities and the Dockerfile for misconfigurations, Dockle checks the image
against the CIS Docker Benchmark, and a ZAP baseline scan tests the running web interface.
Accepted ZAP findings are listed with a reason in [.zap/rules.tsv](.zap/rules.tsv).

A weekly run checks new advisories for the dependencies and the base images.
Dependabot keeps the crates, the actions and the base images up to date.
