<p align="center"><img src="assets/lanlord.svg" alt="lanlord: every device needs a lease" width="400"></p>

# lanlord

A device list for small OpenWrt networks.
Give every device a name and a group, then compare the list with enabled network sources.
Changes in lanlord are not applied to the router or Pi-hole yet.

## How it works

- Groups map to VLANs, for example `lan`, `iot` and `guest`. The groups and their VLAN ids are configuration.
- Devices and groups are stored in the data directory as `devices.toml` and `groups.toml`.
- The Plugins page configures sources and scans them for unknown devices and discrepancies.
- Moving a device changes its group in lanlord only. The router and access points are unchanged.
- Pi-hole can report network devices, but OpenWrt remains the DHCP source of truth.

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

The OpenWrt plugin uses `host`, `user`, `port`, `key_file` and `host_key_file` settings. The private key and pinned
host public key stay in files in the data directory. The private key file must be readable by the lanlord user and
have mode `0600`.

The restricted `lanlord-apply read` helper emits tab-separated records:

```text
lease<TAB>mac<TAB>ip<TAB>hostname
entry<TAB>mac<TAB>name<TAB>ip-or--<TAB>vlan-or--
```

The current helper supports reads only. It rejects every other request and does not change router configuration.

The Pi-hole plugin uses the v6 API's `/network/devices` endpoint. Set its API URL and a `password_file` path in the
Plugins page. Store an application password in a mode-`0600` file, not in `lanlord.toml`. The URL must be reachable
from the lanlord container.

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
