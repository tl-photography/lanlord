# Security

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub's vulnerability reporting](https://github.com/tl-photography/lanlord/security/advisories/new).

Include what you can:

- the version or commit
- what an attacker can do, and what they need for it (network access, a login, a plugin setting)
- steps to reproduce, or a proof of concept

Reports are handled on a best-effort basis. You get an answer once the report is assessed; a fix is released as
soon as it is ready, and the advisory names you unless you prefer not.

## Supported versions

Only the latest release and `main` get security fixes.

## Scope

In scope: the lanlord code, the container image and the release workflow.

Out of scope: vulnerabilities in OpenWrt, rpcd, dnsmasq or other software lanlord talks to (report them to that
project), findings that need an attacker who can already write to the data directory, and missing hardening
without a concrete attack.

## Security model

lanlord is meant for a home or small office network, behind a reverse proxy with TLS.

- **Login:** one password, stored as an Argon2id hash. Sessions live in memory for 12 hours; cookies are
  `HttpOnly`, `Secure` and `SameSite=Strict`. Failed logins slow down further attempts.
- **Requests:** every change must come from lanlord's own pages (`Sec-Fetch-Site` or `Origin` check). The Content
  Security Policy allows no inline scripts or styles and no external content.
- **Devices on the network:** lanlord talks to OpenWrt only over HTTPS and trusts exactly one pinned certificate.
  It logs in as its own rpcd user; the rpcd ACL on the device limits what that user can read and change.
- **Changes on the network:** nothing is applied without an explicit Apply. Changes are applied with rollback and
  confirmed only after lanlord reads them back.
- **Secrets:** passwords are files in the data directory with mode `0600`, never in `lanlord.toml` or the log.
  Plugin file settings are file names inside the data directory, never paths.
- **Container:** a static binary in an empty (`scratch`) image: no shell, no package manager, no root. It runs
  read-only, without capabilities and as any user id.

## How it is checked

Every change runs through formatting, lints, unit and HTTP tests, coverage targets, `cargo-deny`, a secret scan,
CodeQL, container tests, Trivy, Dockle and a ZAP baseline scan; see the README and [TESTING.md](TESTING.md).
Dependencies and base images are checked weekly for new advisories and updated by Dependabot. Releases come with
SBOMs and build provenance.
