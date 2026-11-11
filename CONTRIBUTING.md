# Contributing

Issues and pull requests are welcome. For larger changes, open an issue first, so the idea can be discussed before
the work starts. Each pull request should do one thing; small ones are reviewed faster.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Plugins use the libraries the core already has and add no dependency of their own, to keep the attack surface
small. A new library is proposed in its own issue first: what it is needed for, why no existing one covers it, its
maintenance, advisories, license and what it pulls in.

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

## Running from source

```sh
cargo run --release
```

The toolchain version is pinned in [rust-toolchain.toml](rust-toolchain.toml), rustup installs it on the first build.
