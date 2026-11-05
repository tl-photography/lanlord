# Agent notes

Working rules for lanlord. The project will be published: nothing in the repo describes one particular network.

## Repository

- `README.md` describes what lanlord is and how to install, configure and use it. No status, no dates, no plans,
  no "not yet". Open work goes into the local `ToDo.md`, which is not committed.
- Examples use documentation addresses (`192.0.2.0/24`) and generic names (`router.lan`), never real devices.
- `TESTING.md` is the test plan: levels, coverage measures and targets. CI enforces the targets; they are only raised.

## Code

- Rust, toolchain pinned in `rust-toolchain.toml`. `cargo fmt`, `cargo clippy --all-targets -- -D warnings` with the
  pedantic lints from `Cargo.toml`, `cargo test`. Coverage with `cargo llvm-cov`, `src/main.rs` excluded (covered by
  `tests/container.sh`).
- Pages are askama templates. No inline scripts or styles: the Content Security Policy forbids them. JavaScript only
  improves pages that work without it.
- Every request that changes data passes the origin check (`src/origin.rs`) and the login (`src/auth.rs`).
- Plugins describe their settings in their `PluginType` (`src/plugins/`); the web interface and the validation are
  generic. File settings are file names in the data directory, never paths. A broken plugin entry is left out and
  shown, it never stops lanlord.
- Secrets (passwords) live in `0600` files in the data directory, never in `lanlord.toml` or the log.
- New code comes with tests; network plugins are tested against a small fake server in the test.

## Commits

- Small commits, one change each, short imperative subject in sentence case ("Add the login", "Fix ...").
- Stage files by name, never `git add -A`: other work may be in the same working copy.
- Commits are signed; the key is set in the repo's git config.
