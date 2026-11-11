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
- The core decides the libraries, to keep the attack surface small. Plugins use what the core offers (SSH only through
  `src/ssh.rs`) and add no dependency. A new library is proposed in its own issue and checked first: maintenance,
  advisories, license, what it pulls in, and whether an existing one already covers it.
- New code comes with tests; network plugins are tested against a small fake server in the test. Unit tests are
  in `src/<module>/tests.rs` (`#[cfg(test)] mod tests;` at the end of the module), so they can test private code;
  HTTP tests are in `tests/`. The rules and coverage targets are in `TESTING.md`.

## Tests

- Shared helpers instead of copies: the HTTP tests use `tests/common/mod.rs` (`app`, `send`, `get`, `post`).
- Test data sets only the fields a test is about and fills the rest with `..Default::default()`.
- Several inputs of one function are one test over a table of cases, with the case in the assertion message, not
  several near-identical tests.

## Commits

- Small commits, one change each, short imperative subject in sentence case ("Add the login", "Fix ...").
- Stage files by name, never `git add -A`: other work may be in the same working copy.
- Commits are signed; the key is set in the repo's git config.
- Hooks are installed with `pre-commit install` and never skipped (no `--no-verify`, no `SKIP`).

## Pull requests

- One change per pull request, small enough to review at once; a branch from the current `main`.
- Open it with `gh pr create`, then `gh pr merge <number> --auto --squash`. `main` only takes squash merges of
  signed commits with a linear history.
- A branch that conflicts with `main` is rebased onto it, never merged with it, and pushed with
  `--force-with-lease`. After a squash merge of the base of a stacked branch: `git rebase --onto origin/main <old base>`.
- The ruleset on `main` needs the CI checks and the code scanning results of CodeQL, clippy and Trivy. A pull
  request that only changes documentation skips the jobs that produce them: start them with
  `gh workflow run ci.yml --ref <branch>`.
- CI runs only the checks a change needs, and on a later push only those its changes touch plus every one that
  failed; see `CONTRIBUTING.md`.

## Local notes

Notes for one installation (deployment, the network it manages, local tools) are in `AGENTS.local.md` and open work
in `ToDo.md`. Both are not committed.
