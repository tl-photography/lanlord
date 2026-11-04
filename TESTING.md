# Testing

How lanlord is tested and which coverage it must reach. Terms follow ISO/IEC/IEEE 29119-4 (test techniques and
coverage measures).

## Test levels

| Level       | What                                                          | Where                                   |
| ----------- | ------------------------------------------------------------- | --------------------------------------- |
| Static      | formatting, lints, Dockerfile, workflows, shell scripts        | `rustfmt`, `clippy`, hadolint, actionlint, shellcheck |
| Unit        | one module at a time: validation, comparison, origin check     | `#[cfg(test)]` in `src/`                |
| Integration | the web interface through the router, without a network socket | `tests/*.rs`                            |
| System      | the built image as it runs on a server                         | `tests/container.sh`, ZAP baseline scan |
| Security    | dependencies, image, Dockerfile, secrets                       | cargo-deny, Trivy, Dockle, TruffleHog   |

## Coverage

Measured with `cargo llvm-cov` over the unit and integration tests.

| Measure                                | Target | Notes                                                                    |
| -------------------------------------- | ------ | ------------------------------------------------------------------------ |
| Statement coverage (as line coverage)  | 90 %   | lines of the library code                                                |
| Region coverage                        | 90 %   | LLVM code regions, including the outcomes of each condition              |
| Branch coverage (decision outcomes)    | -      | not measured: branch instrumentation is only available on nightly Rust   |

CI fails below a target. Targets are only raised, never lowered.

`src/main.rs` is excluded from the measurement: process start, signal handling and the health check run in the
system tests (`tests/container.sh`), not in `cargo test`.

## Rules

- New code comes with tests on the lowest level that can check it.
- Every bug fix comes with a test that fails without the fix.
- Inputs from users and from the network are tested with invalid values too: wrong formats, duplicates, limits,
  markup that must be escaped.

## Running the tests

```sh
cargo test --locked
cargo llvm-cov --locked --ignore-filename-regex 'src/main\.rs' --fail-under-lines 90 --fail-under-regions 90
docker build -t lanlord:local . && tests/container.sh lanlord:local
```
