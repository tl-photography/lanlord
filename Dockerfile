# One static binary on an empty base: no shell, no package manager, no libraries.
FROM rust:1.99.1-alpine3.24@sha256:27cd9befd4a05d6f6eb407c3e28365f5092f008bfc5946207cca76ae5179ef23 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/lanlord /lanlord
# Any other uid:gid works too (--user), lanlord needs no passwd entry.
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=5m --timeout=5s --start-period=30s --start-interval=5s CMD ["/lanlord", "healthcheck"]
ENTRYPOINT ["/lanlord"]
