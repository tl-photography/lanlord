# syntax=docker/dockerfile:1
# One static binary on an empty base: no shell, no package manager, no libraries.
FROM rust:1.99.1-alpine3.24@sha256:27cd9befd4a05d6f6eb407c3e28365f5092f008bfc5946207cca76ae5179ef23 AS chef
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
	cargo install cargo-auditable@0.7.7 cargo-chef@0.1.78 --locked
WORKDIR /src

# The recipe holds only the dependencies, so their layer below stays cached until Cargo.toml or Cargo.lock change.
FROM chef AS plan
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
# release: thin LTO for every build; dist: full LTO for published releases.
ARG PROFILE=release
COPY --from=plan /src/recipe.json recipe.json
COPY rust-toolchain.toml ./
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
	cargo chef cook --profile "${PROFILE}" --locked --recipe-path recipe.json
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml clippy.toml ./
COPY src ./src
COPY templates ./templates
COPY static ./static
COPY assets ./assets
# A cached source layer brings back old file times, so cargo would keep a binary built from other sources: touch first.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
	touch src/main.rs src/lib.rs \
	&& cargo auditable build --profile "${PROFILE}" --locked \
	&& cp "target/${PROFILE}/lanlord" /lanlord

FROM scratch
COPY --from=build /lanlord /lanlord
# Any other uid:gid works too (--user), lanlord needs no passwd entry.
USER 10001:10001
ENV LANLORD_DATA=/data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=5m --timeout=5s --start-period=30s --start-interval=5s CMD ["/lanlord", "healthcheck"]
ENTRYPOINT ["/lanlord"]
