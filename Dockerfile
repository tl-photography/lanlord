# syntax=docker/dockerfile:1
# One static binary on an empty base: no shell, no package manager, no libraries.
FROM rust:1.99.1-alpine3.24@sha256:27cd9befd4a05d6f6eb407c3e28365f5092f008bfc5946207cca76ae5179ef23 AS build
# release: thin LTO for every build; dist: full LTO for published releases.
ARG PROFILE=release
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
	cargo install cargo-auditable@0.7.7 --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml clippy.toml ./
COPY src ./src
COPY templates ./templates
COPY static ./static
COPY assets ./assets
# The registry and target stay in BuildKit caches between builds: only changed crates are compiled again.
# A cached source layer brings back old file times, so cargo would keep a binary built from other sources: touch first.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
	--mount=type=cache,target=/src/target,sharing=locked \
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
