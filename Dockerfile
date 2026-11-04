# Static musl binary on Alpine; the ssh client stays in the image because lanlord reaches the routers over ssh.
FROM rust:1.99.1-alpine3.24@sha256:27cd9befd4a05d6f6eb407c3e28365f5092f008bfc5946207cca76ae5179ef23 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# Without the package manager nothing can be installed in a running container.
RUN apk add --no-cache openssh-client-default \
    && apk del --no-cache apk-tools \
    && rm -rf /etc/apk /lib/apk /var/cache/apk \
    && adduser -D -H -u 10001 lanlord
COPY --from=build /src/target/release/lanlord /usr/local/bin/lanlord
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=5m --timeout=5s --start-period=30s --start-interval=5s CMD ["lanlord", "healthcheck"]
ENTRYPOINT ["lanlord"]
