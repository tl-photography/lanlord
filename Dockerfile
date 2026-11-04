# Static musl binary on Alpine; the ssh client stays in the image because lanlord reaches the routers over ssh.
FROM rust:1.99.1-alpine3.24 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3.24
RUN apk add --no-cache openssh-client-default \
    && adduser -D -H -u 10001 lanlord
COPY --from=build /src/target/release/lanlord /usr/local/bin/lanlord
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=5m --timeout=5s --start-period=30s --start-interval=5s CMD ["lanlord", "healthcheck"]
ENTRYPOINT ["lanlord"]
