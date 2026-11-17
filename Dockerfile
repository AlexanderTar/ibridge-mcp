# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# The hosted ibridge server. Build: docker build -t ibridge:test .
# Run:   docker run --rm -p 8080:8080 -v ibridge-data:/data ibridge:test \
#          serve --hosted --http 0.0.0.0:8080 --public-url https://ibridge.example --data-dir /data
# See docs/self-host.md.

ARG RUST_VERSION=1.100.0

FROM rust:${RUST_VERSION}-bookworm AS chef
RUN cargo install --locked cargo-chef
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --features hosted -p ibridge --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --features hosted -p ibridge \
    && mkdir /data-seed

# The debug variant adds a busybox shell, so `railway ssh` and `docker exec` work
# and `ibridge admin` can be run on the host.
FROM gcr.io/distroless/cc-debian12:debug-nonroot
COPY --from=builder /src/target/release/ibridge /usr/local/bin/ibridge
# 65532 is the image's nonroot user. The volume starts out owned by it.
COPY --from=builder --chown=65532:65532 /data-seed /data
USER nonroot
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ibridge"]
CMD ["--help"]
