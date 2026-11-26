# syntax=docker/dockerfile:1
# Bunkr: one image = Rust server + Rust/WASM web client.

FROM rust:1-bookworm AS build
ARG WASM_BINDGEN_VERSION=0.2.130
RUN rustup target add wasm32-unknown-unknown \
 && arch="$(uname -m)" \
 && curl -fsSL "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-${arch}-unknown-linux-musl.tar.gz" \
    | tar xz -C /tmp \
 && mv /tmp/wasm-bindgen-*/wasm-bindgen /usr/local/bin/ \
 && apt-get update && apt-get install -y --no-install-recommends brotli && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    ./scripts/build-web.sh \
 && cargo build --release --locked -p bunkr-server \
 && cp target/release/bunkr-server /bunkr-server \
 && mkdir -p /data-empty

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /bunkr-server /app/bunkr-server
COPY --from=build /src/crates/web/dist /app/web
COPY --from=build --chown=65532:65532 /data-empty /data
ENV BUNKR_DATA=/data \
    BUNKR_WEB_DIR=/app/web \
    BUNKR_BIND=0.0.0.0:8080
VOLUME ["/data"]
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/app/bunkr-server"]
