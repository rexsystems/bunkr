#!/usr/bin/env bash
# Build the WebAssembly client into crates/web/dist.
#   needs: rustup target add wasm32-unknown-unknown && cargo install wasm-bindgen-cli --version 0.2.130
set -euo pipefail
cd "$(dirname "$0")/.."
PROFILE=${PROFILE:-release}
OUT=crates/web/dist
EXTRA=()
# Offline toolchains without the wasm32 std can build it from source.
if [[ "${BUNKR_BUILD_STD:-0}" == "1" ]]; then
  export RUSTC_BOOTSTRAP=1
  EXTRA+=(-Zbuild-std=std,panic_abort)
fi
FLAGS=()
[[ "$PROFILE" == "release" ]] && FLAGS+=(--release)
cargo build -q -p bunkr-web --target wasm32-unknown-unknown "${FLAGS[@]}" "${EXTRA[@]}"
rm -rf "$OUT" && mkdir -p "$OUT"
DIR=$([[ "$PROFILE" == "release" ]] && echo release || echo debug)
${WASM_BINDGEN:-wasm-bindgen} --target web --no-typescript --remove-name-section --remove-producers-section --out-dir "$OUT/pkg" \
  "target/wasm32-unknown-unknown/$DIR/bunkr_web.wasm"
if command -v wasm-opt >/dev/null && [[ "$PROFILE" == "release" ]]; then
  wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
    "$OUT/pkg/bunkr_web_bg.wasm" -o "$OUT/pkg/bunkr_web_bg.wasm" || true
fi
cp -r crates/web/static/. "$OUT/"
# Precompressed copies (served automatically by the server).
find "$OUT" -type f \( -name '*.wasm' -o -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' -o -name '*.webmanifest' \) \
  -exec gzip -kf9 {} \;
if command -v brotli >/dev/null; then
  find "$OUT" -type f \( -name '*.wasm' -o -name '*.js' -o -name '*.css' -o -name '*.html' \) -exec brotli -kf {} \;
fi
du -sh "$OUT/pkg/bunkr_web_bg.wasm"
