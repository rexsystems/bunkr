//! Bunkr web client (Leptos, compiled to WebAssembly).

mod app;
mod chat;
mod engine;
mod icons;
mod net;
mod settings;
mod util;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
