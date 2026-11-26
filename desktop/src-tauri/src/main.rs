//! Bunkr desktop: a thin native shell around the same Rust/WASM client.
//! All crypto still happens inside the client; the shell adds no network
//! access of its own and exposes no commands to the page.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Bunkr");
}
