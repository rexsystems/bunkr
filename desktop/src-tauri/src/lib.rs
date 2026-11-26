//! Bunkr app shell (desktop + Android): a thin native wrapper around the same
//! Rust/WASM client. All crypto happens inside the client; the shell only
//! adds native notifications, opening links in the system browser, and
//! microphone/camera access for calls.

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            #[cfg(target_os = "linux")]
            if let Some(w) = app.get_webview_window("main") {
                // WebKitGTK keeps WebRTC + getUserMedia off by default.
                let _ = w.with_webview(|wv| {
                    use webkit2gtk::glib::prelude::ObjectExt;
                    use webkit2gtk::{PermissionRequestExt, SettingsExt, WebViewExt};
                    let view = wv.inner();
                    if let Some(s) = WebViewExt::settings(&view) {
                        s.set_enable_media_stream(true);
                        s.set_enable_webrtc(true);
                        s.set_enable_mediasource(true);
                    }
                    // Only our own bundled page runs here; grant mic/camera
                    // when the user starts a call from it.
                    view.connect_permission_request(|_, req| {
                        if req.is::<webkit2gtk::UserMediaPermissionRequest>() {
                            req.allow();
                            return true;
                        }
                        false
                    });
                });
            }
            let _ = app;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Bunkr");
}
