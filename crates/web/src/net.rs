//! Browser HTTP + WebSocket glue.

use std::{cell::RefCell, rc::Rc};

use bunkr_core::Http;
use js_sys::Uint8Array;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response};

#[derive(Clone)]
pub struct WebHttp {
    pub base: Rc<String>,
    token: Rc<RefCell<Option<String>>>,
}

impl WebHttp {
    pub fn new(base: &str) -> Self {
        WebHttp {
            base: Rc::new(base.trim_end_matches('/').to_string()),
            token: Rc::new(RefCell::new(None)),
        }
    }

    pub fn ws_url(&self) -> String {
        let base = if self.base.is_empty() {
            let loc = web_sys::window().unwrap().location();
            format!(
                "{}//{}",
                loc.protocol().unwrap_or_default(),
                loc.host().unwrap_or_default()
            )
        } else {
            self.base.to_string()
        };
        let ws = if let Some(rest) = base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            base
        };
        format!("{ws}/api/ws")
    }

    pub fn token(&self) -> Option<String> {
        self.token.borrow().clone()
    }
}

impl Http for WebHttp {
    fn set_token(&self, token: Option<String>) {
        *self.token.borrow_mut() = token;
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), String> {
        let opts = RequestInit::new();
        opts.set_method(method);
        let headers = web_sys::Headers::new().map_err(js_err)?;
        if let Some(t) = self.token.borrow().as_ref() {
            headers
                .set("authorization", &format!("Bearer {t}"))
                .map_err(js_err)?;
        }
        if let Some(b) = &body {
            headers
                .set("content-type", "application/json")
                .map_err(js_err)?;
            let arr = Uint8Array::from(b.as_slice());
            opts.set_body(&arr.into());
        }
        opts.set_headers(&headers.into());
        opts.set_cache(web_sys::RequestCache::NoStore);
        let req = Request::new_with_str_and_init(&format!("{}{}", self.base, path), &opts)
            .map_err(js_err)?;
        let win = web_sys::window().ok_or("no window")?;
        let resp: Response = JsFuture::from(win.fetch_with_request(&req))
            .await
            .map_err(|_| "Can't reach the server".to_string())?
            .dyn_into()
            .map_err(js_err)?;
        let status = resp.status();
        let buf = JsFuture::from(resp.array_buffer().map_err(js_err)?)
            .await
            .map_err(js_err)?;
        Ok((status, Uint8Array::new(&buf).to_vec()))
    }
}

fn js_err(e: JsValue) -> String {
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

/// Await `ms` milliseconds.
pub async fn sleep(ms: i32) {
    let p = js_sys::Promise::new(&mut |resolve, _| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms)
            .unwrap();
    });
    let _ = JsFuture::from(p).await;
}

pub fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

// ---------- local storage ----------

pub fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

pub fn store_get(k: &str) -> Option<String> {
    storage()?.get_item(k).ok()?
}

pub fn store_set(k: &str, v: &str) {
    if let Some(s) = storage() {
        let _ = s.set_item(k, v);
    }
}

pub fn store_del(k: &str) {
    if let Some(s) = storage() {
        let _ = s.remove_item(k);
    }
}

pub const VAULT_KEY: &str = "bunkr.vault";
pub const SERVER_KEY: &str = "bunkr.server";

/// Running inside the Tauri desktop shell (no same-origin server).
pub fn is_desktop() -> bool {
    let Some(w) = web_sys::window() else {
        return false;
    };
    js_sys::Reflect::has(&w, &JsValue::from_str("__TAURI_INTERNALS__")).unwrap_or(false)
}

/// Server base URL: same origin on the web, configurable in the desktop app.
pub fn server_base() -> String {
    if is_desktop() {
        store_get(SERVER_KEY).unwrap_or_default()
    } else {
        String::new()
    }
}

pub fn copy_to_clipboard(text: &str) {
    if let Some(w) = web_sys::window() {
        let _ = w.navigator().clipboard().write_text(text);
    }
}
