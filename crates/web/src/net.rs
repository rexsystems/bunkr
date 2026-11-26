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

fn tauri_invoke(cmd: &str, args: &JsValue) -> Option<js_sys::Promise> {
    let w = web_sys::window()?;
    let internals = js_sys::Reflect::get(&w, &"__TAURI_INTERNALS__".into()).ok()?;
    let invoke: js_sys::Function = js_sys::Reflect::get(&internals, &"invoke".into())
        .ok()?
        .dyn_into()
        .ok()?;
    invoke
        .call2(&internals, &cmd.into(), args)
        .ok()?
        .dyn_into()
        .ok()
}

/// Open an external https link (system browser in the desktop app).
pub fn open_external(url: &str) {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return;
    }
    if is_desktop() {
        let args = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&args, &"url".into(), &url.into());
        let _ = tauri_invoke("plugin:opener|open_url", &args);
    } else if let Some(w) = web_sys::window() {
        let _ = w.open_with_url_and_target_and_features(url, "_blank", "noopener,noreferrer");
    }
}

/// In the desktop shell, route every external link to the system browser.
pub fn install_link_handler() {
    if !is_desktop() {
        return;
    }
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |e: web_sys::Event| {
        let mut node = e
            .target()
            .and_then(|t| t.dyn_into::<web_sys::Element>().ok());
        while let Some(el) = node {
            if el.tag_name().eq_ignore_ascii_case("a") {
                if let Some(href) = el.get_attribute("href") {
                    if href.starts_with("http://") || href.starts_with("https://") {
                        e.prevent_default();
                        open_external(&href);
                    }
                }
                return;
            }
            node = el.parent_element();
        }
    });
    let _ =
        doc.add_event_listener_with_callback_and_bool("click", cb.as_ref().unchecked_ref(), true);
    cb.forget();
}

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const UPDATE_REPO: &str = match option_env!("BUNKR_UPDATE_REPO") {
    Some(r) => r,
    None => "rexsystems/bunkr",
};

fn parse_ver(v: &str) -> (u32, u32, u32) {
    let mut it = v
        .trim_start_matches('v')
        .split(['.', '-'])
        .map(|x| x.parse().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// Desktop only: the newest release tag on GitHub, if newer than this build.
pub async fn check_update() -> Option<(String, String)> {
    if !is_desktop() {
        return None;
    }
    let url = format!("https://api.github.com/repos/{UPDATE_REPO}/releases/latest");
    let opts = RequestInit::new();
    opts.set_method("GET");
    let req = Request::new_with_str_and_init(&url, &opts).ok()?;
    let resp: Response = JsFuture::from(web_sys::window()?.fetch_with_request(&req))
        .await
        .ok()?
        .dyn_into()
        .ok()?;
    if !resp.ok() {
        return None;
    }
    let json = JsFuture::from(resp.json().ok()?).await.ok()?;
    let tag = js_sys::Reflect::get(&json, &"tag_name".into())
        .ok()?
        .as_string()?;
    let page = js_sys::Reflect::get(&json, &"html_url".into())
        .ok()?
        .as_string()?;
    (parse_ver(&tag) > parse_ver(APP_VERSION)).then_some((tag, page))
}
