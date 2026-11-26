//! Notifications: in-page (Notification API / Tauri plugin) while the app is
//! open, and contentless Web Push while it is closed.

use std::cell::RefCell;

use bunkr_proto::ChannelId;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;

use crate::net;

pub const PREF_KEY: &str = "bunkr.notify"; // all | important | off
pub const PREVIEW_KEY: &str = "bunkr.previews"; // 1 | 0
pub const PUSH_KEY: &str = "bunkr.push"; // all | dm | off

thread_local! {
    static ON_CLICK: RefCell<Option<Box<dyn Fn(ChannelId)>>> = const { RefCell::new(None) };
}

pub fn set_on_click(f: impl Fn(ChannelId) + 'static) {
    ON_CLICK.with(|c| *c.borrow_mut() = Some(Box::new(f)));
}

pub fn pref() -> String {
    net::store_get(PREF_KEY).unwrap_or_else(|| "important".into())
}

pub fn previews() -> bool {
    net::store_get(PREVIEW_KEY).as_deref() == Some("1")
}

pub fn page_visible() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .map(|d| {
            d.visibility_state() == web_sys::VisibilityState::Visible
                && d.has_focus().unwrap_or(true)
        })
        .unwrap_or(true)
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

pub fn permission() -> String {
    if net::is_desktop() {
        return net::store_get("bunkr.tauri_notify").unwrap_or_else(|| "default".into());
    }
    match web_sys::Notification::permission() {
        web_sys::NotificationPermission::Granted => "granted",
        web_sys::NotificationPermission::Denied => "denied",
        _ => "default",
    }
    .into()
}

pub async fn request_permission() -> String {
    if net::is_desktop() {
        let r = match tauri_invoke(
            "plugin:notification|request_permission",
            &JsValue::UNDEFINED,
        ) {
            Some(p) => JsFuture::from(p).await.ok().and_then(|v| v.as_string()),
            None => None,
        };
        let r = r.unwrap_or_else(|| "denied".into());
        net::store_set("bunkr.tauri_notify", &r);
        return r;
    }
    match web_sys::Notification::request_permission() {
        Ok(p) => JsFuture::from(p)
            .await
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_else(|| "denied".into()),
        Err(_) => "denied".into(),
    }
}

fn show(title: &str, body: &str, cid: ChannelId) {
    if net::is_desktop() {
        let opts = js_sys::Object::new();
        let inner = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&inner, &"title".into(), &title.into());
        let _ = js_sys::Reflect::set(&inner, &"body".into(), &body.into());
        let _ = js_sys::Reflect::set(&opts, &"options".into(), &inner);
        let _ = tauri_invoke("plugin:notification|notify", &opts);
        return;
    }
    let opts = web_sys::NotificationOptions::new();
    opts.set_body(body);
    opts.set_tag(&format!("bunkr-{cid}"));
    opts.set_icon("icon-192.png");
    if let Ok(n) = web_sys::Notification::new_with_options(title, &opts) {
        let cb = Closure::<dyn FnMut()>::new(move || {
            if let Some(w) = web_sys::window() {
                let _ = w.focus();
            }
            ON_CLICK.with(|c| {
                if let Some(f) = c.borrow().as_ref() {
                    f(cid)
                }
            });
        });
        n.set_onclick(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }
}

/// A new message arrived somewhere the user isn't looking.
pub fn message(place: &str, text: &str, important: bool, count: usize, cid: ChannelId) {
    let p = pref();
    if p == "off" || (p == "important" && !important) || permission() != "granted" {
        return;
    }
    let body = if previews() {
        text.chars().take(140).collect()
    } else if count > 1 {
        format!("{count} new encrypted messages")
    } else {
        "New encrypted message".to_string()
    };
    show(&format!("Bunkr · {place}"), &body, cid);
}

// ---------------- web push ----------------

pub fn push_supported() -> bool {
    if net::is_desktop() {
        return false;
    }
    let Some(w) = web_sys::window() else {
        return false;
    };
    js_sys::Reflect::has(&w.navigator(), &"serviceWorker".into()).unwrap_or(false)
        && js_sys::Reflect::has(&w, &"PushManager".into()).unwrap_or(false)
}

async fn registration() -> Result<web_sys::ServiceWorkerRegistration, String> {
    let w = web_sys::window().ok_or("no window")?;
    let sw = w.navigator().service_worker();
    let reg = JsFuture::from(sw.register("sw.js"))
        .await
        .map_err(|_| "Service worker unavailable (HTTPS required)".to_string())?;
    let _ = JsFuture::from(sw.ready().map_err(|_| "no sw")?).await;
    reg.dyn_into().map_err(|_| "bad registration".to_string())
}

fn b64url_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .unwrap_or_default()
}

/// Subscribe this browser; returns the endpoint to register on the server.
pub async fn push_subscribe(vapid_b64: &str) -> Result<String, String> {
    let reg = registration().await?;
    let pm = reg.push_manager().map_err(|_| "Push not supported")?;
    let key = js_sys::Uint8Array::from(b64url_decode(vapid_b64).as_slice());
    let opts = web_sys::PushSubscriptionOptionsInit::new();
    opts.set_user_visible_only(true);
    opts.set_application_server_key(&key.into());
    let sub = JsFuture::from(
        pm.subscribe_with_options(&opts)
            .map_err(|_| "subscribe failed")?,
    )
    .await
    .map_err(|_| "Push permission denied".to_string())?;
    let sub: web_sys::PushSubscription = sub.dyn_into().map_err(|_| "bad subscription")?;
    Ok(sub.endpoint())
}

pub async fn push_unsubscribe() {
    if let Ok(reg) = registration().await {
        if let Ok(pm) = reg.push_manager() {
            if let Ok(p) = pm.get_subscription() {
                if let Ok(sub) = JsFuture::from(p).await {
                    if let Ok(sub) = sub.dyn_into::<web_sys::PushSubscription>() {
                        if let Ok(p) = sub.unsubscribe() {
                            let _ = JsFuture::from(p).await;
                        }
                    }
                }
            }
        }
    }
}
