use leptos::prelude::*;
use wasm_bindgen::JsValue;

/// Inline Hugeicon.
#[component]
pub fn Icon(
    svg: &'static str,
    #[prop(default = 20)] size: u32,
    #[prop(optional)] class: &'static str,
) -> impl IntoView {
    view! {
        <svg
            class=format!("icon {class}")
            width=size
            height=size
            viewBox="0 0 24 24"
            fill="none"
            aria-hidden="true"
            inner_html=svg
        ></svg>
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
#[allow(dead_code)]
pub enum ToastKind {
    Info,
    Error,
    Ok,
}

#[derive(Clone, Debug)]
pub struct Toast {
    pub id: u64,
    pub text: String,
    pub kind: ToastKind,
}

#[derive(Clone, Copy)]
pub struct Toasts(pub RwSignal<Vec<Toast>>);

impl Toasts {
    pub fn push(&self, kind: ToastKind, text: impl Into<String>) {
        let id = (js_sys::Math::random() * 1e12) as u64;
        let sig = self.0;
        sig.update(|v| {
            v.push(Toast {
                id,
                text: text.into(),
                kind,
            });
            if v.len() > 4 {
                v.remove(0);
            }
        });
        leptos::task::spawn_local(async move {
            crate::net::sleep(4500).await;
            sig.update(|v| v.retain(|t| t.id != id));
        });
    }
    pub fn err(&self, t: impl Into<String>) {
        self.push(ToastKind::Error, t)
    }
    pub fn ok(&self, t: impl Into<String>) {
        self.push(ToastKind::Ok, t)
    }
}

pub fn toasts() -> Toasts {
    expect_context::<Toasts>()
}

#[component]
pub fn ToastHost() -> impl IntoView {
    let t = toasts();
    view! {
        <div class="toasts" role="status" aria-live="polite">
            <For each=move || t.0.get() key=|x| x.id let:x>
                <div class=move || {
                    format!(
                        "toast {}",
                        match x.kind {
                            ToastKind::Error => "toast-err",
                            ToastKind::Ok => "toast-ok",
                            ToastKind::Info => "",
                        },
                    )
                }>
                    <Icon
                        svg=match x.kind {
                            ToastKind::Error => crate::icons::ALERT,
                            ToastKind::Ok => crate::icons::TICK,
                            ToastKind::Info => crate::icons::INFO,
                        }
                        size=18
                    />
                    <span>{x.text.clone()}</span>
                </div>
            </For>
        </div>
    }
}

fn date(ms: i64) -> js_sys::Date {
    js_sys::Date::new(&JsValue::from_f64(ms as f64))
}

pub fn fmt_time(ms: i64) -> String {
    let d = date(ms);
    format!("{:02}:{:02}", d.get_hours(), d.get_minutes())
}

pub fn day_key(ms: i64) -> (u32, u32, u32) {
    let d = date(ms);
    (d.get_full_year(), d.get_month(), d.get_date())
}

pub fn fmt_day(ms: i64) -> String {
    let now = crate::net::now_ms();
    if day_key(ms) == day_key(now) {
        return "Today".into();
    }
    if day_key(ms) == day_key(now - 86_400_000) {
        return "Yesterday".into();
    }
    const M: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let d = date(ms);
    format!(
        "{} {} {}",
        d.get_date(),
        M[d.get_month() as usize % 12],
        d.get_full_year()
    )
}

pub fn hue(name: &str) -> u32 {
    let mut h: u32 = 2166136261;
    for b in name.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h % 360
}

#[component]
pub fn Avatar(name: String, #[prop(default = 36)] size: u32) -> impl IntoView {
    let initials: String = name.chars().take(2).collect::<String>().to_uppercase();
    let h = hue(&name);
    view! {
        <div
            class="avatar"
            style=format!(
                "width:{size}px;height:{size}px;font-size:{}px;--h:{h}",
                size * 38 / 100,
            )
        >
            {initials}
        </div>
    }
}

pub fn ttl_label(hours: i64) -> Option<String> {
    match hours {
        0 => None,
        h if h < 24 => Some(format!("{h}h")),
        h if h % 24 == 0 => Some(format!("{}d", h / 24)),
        h => Some(format!("{h}h")),
    }
}
