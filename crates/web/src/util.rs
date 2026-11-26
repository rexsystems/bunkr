use leptos::prelude::*;
use wasm_bindgen::{JsCast, JsValue};

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

/// Disappearing-message choices, in hours (0 = off).
pub fn ttl_options() -> Vec<(i64, String)> {
    [(0, "Off"), (1, "1 hour"), (24, "1 day"), (168, "7 days"), (720, "30 days"), (2160, "90 days")]
        .into_iter()
        .map(|(h, l)| (h, l.to_string()))
        .collect()
}

/// Custom select: a trigger button and a listbox popover.
/// With `icon`, the trigger is an icon button (menu opens to the left);
/// otherwise it looks like a form field and shows the current label.
#[component]
pub fn Dropdown(
    options: Vec<(i64, String)>,
    #[prop(into)] value: Signal<i64>,
    #[prop(into)] on_pick: Callback<i64>,
    label: &'static str,
    #[prop(optional)] icon: Option<&'static str>,
) -> impl IntoView {
    let open = RwSignal::new(false);
    let trigger: NodeRef<leptos::html::Button> = NodeRef::new();
    let items: Vec<NodeRef<leptos::html::Button>> = options.iter().map(|_| NodeRef::new()).collect();
    let n = options.len();
    let focus = {
        let items = items.clone();
        move |i: usize| {
            if let Some(b) = items.get(i).and_then(|r| r.get_untracked()) {
                let _ = b.focus();
            }
        }
    };
    let current = {
        let options = options.clone();
        move || {
            let v = value.get();
            options.iter().find(|(k, _)| *k == v).map(|(_, l)| l.clone()).unwrap_or_default()
        }
    };
    let close = move |refocus: bool| {
        open.set(false);
        if refocus {
            if let Some(t) = trigger.get_untracked() {
                let _ = t.focus();
            }
        }
    };
    let opts = options.clone();
    let open_menu = {
        let focus = focus.clone();
        move || {
            open.set(true);
            let sel = opts.iter().position(|(k, _)| *k == value.get_untracked()).unwrap_or(0);
            let focus = focus.clone();
            request_animation_frame(move || focus(sel));
        }
    };
    let on_trigger_key = {
        let open_menu = open_menu.clone();
        move |e: leptos::ev::KeyboardEvent| {
            if matches!(e.key().as_str(), "ArrowDown" | "ArrowUp") {
                e.prevent_default();
                open_menu();
            }
        }
    };
    let on_menu_key = {
        let focus = focus.clone();
        let items = items.clone();
        move |e: leptos::ev::KeyboardEvent| {
            let doc_active = web_sys::window().and_then(|w| w.document()).and_then(|d| d.active_element());
            let cur = items.iter().position(|r| {
                r.get_untracked()
                    .map(|b| doc_active.as_ref().map(|a| a == b.unchecked_ref::<web_sys::Element>()).unwrap_or(false))
                    .unwrap_or(false)
            });
            match e.key().as_str() {
                "ArrowDown" => { e.prevent_default(); focus(cur.map(|i| (i + 1) % n).unwrap_or(0)); }
                "ArrowUp" => { e.prevent_default(); focus(cur.map(|i| (i + n - 1) % n).unwrap_or(0)); }
                "Home" => { e.prevent_default(); focus(0); }
                "End" => { e.prevent_default(); focus(n - 1); }
                "Escape" => { e.prevent_default(); e.stop_propagation(); close(true); }
                "Tab" => close(false),
                _ => {}
            }
        }
    };
    let rows = options
        .into_iter()
        .zip(items)
        .map(|((k, l), r)| {
            view! {
                <li role="presentation">
                    <button
                        type="button"
                        role="option"
                        class="dd-item"
                        node_ref=r
                        aria-selected=move || (value.get() == k).to_string()
                        on:click=move |_| { on_pick.run(k); close(true); }
                    >
                        <span class="grow">{l}</span>
                        <Show when=move || value.get() == k>
                            <Icon svg=crate::icons::TICK size=16/>
                        </Show>
                    </button>
                </li>
            }
        })
        .collect_view();
    view! {
        <div class="dd" class:dd-icon=icon.is_some()>
            <button
                type="button"
                node_ref=trigger
                class=if icon.is_some() { "dd-trigger icon-btn" } else { "dd-trigger input" }
                class:active=move || open.get()
                aria-haspopup="listbox"
                aria-expanded=move || open.get().to_string()
                aria-label=label
                title=label
                on:click=move |_| if open.get_untracked() { close(false) } else { open_menu() }
                on:keydown=on_trigger_key
            >
                {match icon {
                    Some(svg) => view! { <Icon svg size=18/> }.into_any(),
                    None => view! {
                        <span class="grow">{current}</span>
                        <Icon svg=crate::icons::ARROW_DOWN size=16 class="dd-chev"/>
                    }.into_any(),
                }}
            </button>
            <Show when=move || open.get()>
                <div class="dd-scrim" on:click=move |_| close(false)></div>
            </Show>
            <ul class="dd-menu" role="listbox" aria-label=label class:open=move || open.get() on:keydown=on_menu_key.clone()>
                {icon.is_some().then(|| view! { <li class="dd-title" role="presentation">{label}</li> })}
                {rows}
            </ul>
        </div>
    }
}

/// Bunker glyph on a 12x12 pixel grid: dome, embrasure slit, base.
/// Keep in sync with static/icon.svg.
pub const LOGO_PIXELS: &str =
    "M4 3h4v1H4zM2 4h8v1H2zM1 5h10v1H1zM1 6h2v1H1zM9 6h2v1H9zM0 7h12v2H0z";

#[component]
pub fn Logo(#[prop(default = 24)] size: u32) -> impl IntoView {
    view! {
        <svg
            class="icon"
            width=size
            height=size
            viewBox="0 0 12 12"
            shape-rendering="crispEdges"
            aria-hidden="true"
        >
            <path d=LOGO_PIXELS fill="currentColor"/>
        </svg>
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
