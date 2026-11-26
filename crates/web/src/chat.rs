use std::collections::HashMap;

use bunkr_core::{device::FileRef, Device, MsgBody};
use bunkr_proto::{ChannelId, UserId};
use futures::channel::oneshot;
use leptos::prelude::*;
use leptos::task::spawn_local;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::app::ctx;
use crate::call::{self, calls, CallUi, Calls};
use crate::engine::{ChanView, Cmd, EngineHandle, MsgView, Outgoing, CALL_SINK};
use crate::icons as ic;
use crate::net;
use crate::util::{fmt_day, fmt_time, toasts, ttl_label, Avatar, Icon};

pub const QUICK_EMOJI: [&str; 8] = ["👍", "❤️", "😂", "🔥", "😮", "😢", "🙏", "🎉"];

#[derive(Clone, Debug, PartialEq)]
pub struct ReplyTo {
    pub id: String,
    pub username: String,
    pub snippet: String,
}

#[derive(Clone, Copy)]
pub struct View {
    pub selected: RwSignal<Option<ChannelId>>,
    pub drawer: RwSignal<bool>,
    pub members: RwSignal<bool>,
    pub settings: RwSignal<bool>,
    pub search: RwSignal<bool>,
    pub dm_picker: RwSignal<bool>,
    pub seen: RwSignal<HashMap<ChannelId, i64>>,
    pub reply: RwSignal<Option<ReplyTo>>,
    pub editing: RwSignal<Option<(String, String)>>,
    pub highlight: RwSignal<Option<String>>,
    pub handle: StoredValue<EngineHandle>,
}

pub fn view_ctx() -> View {
    expect_context::<View>()
}

impl View {
    pub fn open_dm(&self, user: UserId) {
        let (tx, rx) = oneshot::channel();
        self.handle.get_value().send(Cmd::OpenDm(user, tx));
        let v = *self;
        let t = toasts();
        spawn_local(async move {
            match rx.await {
                Ok(Ok(cid)) => {
                    v.selected.set(Some(cid));
                    v.drawer.set(false);
                    v.members.set(false);
                }
                Ok(Err(e)) => t.err(e),
                Err(_) => {}
            }
        });
    }
}

#[component]
pub fn MainView(handle: EngineHandle) -> impl IntoView {
    let c = ctx();
    let v = View {
        selected: c.live.selected,
        drawer: RwSignal::new(false),
        members: RwSignal::new(false),
        settings: RwSignal::new(false),
        search: RwSignal::new(false),
        dm_picker: RwSignal::new(false),
        seen: RwSignal::new(HashMap::new()),
        reply: RwSignal::new(None),
        editing: RwSignal::new(None),
        highlight: RwSignal::new(None),
        handle: StoredValue::new(handle),
    };
    provide_context(v);
    let cu = Calls(RwSignal::new(CallUi::default()));
    provide_context(cu);
    let sig = cu.0;
    CALL_SINK.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |cid, u, d, trusted, e| {
            call::on_signal(cid, u, d, trusted, e, sig)
        }))
    });
    crate::notify::set_on_click(move |cid| v.selected.set(Some(cid)));
    on_cleanup(move || {
        call::leave(sig);
        CALL_SINK.with(|s| *s.borrow_mut() = None);
    });

    // Pick the first channel once channels arrive.
    Effect::new(move |_| {
        let ui = c.ui.get();
        let sel = v.selected.get_untracked();
        if sel.map(|s| ui.chan(s).is_none()).unwrap_or(true) {
            v.selected.set(
                ui.channels
                    .iter()
                    .find(|c| !c.dm)
                    .or(ui.channels.first())
                    .map(|c| c.id),
            );
        }
    });
    // Reset reply/edit when switching conversations.
    Effect::new(move |prev: Option<Option<ChannelId>>| {
        let sel = v.selected.get();
        if prev.flatten() != sel {
            v.reply.set(None);
            v.editing.set(None);
        }
        sel
    });
    // Mark the open channel as read.
    Effect::new(move |_| {
        let ui = c.ui.get();
        if let Some(sel) = v.selected.get() {
            let last = ui
                .messages
                .get(&sel)
                .and_then(|m| m.last())
                .map(|m| m.seq)
                .unwrap_or(0);
            v.seen.update(|s| {
                s.insert(sel, last);
            });
        }
    });
    // Keyboard: Ctrl/Cmd+K search, Esc closes things.
    let keys = window_event_listener(leptos::ev::keydown, move |e| {
        if (e.ctrl_key() || e.meta_key()) && e.key().eq_ignore_ascii_case("k") {
            e.prevent_default();
            v.search.set(true);
        } else if e.key() == "Escape" {
            v.search.set(false);
            v.dm_picker.set(false);
            v.reply.set(None);
            v.editing.set(None);
        }
    });
    on_cleanup(move || keys.remove());

    view! {
        <div class="shell" class:drawer-open=move || v.drawer.get()>
            <div class="scrim" on:click=move |_| { v.drawer.set(false); v.members.set(false); }></div>
            <Sidebar/>
            <ChatPane/>
            <Show when=move || v.members.get()>
                <MembersPanel/>
            </Show>
            <Show when=move || v.settings.get()>
                <crate::settings::Settings/>
            </Show>
            <Show when=move || v.search.get()>
                <SearchModal/>
            </Show>
            <Show when=move || v.dm_picker.get()>
                <DmPicker/>
            </Show>
        </div>
    }
}

fn unread_count(ui: &crate::engine::Ui, seen: &HashMap<ChannelId, i64>, id: ChannelId) -> usize {
    let seen = seen.get(&id).copied().unwrap_or(0);
    ui.messages
        .get(&id)
        .map(|m| {
            m.iter()
                .filter(|m| m.seq > seen && !m.mine && matches!(m.body, MsgBody::Text(_)))
                .count()
        })
        .unwrap_or(0)
}

#[component]
fn ChannelItem(ch: ChanView) -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let cu = calls();
    let id = ch.id;
    let unread = move || unread_count(&c.ui.get(), &v.seen.get(), id);
    let in_call = move || cu.0.get().presence.get(&id).map(|p| p.len()).unwrap_or(0);
    let ttl = ttl_label(ch.ttl_hours);
    let title = move || {
        c.ui.with(|u| u.chan(id).map(|c| u.title(c)).unwrap_or_default())
    };
    let dm = ch.dm;
    view! {
        <li>
            <button
                class="channel"
                class:active=move || v.selected.get() == Some(id)
                class:unread={move || unread() > 0}
                on:click=move |_| {
                    v.selected.set(Some(id));
                    v.drawer.set(false);
                }
            >
                {if dm {
                    view! { <Avatar name=title() size=22/> }.into_any()
                } else {
                    view! { <Icon svg=ic::HASHTAG size=18 class="ch-hash"/> }.into_any()
                }}
                <span class="ch-name">{title}</span>
                <Show when=move || { in_call() > 0 }>
                    <span class="ch-call" title="People in the call"><Icon svg=ic::CALL size=12/>{in_call}</span>
                </Show>
                {ttl.map(|t| view! { <span class="ch-ttl mono" title="Disappearing messages"><Icon svg=ic::TIMER size=12/>{t}</span> })}
                {(!ch.joined).then(|| view! { <span class="ch-joining" title="Waiting for a member to let this device in"><span class="spinner xs"></span></span> })}
                <Show when=move || { unread() > 0 && v.selected.get() != Some(id) }>
                    <span class="badge">{move || unread().min(99)}</span>
                </Show>
            </button>
        </li>
    }
}

#[component]
fn Sidebar() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let publics = move || {
        c.ui.get()
            .channels
            .into_iter()
            .filter(|c| !c.dm)
            .collect::<Vec<_>>()
    };
    let dms = move || {
        c.ui.get()
            .channels
            .into_iter()
            .filter(|c| c.dm)
            .collect::<Vec<_>>()
    };
    view! {
        <nav class="sidebar">
            <div class="server-head">
                <div class="logo-mark"><Icon svg=ic::LOCK size=20/></div>
                <div class="server-meta grow">
                    <div class="server-name">{move || c.ui.get().server_name}</div>
                    <div class="server-sub mono">
                        {move || {
                            if c.ui.get().online {
                                view! { <span class="dot dot-on"></span><span>"E2EE · live"</span> }.into_any()
                            } else {
                                view! { <span class="dot dot-off"></span><span>"reconnecting…"</span> }.into_any()
                            }
                        }}
                    </div>
                </div>
                <button class="icon-btn" title="Search (Ctrl+K)" aria-label="Search" on:click=move |_| v.search.set(true)>
                    <Icon svg=ic::SEARCH size=19/>
                </button>
            </div>
            <div class="channel-scroll">
                <div class="section-label"><span>"Channels"</span></div>
                <ul class="channel-list">
                    <For each=publics key=|ch| (ch.id, ch.name.clone(), ch.joined, ch.ttl_hours) let:ch>
                        <ChannelItem ch/>
                    </For>
                </ul>
                <div class="section-label">
                    <span>"Direct messages"</span>
                    <button class="icon-btn sm" title="New direct message" aria-label="New direct message" on:click=move |_| v.dm_picker.set(true)>
                        <Icon svg=ic::ADD size=16/>
                    </button>
                </div>
                <ul class="channel-list">
                    <For each=dms key=|ch| (ch.id, ch.dm_peer, ch.joined, ch.ttl_hours) let:ch>
                        <ChannelItem ch/>
                    </For>
                    <Show when=move || dms().is_empty()>
                        <li class="empty-hint">"No DMs yet. Every DM is its own end-to-end encrypted group of two."</li>
                    </Show>
                </ul>
            </div>
            <UpdateBanner/>
            <div class="sidebar-foot">
                <div class="me">
                    <Avatar name=c.ui.get_untracked().username size=34/>
                    <div class="me-meta">
                        <div class="me-name">
                            {move || c.ui.get().username}
                            <Show when=move || c.ui.get().is_admin>
                                <span class="crown" title="Admin"><Icon svg=ic::CROWN size=14/></span>
                            </Show>
                        </div>
                        <div class="me-sub mono">{move || format!("device #{}", c.ui.get().device_id)}</div>
                    </div>
                </div>
                <button class="icon-btn" title="Settings" aria-label="Settings" on:click=move |_| v.settings.set(true)>
                    <Icon svg=ic::SETTINGS size=20/>
                </button>
            </div>
        </nav>
    }
}

#[component]
fn UpdateBanner() -> impl IntoView {
    let update = RwSignal::new(None::<(String, String)>);
    spawn_local(async move {
        if let Some(u) = net::check_update().await {
            let _ = update.try_set(Some(u));
        }
    });
    move || {
        update.get().map(|(tag, url)| {
            view! {
                <button class="update" on:click=move |_| net::open_external(&url)>
                    <Icon svg=ic::DOWNLOAD size=16/>
                    <span>{format!("Update available: {tag}")}</span>
                </button>
            }
        })
    }
}

#[component]
fn ChatPane() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let cu = calls();
    let chan = move || {
        let sel = v.selected.get()?;
        c.ui.with(|u| u.chan(sel).cloned())
    };
    let title = move || {
        chan()
            .map(|ch| c.ui.with(|u| u.title(&ch)))
            .unwrap_or_default()
    };
    let messages = Memo::new(move |_| {
        let Some(sel) = v.selected.get() else {
            return vec![];
        };
        c.ui.with(|u| u.messages.get(&sel).cloned().unwrap_or_default())
    });
    let scroller: NodeRef<leptos::html::Div> = NodeRef::new();
    let stick = RwSignal::new(true);
    let show_jump = RwSignal::new(false);
    let dragging = RwSignal::new(false);
    let dropped: RwSignal<Vec<Pending>, LocalStorage> = RwSignal::new_local(vec![]);

    let scroll_bottom = move || {
        if let Some(el) = scroller.try_get_untracked().flatten() {
            el.set_scroll_top(el.scroll_height());
        }
    };
    Effect::new(move |_| {
        let _ = messages.get();
        let _ = v.selected.get();
        if stick.get_untracked() {
            request_animation_frame(scroll_bottom);
        } else {
            show_jump.set(true);
        }
    });
    Effect::new(move |_| {
        let _ = v.selected.get();
        stick.set(true);
        show_jump.set(false);
        request_animation_frame(scroll_bottom);
    });
    // Jump to a highlighted message (from search or a reply quote).
    Effect::new(move |_| {
        if let Some(id) = v.highlight.get() {
            stick.set(false);
            request_animation_frame(move || {
                if let Some(el) = web_sys::window()
                    .and_then(|w| w.document())
                    .and_then(|d| d.get_element_by_id(&format!("m-{id}")))
                {
                    let o = web_sys::ScrollIntoViewOptions::new();
                    o.set_block(web_sys::ScrollLogicalPosition::Center);
                    el.scroll_into_view_with_scroll_into_view_options(&o);
                }
            });
            spawn_local(async move {
                net::sleep(2200).await;
                let _ = v.highlight.try_set(None);
            });
        }
    });
    let on_scroll = move |_| {
        if let Some(el) = scroller.try_get_untracked().flatten() {
            let near = el.scroll_height() - el.scroll_top() - el.client_height() < 80;
            stick.set(near);
            if near {
                show_jump.set(false);
            }
        }
    };
    let dm = move || chan().map(|c| c.dm).unwrap_or(false);
    let joined = move || chan().map(|c| c.joined).unwrap_or(false);
    let in_this_call = move || {
        let a = cu.0.get().active;
        a.is_some() && a == v.selected.get()
    };
    let start_call = move |video: bool| {
        let Some(cid) = v.selected.get_untracked() else {
            return;
        };
        let t = toasts();
        call::join(
            cid,
            video,
            c.ui.get_untracked().device_id,
            c.http.get_value(),
            v.handle.get_value(),
            cu.0,
            move |e| t.err(e),
        );
    };

    view! {
        <section
            class="chat"
            class:dragging=move || dragging.get()
            on:dragover=move |e: web_sys::DragEvent| { e.prevent_default(); if joined() { dragging.set(true); } }
            on:dragleave=move |_| dragging.set(false)
            on:drop=move |e: web_sys::DragEvent| {
                e.prevent_default();
                dragging.set(false);
                if let Some(files) = e.data_transfer().and_then(|d| d.files()) {
                    read_files(files, dropped);
                }
            }
        >
            <header class="chat-head">
                <button class="icon-btn only-mobile" aria-label="Channels" on:click=move |_| v.drawer.set(true)>
                    <Icon svg=ic::MENU size=22/>
                </button>
                {move || {
                    if dm() {
                        view! { <Avatar name=title() size=28/> }.into_any()
                    } else {
                        view! { <Icon svg=ic::HASHTAG size=22 class="head-hash"/> }.into_any()
                    }
                }}
                <div class="head-title">
                    <h1>{title}</h1>
                    <span class="head-topic">
                        {move || {
                            if dm() {
                                "Private · only the two of you hold the keys".to_string()
                            } else {
                                chan().map(|c| c.topic).unwrap_or_default()
                            }
                        }}
                    </span>
                </div>
                <div class="head-actions">
                    {move || {
                        let sel = v.selected.get()?;
                        let code = c.ui.get().epoch_codes.get(&sel).cloned()?;
                        Some(view! {
                            <div class="e2ee-pill" title="Security code for this conversation's current encryption epoch. Everyone in it sees the same code; compare it out-of-band to rule out a man-in-the-middle.">
                                <Icon svg=ic::SECURITY size=16/>
                                <span class="mono">{code}</span>
                            </div>
                        })
                    }}
                    <Show when=move || joined() && !in_this_call()>
                        <button class="icon-btn" title="Voice call" aria-label="Voice call" on:click=move |_| start_call(false)>
                            <Icon svg=ic::CALL size=20/>
                        </button>
                        <button class="icon-btn hide-xs" title="Video call" aria-label="Video call" on:click=move |_| start_call(true)>
                            <Icon svg=ic::VIDEO size=20/>
                        </button>
                    </Show>
                    <Show when=dm>
                        <DmTimer/>
                    </Show>
                    <button class="icon-btn" aria-label="Members" title="Members" class:active=move || v.members.get() on:click=move |_| v.members.update(|m| *m = !*m)>
                        <Icon svg=ic::USERS size=20/>
                    </button>
                </div>
            </header>
            <CallStage/>
            <div class="messages" node_ref=scroller on:scroll=on_scroll>
                <div class="messages-inner">
                    <ChannelIntro/>
                    <For each=move || grouped(messages.get()) key=|g| g.key.clone() let:g>
                        <MessageGroup g/>
                    </For>
                </div>
            </div>
            <Show when=move || show_jump.get()>
                <button class="jump" on:click=move |_| { stick.set(true); show_jump.set(false); scroll_bottom(); }>
                    <Icon svg=ic::ARROW_DOWN size=16/>
                    <span>"New messages"</span>
                </button>
            </Show>
            <div class="drop-hint"><Icon svg=ic::ATTACH size=28/><span>"Drop to attach. Files are encrypted before upload."</span></div>
            <Composer dropped/>
        </section>
    }
}

#[component]
fn DmTimer() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let t = toasts();
    let ttl = move || {
        let sel = v.selected.get();
        c.ui.with(|u| {
            sel.and_then(|s| u.chan(s))
                .map(|c| c.ttl_hours)
                .unwrap_or(0)
        })
    };
    let set = move |e: leptos::ev::Event| {
        let Some(cid) = v.selected.get_untracked() else {
            return;
        };
        let hours: i64 = event_target_value(&e).parse().unwrap_or(0);
        let http = c.http.get_value();
        spawn_local(async move {
            let body = bunkr_proto::TtlReq { ttl_hours: hours };
            match bunkr_core::call_ok::<()>(
                &http,
                "PUT",
                &format!("/api/dms/{cid}/ttl"),
                Some(&body),
            )
            .await
            {
                Ok(()) => t.ok(if hours == 0 {
                    "Disappearing messages off"
                } else {
                    "Disappearing messages on"
                }),
                Err(e) => t.err(e.to_string()),
            }
        });
    };
    const OPTS: [(i64, &str); 6] = [
        (0, "Off"),
        (1, "1h"),
        (24, "1d"),
        (168, "7d"),
        (720, "30d"),
        (2160, "90d"),
    ];
    view! {
        <label class="timer-select" title="Disappearing messages">
            <Icon svg=ic::TIMER size=18/>
            <select on:change=set prop:value=move || ttl().to_string()>
                {OPTS.iter().map(|(h, l)| view! { <option value=h.to_string() selected=move || ttl() == *h>{*l}</option> }).collect_view()}
            </select>
        </label>
    }
}

#[component]
fn ChannelIntro() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let chan = move || {
        let sel = v.selected.get()?;
        c.ui.with(|u| u.chan(sel).cloned())
    };
    view! {
        <div class="intro">
            <div class="intro-icon"><Icon svg=ic::CHAT_LOCK size=30/></div>
            <h2>
                {move || match chan() {
                    Some(ch) if ch.dm => format!("You and {}", c.ui.with(|u| u.title(&ch))),
                    Some(ch) => format!("Welcome to #{}", ch.name),
                    None => String::new(),
                }}
            </h2>
            <p class="muted">
                "Messages, files and calls here are end-to-end encrypted with MLS and a post-quantum hybrid key exchange. "
                "The server can't read them, and new devices can't read anything sent before they joined."
            </p>
            {move || {
                let ttl = chan().and_then(|c| ttl_label(c.ttl_hours))?;
                Some(view! {
                    <div class="chip"><Icon svg=ic::TIMER size=14/><span>{format!("Messages disappear after {ttl}")}</span></div>
                })
            }}
        </div>
    }
}

#[derive(Clone, PartialEq)]
struct Group {
    key: String,
    day: Option<String>,
    system: bool,
    items: Vec<MsgView>,
}

fn grouped(msgs: Vec<MsgView>) -> Vec<Group> {
    let mut out: Vec<Group> = vec![];
    let mut last_day: Option<(u32, u32, u32)> = None;
    for m in msgs {
        let dk = crate::util::day_key(m.ts);
        let new_day = last_day != Some(dk);
        last_day = Some(dk);
        let system = matches!(m.body, MsgBody::System(_) | MsgBody::Undecryptable);
        let joinable = out.last().map(|g| {
            !new_day
                && !g.system
                && !system
                && m.reply.is_none()
                && g.items[0].user_id == m.user_id
                && m.ts - g.items.last().unwrap().ts < 5 * 60_000
        });
        if joinable == Some(true) {
            out.last_mut().unwrap().items.push(m);
        } else {
            out.push(Group {
                key: String::new(),
                day: new_day.then(|| fmt_day(m.ts)),
                system,
                items: vec![m],
            });
        }
    }
    // The key covers contents so edits/reactions re-render the group.
    for g in out.iter_mut() {
        g.key = format!(
            "{:?}{}",
            g.items
                .iter()
                .map(|m| (
                    &m.id,
                    &m.body,
                    &m.reactions,
                    m.edited,
                    m.files.len(),
                    m.unverified,
                    &m.reply
                ))
                .collect::<Vec<_>>(),
            g.day.is_some()
        );
    }
    out
}

#[component]
fn MessageGroup(g: Group) -> impl IntoView {
    let day = g
        .day
        .clone()
        .map(|d| view! { <div class="day-sep"><span>{d}</span></div> });
    if g.system {
        let items = g
            .items
            .into_iter()
            .map(|m| {
                let (icon, text) = match &m.body {
                    MsgBody::System(t) => (ic::SHIELD, t.clone()),
                    _ => (
                        ic::ALERT,
                        "A message couldn't be decrypted on this device".to_string(),
                    ),
                };
                view! {
                    <div class="sys" class:sys-bad=matches!(m.body, MsgBody::Undecryptable)>
                        <Icon svg=icon size=14/>
                        <span>{text}</span>
                        <span class="sys-time mono">{fmt_time(m.ts)}</span>
                    </div>
                }
            })
            .collect_view();
        return view! { {day} {items} }.into_any();
    }
    let first = g.items[0].clone();
    let h = crate::util::hue(&first.username);
    let lines = g
        .items
        .into_iter()
        .map(|m| view! { <Line m/> })
        .collect_view();
    view! {
        {day}
        <article class="group" class:mine=first.mine>
            <Avatar name=first.username.clone() size=38/>
            <div class="group-body">
                {first.reply.clone().map(|r| view! { <ReplyQuote r/> })}
                <header class="group-head">
                    <span class="author" style=format!("--h:{h}")>{first.username.clone()}</span>
                    {first.unverified.then(|| view! {
                        <span class="tag tag-warn" title="This device was not signed by the account key we know for this user">
                            <Icon svg=ic::ALERT size=12/>"unverified"
                        </span>
                    })}
                    <time class="mono">{fmt_time(first.ts)}</time>
                </header>
                {lines}
            </div>
        </article>
    }
    .into_any()
}

#[component]
fn ReplyQuote(r: crate::engine::ReplyView) -> impl IntoView {
    let v = view_ctx();
    let id = r.id.clone();
    view! {
        <button class="reply-quote" on:click=move |_| v.highlight.set(Some(id.clone()))>
            <Icon svg=ic::REPLY size=14/>
            <span class="rq-name">{if r.username.is_empty() { String::new() } else { format!("@{}", r.username) }}</span>
            <span class="rq-text">{r.snippet}</span>
        </button>
    }
}

#[component]
fn Line(m: MsgView) -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let t = toasts();
    let picker = RwSignal::new(false);
    let id = m.id.clone();
    let seq = m.seq;
    let deleted = matches!(m.body, MsgBody::Deleted);
    let text = match &m.body {
        MsgBody::Text(t) => t.clone(),
        _ => String::new(),
    };
    let me = c.ui.get_untracked().username;
    let mention = text.contains(&format!("@{me}"));
    let is_public = move || {
        let sel = v.selected.get();
        c.ui.with(|u| sel.and_then(|s| u.chan(s)).map(|c| !c.dm).unwrap_or(false))
    };
    let react = {
        let id = id.clone();
        move |emoji: String| {
            let Some(cid) = v.selected.get_untracked() else {
                return;
            };
            v.handle.get_value().send(Cmd::React {
                cid,
                id: id.clone(),
                emoji,
            });
            picker.set(false);
        }
    };
    let reply = {
        let (id, user, text) = (id.clone(), m.username.clone(), text.clone());
        move |_| {
            v.editing.set(None);
            v.reply.set(Some(ReplyTo {
                id: id.clone(),
                username: user.clone(),
                snippet: if text.is_empty() {
                    "📎 attachment".into()
                } else {
                    text.chars().take(120).collect()
                },
            }));
            focus_composer();
        }
    };
    let edit = {
        let (id, text) = (id.clone(), text.clone());
        move |_| {
            v.reply.set(None);
            v.editing.set(Some((id.clone(), text.clone())));
            focus_composer();
        }
    };
    let del = {
        let id = id.clone();
        move |_| {
            let Some(cid) = v.selected.get_untracked() else {
                return;
            };
            let (tx, rx) = oneshot::channel();
            v.handle.get_value().send(Cmd::Delete {
                cid,
                id: id.clone(),
                reply: tx,
            });
            spawn_local(async move {
                if let Ok(Err(e)) = rx.await {
                    t.err(e);
                }
            });
        }
    };
    let mod_del = move |_| {
        let http = c.http.get_value();
        spawn_local(async move {
            match bunkr_core::call_ok::<()>(
                &http,
                "DELETE",
                &format!("/api/admin/log/{seq}"),
                bunkr_core::NO_BODY,
            )
            .await
            {
                Ok(()) => t.ok("Message removed by moderator"),
                Err(e) => t.err(e.to_string()),
            }
        });
    };
    let hl_id = id.clone();
    let reactions = m.reactions.clone();
    let mine = m.mine;
    let files = m.files.clone();
    let has_text = !text.is_empty();
    let react_chips = react.clone();
    let react_pop = react.clone();
    view! {
        <div
            class="line"
            id=format!("m-{id}")
            class:mention=mention
            class:highlight=move || v.highlight.get().as_deref() == Some(hl_id.as_str())
        >
            <span class="line-time mono">{fmt_time(m.ts)}</span>
            <div class="line-main">
                {if deleted {
                    view! { <div class="line-text deleted">"message deleted"</div> }.into_any()
                } else {
                    view! {
                        {has_text.then(|| view! {
                            <div class="line-text">
                                {rich_text(&text, &me)}
                                {m.edited.then(|| view! { <span class="edited">" (edited)"</span> })}
                            </div>
                        })}
                        {(!files.is_empty()).then(|| view! {
                            <div class="files">{files.into_iter().map(|f| view! { <FileView f/> }).collect_view()}</div>
                        })}
                    }
                    .into_any()
                }}
                {(!reactions.is_empty()).then(|| view! {
                    <div class="reactions">
                        {reactions.into_iter().map(|(e, n, me)| {
                            let react = react_chips.clone();
                            let e2 = e.clone();
                            view! {
                                <button class="reaction" class:me=me on:click=move |_| react(e2.clone())>
                                    <span>{e}</span><span class="mono">{n}</span>
                                </button>
                            }
                        }).collect_view()}
                    </div>
                })}
            </div>
            {(!deleted).then(|| view! {
                <div class="line-actions" class:open=move || picker.get()>
                    <Show when=move || picker.get()>
                        <div class="emoji-pop">
                            {QUICK_EMOJI.iter().map(|e| {
                                let react = react_pop.clone();
                                view! { <button class="emoji" on:click=move |_| react(e.to_string())>{*e}</button> }
                            }).collect_view()}
                        </div>
                    </Show>
                    <button class="icon-btn sm" title="React" on:click=move |_| picker.update(|p| *p = !*p)><Icon svg=ic::SMILE size=16/></button>
                    <button class="icon-btn sm" title="Reply" on:click=reply.clone()><Icon svg=ic::REPLY size=16/></button>
                    {(mine && has_text).then(|| view! { <button class="icon-btn sm" title="Edit" on:click=edit.clone()><Icon svg=ic::EDIT size=16/></button> })}
                    {mine.then(|| view! { <button class="icon-btn sm danger" title="Delete for everyone" on:click=del.clone()><Icon svg=ic::DELETE size=16/></button> })}
                    <Show when=move || !mine && c.ui.get().is_admin && is_public()>
                        <button class="icon-btn sm danger" title="Remove (moderator)" on:click=mod_del><Icon svg=ic::BLOCK size=16/></button>
                    </Show>
                </div>
            })}
        </div>
    }
}

fn focus_composer() {
    request_animation_frame(|| {
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.query_selector(".composer textarea").ok().flatten())
        {
            let _ = el.unchecked_into::<web_sys::HtmlElement>().focus();
        }
    });
}

/// Linkify URLs, highlight @mentions and `inline code`.
fn rich_text(text: &str, me: &str) -> Vec<AnyView> {
    let mut parts = vec![];
    let code_ok = text.matches('`').count() >= 2;
    for (i, seg) in text.split('`').enumerate() {
        if i % 2 == 1 && code_ok {
            parts.push(view! { <code>{seg.to_string()}</code> }.into_any());
            continue;
        }
        if i > 0 && !code_ok {
            parts.push(view! { "`" }.into_any());
        }
        for word in seg.split_inclusive(char::is_whitespace) {
            let trimmed = word.trim_end();
            let tail = word[trimmed.len()..].to_string();
            if (trimmed.starts_with("https://") || trimmed.starts_with("http://"))
                && trimmed.len() > 10
            {
                parts.push(
                    view! {
                        <a href=trimmed.to_string() target="_blank" rel="noopener noreferrer nofollow">{trimmed.to_string()}</a>
                        {tail}
                    }
                    .into_any(),
                );
            } else if trimmed.len() > 1 && trimmed.starts_with('@') {
                let name = trimmed
                    .trim_start_matches('@')
                    .trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
                let is_me = name == me;
                parts.push(
                    view! { <span class="at" class:at-me=is_me>{trimmed.to_string()}</span>{tail} }
                        .into_any(),
                );
            } else {
                parts.push(view! { {word.to_string()} }.into_any());
            }
        }
    }
    parts
}

// ---------------- attachments ----------------

thread_local! {
    static OBJECT_URLS: std::cell::RefCell<HashMap<String, String>> = std::cell::RefCell::new(HashMap::new());
}

fn inline_image(f: &FileRef) -> bool {
    matches!(
        f.mime.as_str(),
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/avif"
    ) && f.size <= 15 * 1024 * 1024
}

fn object_url(bytes: &[u8], mime: &str) -> Option<String> {
    let arr = js_sys::Array::new();
    arr.push(&js_sys::Uint8Array::from(bytes).into());
    let bag = web_sys::BlobPropertyBag::new();
    bag.set_type(mime);
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&arr, &bag).ok()?;
    web_sys::Url::create_object_url_with_blob(&blob).ok()
}

fn human_size(n: u64) -> String {
    match n {
        n if n >= 1024 * 1024 => format!("{:.1} MB", n as f64 / 1024.0 / 1024.0),
        n if n >= 1024 => format!("{:.0} KB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

fn save_as(url: &str, name: &str) {
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    if let Ok(a) = doc.create_element("a") {
        let a: web_sys::HtmlAnchorElement = a.unchecked_into();
        a.set_href(url);
        a.set_download(name);
        a.click();
    }
}

fn fetch_file(
    f: FileRef,
    url: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    failed: RwSignal<bool>,
    then_save: bool,
) {
    if let Some(u) = url.get_untracked() {
        if then_save {
            save_as(&u, &f.name);
        }
        return;
    }
    if busy.get_untracked() {
        return;
    }
    busy.set(true);
    let http = ctx().http.get_value();
    let t = toasts();
    spawn_local(async move {
        match Device::download_file(&http, &f).await {
            Ok(bytes) => {
                if let Some(u) = object_url(&bytes, &f.mime) {
                    OBJECT_URLS.with(|m| m.borrow_mut().insert(f.blob.clone(), u.clone()));
                    if then_save {
                        save_as(&u, &f.name);
                    }
                    let _ = url.try_set(Some(u));
                }
            }
            Err(e) => {
                let _ = failed.try_set(true);
                if then_save {
                    t.err(e.to_string());
                }
            }
        }
        let _ = busy.try_set(false);
    });
}

#[component]
fn FileView(f: FileRef) -> impl IntoView {
    let url = RwSignal::new(OBJECT_URLS.with(|m| m.borrow().get(&f.blob).cloned()));
    let busy = RwSignal::new(false);
    let failed = RwSignal::new(false);
    if inline_image(&f) {
        fetch_file(f.clone(), url, busy, failed, false);
        let style = match (f.w, f.h) {
            (Some(w), Some(h)) if w > 0 && h > 0 => {
                format!("aspect-ratio:{w}/{h};width:min({w}px,100%)")
            }
            _ => String::new(),
        };
        let name = f.name.clone();
        let open = RwSignal::new(false);
        let f2 = f.clone();
        return view! {
            <div class="file-img" style=style>
                {move || match (url.get(), failed.get()) {
                    (Some(u), _) => view! { <img src=u alt=name.clone() on:click=move |_| open.set(true)/> }.into_any(),
                    (None, true) => view! { <div class="img-gone"><Icon svg=ic::IMAGE size=22/><span>"Image expired or deleted"</span></div> }.into_any(),
                    _ => view! { <div class="img-loading"><span class="spinner sm"></span><span class="mono">"decrypting…"</span></div> }.into_any(),
                }}
                <button class="img-dl icon-btn sm" title="Download" on:click=move |_| fetch_file(f2.clone(), url, busy, failed, true)><Icon svg=ic::DOWNLOAD size=16/></button>
                <Show when=move || open.get()>
                    <div class="lightbox" on:click=move |_| open.set(false)>
                        <img src=move || url.get().unwrap_or_default()/>
                    </div>
                </Show>
            </div>
        }
        .into_any();
    }
    let name = f.name.clone();
    let size = f.size;
    view! {
        <button class="file-card" on:click=move |_| fetch_file(f.clone(), url, busy, failed, true)>
            <div class="file-icon"><Icon svg=ic::FILE size=22/></div>
            <div class="file-meta">
                <div class="file-name">{name}</div>
                <div class="file-sub mono">{human_size(size)}" · encrypted"</div>
            </div>
            {move || if busy.get() { view! { <span class="spinner sm"></span> }.into_any() } else { view! { <Icon svg=ic::DOWNLOAD size=18/> }.into_any() }}
        </button>
    }
    .into_any()
}

// ---------------- composer ----------------

#[derive(Clone)]
pub struct Pending {
    pub id: u32,
    pub name: String,
    pub mime: String,
    pub bytes: std::sync::Arc<Vec<u8>>,
    pub preview: Option<String>,
    pub dims: Option<(u32, u32)>,
}

fn read_files(list: web_sys::FileList, into: RwSignal<Vec<Pending>, LocalStorage>) {
    let max = ctx()
        .info
        .get_untracked()
        .map(|i| i.max_upload)
        .filter(|m| *m > 0)
        .unwrap_or(25 * 1024 * 1024);
    let t = toasts();
    for i in 0..list.length() {
        let Some(file) = list.get(i) else { continue };
        if file.size() as u64 > max {
            t.err(format!(
                "{} is too large (max {})",
                file.name(),
                human_size(max)
            ));
            continue;
        }
        spawn_local(async move {
            let Ok(buf) = JsFuture::from(file.array_buffer()).await else {
                return;
            };
            let bytes = js_sys::Uint8Array::new(&buf).to_vec();
            let mime = file.type_();
            let mime = if mime.is_empty() {
                "application/octet-stream".to_string()
            } else {
                mime
            };
            let (preview, dims) = if mime.starts_with("image/") && mime != "image/svg+xml" {
                let url = object_url(&bytes, &mime);
                let dims = match &url {
                    Some(u) => image_dims(u).await,
                    None => None,
                };
                (url, dims)
            } else {
                (None, None)
            };
            let _ = into.try_update(|v| {
                if v.len() < bunkr_core::device::MAX_FILES {
                    v.push(Pending {
                        id: (js_sys::Math::random() * 1e9) as u32,
                        name: file.name(),
                        mime,
                        bytes: std::sync::Arc::new(bytes),
                        preview,
                        dims,
                    })
                }
            });
        });
    }
}

async fn image_dims(url: &str) -> Option<(u32, u32)> {
    let img = web_sys::HtmlImageElement::new().ok()?;
    img.set_src(url);
    JsFuture::from(img.decode()).await.ok()?;
    Some((img.natural_width(), img.natural_height()))
}

fn resize_area() {
    if let Some(el) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.query_selector(".composer textarea").ok().flatten())
    {
        let el: web_sys::HtmlElement = el.unchecked_into();
        let _ = el.style().set_property("height", "auto");
        let h = el.scroll_height().min(220);
        let _ = el.style().set_property("height", &format!("{h}px"));
    }
}

#[component]
fn Composer(dropped: RwSignal<Vec<Pending>, LocalStorage>) -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let text = RwSignal::new(String::new());
    let sending = RwSignal::new(false);
    let files = dropped;
    let last_typing = StoredValue::new(0i64);
    let picker: NodeRef<leptos::html::Input> = NodeRef::new();
    let chan = move || {
        let sel = v.selected.get();
        c.ui.with(|u| sel.and_then(|s| u.chan(s).cloned()))
    };
    let joined = move || chan().map(|c| c.joined).unwrap_or(false);
    let placeholder = move || match chan() {
        Some(ch) if ch.dm => format!("Message @{}", c.ui.with(|u| u.title(&ch))),
        Some(ch) => format!("Message #{}", ch.name),
        None => String::new(),
    };
    // Load the message being edited into the box.
    Effect::new(move |_| {
        if let Some((_, t)) = v.editing.get() {
            text.set(t);
            request_animation_frame(resize_area);
        }
    });
    let typing = move || {
        let now = net::now_ms();
        if now - last_typing.get_value() > 3500 {
            last_typing.set_value(now);
            if let Some(cid) = v.selected.get_untracked() {
                v.handle.get_value().send(Cmd::Typing(cid));
            }
        }
    };
    let send = move || {
        let body = text.get_untracked();
        let pending = files.get_untracked();
        if (body.trim().is_empty() && pending.is_empty()) || sending.get_untracked() {
            return;
        }
        let Some(cid) = v.selected.get_untracked() else {
            return;
        };
        let (tx, rx) = oneshot::channel();
        if let Some((id, _)) = v.editing.get_untracked() {
            v.handle.get_value().send(Cmd::Edit {
                cid,
                id,
                text: body,
                reply: tx,
            });
            v.editing.set(None);
        } else {
            let outgoing = pending
                .iter()
                .map(|p| Outgoing {
                    bytes: (*p.bytes).clone(),
                    name: p.name.clone(),
                    mime: p.mime.clone(),
                    dims: p.dims,
                })
                .collect();
            v.handle.get_value().send(Cmd::Send {
                cid,
                text: body,
                reply_to: v.reply.get_untracked().map(|r| r.id),
                files: outgoing,
                reply: tx,
            });
            v.reply.set(None);
            files.set(vec![]);
        }
        text.set(String::new());
        request_animation_frame(resize_area);
        sending.set(true);
        let t = toasts();
        spawn_local(async move {
            if let Ok(Err(e)) = rx.await {
                t.err(e);
            }
            let _ = sending.try_set(false);
        });
    };
    let typing_line = move || {
        let sel = v.selected.get()?;
        let ui = c.ui.get();
        let names: Vec<String> = c
            .live
            .typing
            .get()
            .get(&sel)
            .map(|v| v.iter().map(|(u, _)| ui.username(*u)).collect())
            .unwrap_or_default();
        match names.len() {
            0 => None,
            1 => Some(format!("{} is typing…", names[0])),
            2 => Some(format!("{} and {} are typing…", names[0], names[1])),
            _ => Some("Several people are typing…".to_string()),
        }
    };
    view! {
        <div class="composer-wrap">
            <div class="typing" class:on=move || typing_line().is_some()>
                <span class="dots"><i></i><i></i><i></i></span>
                <span>{move || typing_line().unwrap_or_default()}</span>
            </div>
            <Show
                when=joined
                fallback=|| view! {
                    <div class="composer-wait">
                        <span class="spinner sm"></span>
                        <span>"Securing this device… a member's app will add you to the encrypted group automatically."</span>
                    </div>
                }
            >
                {move || v.reply.get().map(|r| view! {
                    <div class="compose-banner">
                        <Icon svg=ic::REPLY size=16/>
                        <span class="grow">"Replying to "<b>{format!("@{}", r.username)}</b>" · "<span class="muted">{r.snippet}</span></span>
                        <button class="icon-btn sm" on:click=move |_| v.reply.set(None)><Icon svg=ic::CLOSE size=14/></button>
                    </div>
                })}
                {move || v.editing.get().map(|_| view! {
                    <div class="compose-banner edit">
                        <Icon svg=ic::EDIT size=16/>
                        <span class="grow">"Editing message · Esc to cancel"</span>
                        <button class="icon-btn sm" on:click=move |_| { v.editing.set(None); text.set(String::new()); }><Icon svg=ic::CLOSE size=14/></button>
                    </div>
                })}
                <Show when=move || !files.get().is_empty()>
                    <div class="pending-files">
                        <For each=move || files.get() key=|p| p.id let:p>
                            {
                                let id = p.id;
                                view! {
                                    <div class="pending">
                                        {match p.preview.clone() {
                                            Some(u) => view! { <img src=u/> }.into_any(),
                                            None => view! { <div class="file-icon"><Icon svg=ic::FILE size=20/></div> }.into_any(),
                                        }}
                                        <span class="pending-name">{p.name.clone()}</span>
                                        <button class="pending-x" aria-label="Remove" on:click=move |_| files.update(|v| v.retain(|x| x.id != id))><Icon svg=ic::CLOSE size=12/></button>
                                    </div>
                                }
                            }
                        </For>
                    </div>
                </Show>
                <form class="composer" on:submit=move |e| { e.prevent_default(); send(); }>
                    <input type="file" multiple node_ref=picker class="hidden-input" on:change=move |e| {
                        let input: web_sys::HtmlInputElement = event_target(&e);
                        if let Some(list) = input.files() { read_files(list, files); }
                        input.set_value("");
                    }/>
                    <button type="button" class="attach icon-btn" title="Attach files (encrypted)" aria-label="Attach" on:click=move |_| {
                        if let Some(p) = picker.get_untracked() { p.click(); }
                    }>
                        <Icon svg=ic::ATTACH size=20/>
                    </button>
                    <textarea
                        rows="1"
                        maxlength="4000"
                        placeholder=placeholder
                        prop:value=move || text.get()
                        on:input=move |e| { text.set(event_target_value(&e)); resize_area(); typing(); }
                        on:paste=move |e: web_sys::ClipboardEvent| {
                            if let Some(list) = e.clipboard_data().and_then(|d| d.files()) {
                                if list.length() > 0 {
                                    e.prevent_default();
                                    read_files(list, files);
                                }
                            }
                        }
                        on:keydown=move |e: web_sys::KeyboardEvent| {
                            if e.key() == "Enter" && !e.shift_key() && !e.is_composing() {
                                e.prevent_default();
                                send();
                            } else if e.key() == "ArrowUp" && text.get_untracked().is_empty() {
                                // Edit your last message, Discord-style.
                                let sel = v.selected.get_untracked();
                                let last = c.ui.with_untracked(|u| {
                                    sel.and_then(|s| u.messages.get(&s)).and_then(|m| {
                                        m.iter()
                                            .rev()
                                            .find(|m| m.mine && matches!(&m.body, MsgBody::Text(t) if !t.is_empty()))
                                            .cloned()
                                    })
                                });
                                if let Some(m) = last {
                                    if let MsgBody::Text(t) = m.body {
                                        e.prevent_default();
                                        v.editing.set(Some((m.id, t)));
                                    }
                                }
                            }
                        }
                    ></textarea>
                    <button
                        type="submit"
                        class="send"
                        aria-label="Send"
                        disabled=move || (text.get().trim().is_empty() && files.get().is_empty()) || sending.get()
                    >
                        {move || if sending.get() { view! { <span class="spinner sm"></span> }.into_any() } else { view! { <Icon svg=ic::SEND size=20/> }.into_any() }}
                    </button>
                </form>
                <div class="composer-hint mono">
                    <Icon svg=ic::LOCK size=12/>
                    <span>"end-to-end encrypted · padded · sender hidden from server"</span>
                </div>
            </Show>
        </div>
    }
}

// ---------------- calls ----------------

#[component]
fn CallStage() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let cu = calls();
    let here = move || {
        let sel = v.selected.get()?;
        let ui = cu.0.get();
        if ui.active == Some(sel) {
            return Some(true);
        }
        ui.presence
            .get(&sel)
            .filter(|p| !p.is_empty())
            .map(|_| false)
    };
    let others_in_call = move || {
        let sel = v.selected.get().unwrap_or(-1);
        let ui = c.ui.get();
        cu.0.get()
            .presence
            .get(&sel)
            .map(|p| {
                let mut names: Vec<String> = p.iter().map(|(u, _, _)| ui.username(*u)).collect();
                names.sort();
                names.dedup();
                names
            })
            .unwrap_or_default()
    };
    let join = move |video: bool| {
        let Some(cid) = v.selected.get_untracked() else {
            return;
        };
        let t = toasts();
        call::join(
            cid,
            video,
            c.ui.get_untracked().device_id,
            c.http.get_value(),
            v.handle.get_value(),
            cu.0,
            move |e| t.err(e),
        );
    };
    move || {
        match here() {
        None => None,
        Some(false) => Some(
            view! {
                <div class="call-banner">
                    <span class="live-dot"></span>
                    <span class="grow">{move || format!("In call: {}", others_in_call().join(", "))}</span>
                    <button class="btn sm btn-primary" on:click=move |_| join(false)><Icon svg=ic::CALL size=16/><span>"Join"</span></button>
                    <button class="btn sm" on:click=move |_| join(true)><Icon svg=ic::VIDEO size=16/><span>"With video"</span></button>
                </div>
            }
            .into_any(),
        ),
        Some(true) => Some(view! { <ActiveCall/> }.into_any()),
    }
    }
}

#[component]
fn ActiveCall() -> impl IntoView {
    let c = ctx();
    let cu = calls();
    let sig = cu.0;
    let t = toasts();
    let tiles = move || {
        let ui = sig.get();
        let mut v: Vec<(i64, String, bool, u64)> = vec![(
            0,
            c.ui.get_untracked().username,
            ui.video && !ui.cam_off || ui.sharing,
            ui.streams_rev,
        )];
        for p in &ui.peers {
            v.push((
                p.device,
                c.ui.with(|u| u.username(p.user)),
                p.video,
                ui.streams_rev,
            ));
        }
        v
    };
    view! {
        <div class="call" class:video=move || sig.get().video>
            <div class="call-grid">
                <For each=tiles key=|t| (t.0, t.2, t.3) let:tile>
                    <CallTile device=tile.0 name=tile.1 video=tile.2/>
                </For>
                <Show when=move || sig.get().peers.is_empty() && !sig.get().joining>
                    <div class="call-wait mono">"Waiting for others to join…"</div>
                </Show>
            </div>
            <div class="call-controls">
                <span class="call-e2e mono"><Icon svg=ic::LOCK size=12/>"E2E · DTLS-SRTP · keys verified via MLS"</span>
                <button class="round" class:off=move || sig.get().muted title="Mute" on:click=move |_| call::toggle_mute(sig)>
                    {move || if sig.get().muted { view! { <Icon svg=ic::MIC_OFF size=20/> }.into_any() } else { view! { <Icon svg=ic::MIC size=20/> }.into_any() }}
                </button>
                <Show when=move || sig.get().video>
                    <button class="round" class:off=move || sig.get().cam_off title="Camera" on:click=move |_| call::toggle_cam(sig)>
                        {move || if sig.get().cam_off { view! { <Icon svg=ic::CAM_OFF size=20/> }.into_any() } else { view! { <Icon svg=ic::VIDEO size=20/> }.into_any() }}
                    </button>
                    <button class="round hide-xs" class:on=move || sig.get().sharing title="Share screen" on:click=move |_| call::toggle_share(sig, move |e| t.err(e))>
                        <Icon svg=ic::SCREEN size=20/>
                    </button>
                </Show>
                <button class="round hangup" title="Leave call" on:click=move |_| call::leave(sig)>
                    <Icon svg=ic::HANGUP size=20/>
                </button>
            </div>
        </div>
    }
}

#[component]
fn CallTile(device: i64, name: String, video: bool) -> impl IntoView {
    let vid: NodeRef<leptos::html::Video> = NodeRef::new();
    let aud: NodeRef<leptos::html::Audio> = NodeRef::new();
    Effect::new(move |_| {
        if let Some(v) = vid.get() {
            call::attach(v.unchecked_ref(), device);
        }
        if let Some(a) = aud.get() {
            call::attach(a.unchecked_ref(), device);
        }
    });
    let local = device == 0;
    view! {
        <div class="tile" class:has-video=video>
            {if video {
                view! { <video node_ref=vid autoplay=true playsinline=true prop:muted=local class:mirror=local></video> }.into_any()
            } else {
                view! {
                    <div class="tile-avatar"><Avatar name=name.clone() size=64/></div>
                    {(!local).then(|| view! { <audio node_ref=aud autoplay=true></audio> })}
                }
                .into_any()
            }}
            <span class="tile-name">{if local { format!("{name} (you)") } else { name }}</span>
        </div>
    }
}

// ---------------- search & DM picker ----------------

#[component]
fn SearchModal() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let q = RwSignal::new(String::new());
    let input: NodeRef<leptos::html::Input> = NodeRef::new();
    Effect::new(move |_| {
        if let Some(i) = input.get() {
            let _ = i.focus();
        }
    });
    let results = move || {
        let needle = q.get().trim().to_lowercase();
        if needle.chars().count() < 2 {
            return vec![];
        }
        let ui = c.ui.get();
        let mut out = vec![];
        for ch in &ui.channels {
            for m in ui.messages.get(&ch.id).into_iter().flatten() {
                let hit = match &m.body {
                    MsgBody::Text(t) => {
                        t.to_lowercase().contains(&needle)
                            || m.files
                                .iter()
                                .any(|f| f.name.to_lowercase().contains(&needle))
                    }
                    _ => false,
                };
                if hit {
                    out.push((ch.id, ui.title(ch), ch.dm, m.clone()));
                }
            }
        }
        out.sort_by_key(|r| -r.3.ts);
        out.truncate(60);
        out
    };
    view! {
        <div class="modal-backdrop top" on:click=move |_| v.search.set(false)>
            <div class="modal search" on:click=|e| e.stop_propagation()>
                <div class="search-bar">
                    <Icon svg=ic::SEARCH size=20/>
                    <input node_ref=input class="search-input" placeholder="Search your decrypted messages…" prop:value=move || q.get() on:input=move |e| q.set(event_target_value(&e))/>
                    <kbd class="mono">"esc"</kbd>
                </div>
                <div class="search-results">
                    {move || {
                        let r = results();
                        if r.is_empty() {
                            let hint = if q.get().trim().chars().count() < 2 {
                                "Search runs on this device only. The server can't search what it can't read."
                            } else {
                                "No matches in the messages stored on this device."
                            };
                            return view! { <div class="search-empty muted small">{hint}</div> }.into_any();
                        }
                        r.into_iter().map(|(cid, title, dm, m)| {
                            let id = m.id.clone();
                            let text = match &m.body {
                                MsgBody::Text(t) if !t.is_empty() => t.clone(),
                                _ => m.files.first().map(|f| format!("📎 {}", f.name)).unwrap_or_default(),
                            };
                            view! {
                                <button class="result" on:click=move |_| {
                                    v.selected.set(Some(cid));
                                    v.search.set(false);
                                    v.drawer.set(false);
                                    let id = id.clone();
                                    spawn_local(async move { net::sleep(80).await; let _ = v.highlight.try_set(Some(id)); });
                                }>
                                    <div class="result-head">
                                        <span class="result-where mono">{if dm { format!("@{title}") } else { format!("#{title}") }}</span>
                                        <b>{m.username.clone()}</b>
                                        <span class="muted mono small">{format!("{} {}", fmt_day(m.ts), fmt_time(m.ts))}</span>
                                    </div>
                                    <div class="result-text">{text}</div>
                                </button>
                            }
                        }).collect_view().into_any()
                    }}
                </div>
            </div>
        </div>
    }
}

#[component]
fn DmPicker() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let q = RwSignal::new(String::new());
    let users = move || {
        let ui = c.ui.get();
        let needle = q.get().to_lowercase();
        ui.users
            .iter()
            .filter(|u| u.id != ui.user_id && u.username.contains(&needle))
            .cloned()
            .collect::<Vec<_>>()
    };
    view! {
        <div class="modal-backdrop top" on:click=move |_| v.dm_picker.set(false)>
            <div class="modal search" on:click=|e| e.stop_propagation()>
                <div class="search-bar">
                    <Icon svg=ic::DM size=20/>
                    <input class="search-input" placeholder="Start a private conversation with…" prop:value=move || q.get() on:input=move |e| q.set(event_target_value(&e))/>
                </div>
                <div class="search-results">
                    <For each=users key=|u| u.id let:u>
                        {
                            let id = u.id;
                            view! {
                                <button class="result row gap-12" on:click=move |_| { v.dm_picker.set(false); v.open_dm(id); }>
                                    <Avatar name=u.username.clone() size=32/>
                                    <div class="grow">
                                        <b>{u.username.clone()}</b>
                                        <div class="muted mono small">{u.fingerprint.split(' ').take(4).collect::<Vec<_>>().join(" ")}</div>
                                    </div>
                                    <Icon svg=ic::DM size=18/>
                                </button>
                            }
                        }
                    </For>
                </div>
            </div>
        </div>
    }
}

// ---------------- members ----------------

#[component]
fn MembersPanel() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let rows = move || {
        let ui = c.ui.get();
        let Some(sel) = v.selected.get() else {
            return vec![];
        };
        let ch = ui.chan(sel).cloned();
        let devs = ui.members.get(&sel).cloned().unwrap_or_default();
        let mut users: Vec<_> = ui
            .users
            .iter()
            .filter(|u| match &ch {
                Some(ch) if ch.dm => u.id == ui.user_id || Some(u.id) == ch.dm_peer,
                _ => true,
            })
            .map(|u| {
                let mine: Vec<_> = devs.iter().filter(|(uid, _, _)| *uid == u.id).collect();
                let verified = !mine.is_empty() && mine.iter().all(|(_, _, ok)| *ok);
                (u.clone(), mine.len(), verified, u.id == ui.user_id)
            })
            .collect();
        users.sort_by_key(|(u, n, _, _)| (*n == 0, !u.is_admin, u.username.clone()));
        users
    };
    view! {
        <aside class="members">
            <header class="members-head">
                <span>"Members"</span>
                <button class="icon-btn" aria-label="Close" on:click=move |_| v.members.set(false)><Icon svg=ic::CLOSE size=18/></button>
            </header>
            <ul>
                <For each=rows key=|(u, n, ok, _)| (u.id, *n, *ok, u.key_changed, u.is_admin) let:row>
                    {
                        let (u, n, ok, is_me) = row;
                        let uid = u.id;
                        let fp = u.fingerprint.clone();
                        view! {
                            <li class="member" class:offline=n == 0>
                                <Avatar name=u.username.clone() size=32/>
                                <div class="member-meta">
                                    <div class="member-name">
                                        {u.username.clone()}
                                        {u.is_admin.then(|| view! { <span class="crown" title="Admin"><Icon svg=ic::CROWN size=13/></span> })}
                                    </div>
                                    <div class="member-sub mono" title="Account key fingerprint. Compare in person to verify.">
                                        {fp.split(' ').take(3).collect::<Vec<_>>().join(" ")}
                                    </div>
                                    {u.key_changed.then(|| view! {
                                        <button class="tag tag-warn" title="This user's identity key changed (they reset their password). Click to acknowledge." on:click=move |_| v.handle.get_value().send(Cmd::AckKeyChange(uid))>
                                            <Icon svg=ic::ALERT size=12/>"new identity"
                                        </button>
                                    })}
                                </div>
                                {(!is_me).then(|| view! {
                                    <button class="icon-btn sm" title="Send a private message" on:click=move |_| v.open_dm(uid)><Icon svg=ic::DM size=16/></button>
                                })}
                                <span class="member-state" title=move || if n == 0 { "No device here".to_string() } else if ok { format!("{n} verified device(s)") } else { "Unverified device!".to_string() }>
                                    {if n == 0 {
                                        view! { <span class="dot dot-off"></span> }.into_any()
                                    } else if ok {
                                        view! { <Icon svg=ic::SECURITY size=16 class="ok"/> }.into_any()
                                    } else {
                                        view! { <Icon svg=ic::ALERT size=16 class="warn"/> }.into_any()
                                    }}
                                </span>
                            </li>
                        }
                    }
                </For>
            </ul>
        </aside>
    }
}
