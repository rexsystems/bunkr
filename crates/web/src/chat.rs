use std::collections::HashMap;

use bunkr_core::MsgBody;
use bunkr_proto::ChannelId;
use futures::channel::oneshot;
use leptos::prelude::*;
use leptos::task::spawn_local;
use wasm_bindgen::JsCast;

use crate::app::ctx;
use crate::engine::{Cmd, EngineHandle, MsgView};
use crate::icons as ic;
use crate::util::{fmt_day, fmt_time, toasts, ttl_label, Avatar, Icon};

#[derive(Clone, Copy)]
pub struct View {
    pub selected: RwSignal<Option<ChannelId>>,
    pub drawer: RwSignal<bool>,
    pub members: RwSignal<bool>,
    pub settings: RwSignal<bool>,
    pub seen: RwSignal<HashMap<ChannelId, i64>>,
    pub handle: StoredValue<EngineHandle>,
}

pub fn view_ctx() -> View {
    expect_context::<View>()
}

#[component]
pub fn MainView(handle: EngineHandle) -> impl IntoView {
    let c = ctx();
    let v = View {
        selected: RwSignal::new(None),
        drawer: RwSignal::new(false),
        members: RwSignal::new(false),
        settings: RwSignal::new(false),
        seen: RwSignal::new(HashMap::new()),
        handle: StoredValue::new(handle),
    };
    provide_context(v);

    // Pick the first channel once channels arrive.
    Effect::new(move |_| {
        let ui = c.ui.get();
        let sel = v.selected.get_untracked();
        if sel
            .map(|s| !ui.channels.iter().any(|c| c.id == s))
            .unwrap_or(true)
        {
            v.selected.set(ui.channels.first().map(|c| c.id));
        }
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
        </div>
    }
}

#[component]
fn Sidebar() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let unread = move |id: ChannelId| -> usize {
        let ui = c.ui.get();
        let seen = v.seen.get().get(&id).copied().unwrap_or(0);
        ui.messages
            .get(&id)
            .map(|m| {
                m.iter()
                    .filter(|m| m.seq > seen && !m.mine && matches!(m.body, MsgBody::Text(_)))
                    .count()
            })
            .unwrap_or(0)
    };
    view! {
        <nav class="sidebar">
            <div class="server-head">
                <div class="logo-mark"><Icon svg=ic::LOCK size=20/></div>
                <div class="server-meta">
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
            </div>
            <div class="section-label">
                <span>"Channels"</span>
            </div>
            <ul class="channel-list">
                <For
                    each=move || c.ui.get().channels
                    key=|ch| (ch.id, ch.name.clone(), ch.joined, ch.ttl_hours)
                    let:ch
                >
                    {
                        let id = ch.id;
                        let ttl = ttl_label(ch.ttl_hours);
                        view! {
                            <li>
                                <button
                                    class="channel"
                                    class:active=move || v.selected.get() == Some(id)
                                    class:unread={move || unread(id) > 0}
                                    on:click=move |_| {
                                        v.selected.set(Some(id));
                                        v.drawer.set(false);
                                    }
                                >
                                    <Icon svg=ic::HASHTAG size=18 class="ch-hash"/>
                                    <span class="ch-name">{ch.name.clone()}</span>
                                    {ttl.map(|t| view! { <span class="ch-ttl mono" title="Disappearing messages"><Icon svg=ic::TIMER size=12/>{t}</span> })}
                                    {(!ch.joined).then(|| view! { <span class="ch-joining" title="Waiting for a member to let this device in"><span class="spinner xs"></span></span> })}
                                    <Show when=move || { unread(id) > 0 && v.selected.get() != Some(id) }>
                                        <span class="badge">{move || unread(id).min(99)}</span>
                                    </Show>
                                </button>
                            </li>
                        }
                    }
                </For>
            </ul>
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
fn ChatPane() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let chan = move || {
        let sel = v.selected.get()?;
        c.ui.get().channels.into_iter().find(|ch| ch.id == sel)
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

    let scroll_bottom = move || {
        if let Some(el) = scroller.try_get_untracked().flatten() {
            el.set_scroll_top(el.scroll_height());
        }
    };
    // Follow new messages when already at the bottom.
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
    let on_scroll = move |_| {
        if let Some(el) = scroller.try_get_untracked().flatten() {
            let near = el.scroll_height() - el.scroll_top() - el.client_height() < 80;
            stick.set(near);
            if near {
                show_jump.set(false);
            }
        }
    };

    view! {
        <section class="chat">
            <header class="chat-head">
                <button class="icon-btn only-mobile" aria-label="Channels" on:click=move |_| v.drawer.set(true)>
                    <Icon svg=ic::MENU size=22/>
                </button>
                <Icon svg=ic::HASHTAG size=22 class="head-hash"/>
                <div class="head-title">
                    <h1>{move || chan().map(|c| c.name).unwrap_or_default()}</h1>
                    <span class="head-topic">{move || chan().map(|c| c.topic).unwrap_or_default()}</span>
                </div>
                <div class="head-actions">
                    {move || {
                        let sel = v.selected.get()?;
                        let code = c.ui.get().epoch_codes.get(&sel).cloned()?;
                        Some(view! {
                            <div class="e2ee-pill" title="Security code for this channel's current encryption epoch. Everyone in the channel sees the same code; compare it out-of-band to rule out a man-in-the-middle.">
                                <Icon svg=ic::SECURITY size=16/>
                                <span class="mono">{code}</span>
                            </div>
                        })
                    }}
                    <button class="icon-btn" aria-label="Members" title="Members" class:active=move || v.members.get() on:click=move |_| v.members.update(|m| *m = !*m)>
                        <Icon svg=ic::USERS size=20/>
                    </button>
                </div>
            </header>
            <div class="messages" node_ref=scroller on:scroll=on_scroll>
                <div class="messages-inner">
                    <ChannelIntro/>
                    <For
                        each=move || grouped(messages.get())
                        key=|g| (g.key.clone(), g.items.len(), g.items.last().map(|m| m.seq))
                        let:g
                    >
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
            <Composer/>
        </section>
    }
}

#[component]
fn ChannelIntro() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let chan = move || {
        let sel = v.selected.get()?;
        c.ui.get().channels.into_iter().find(|ch| ch.id == sel)
    };
    view! {
        <div class="intro">
            <div class="intro-icon"><Icon svg=ic::CHAT_LOCK size=30/></div>
            <h2>{move || format!("Welcome to #{}", chan().map(|c| c.name).unwrap_or_default())}</h2>
            <p class="muted">
                "Messages here are end-to-end encrypted with MLS and a post-quantum hybrid key exchange. "
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
        let system = !matches!(m.body, MsgBody::Text(_));
        let joinable = out.last().map(|g| {
            !new_day
                && !g.system
                && !system
                && g.items[0].user_id == m.user_id
                && m.ts - g.items.last().unwrap().ts < 5 * 60_000
        });
        if joinable == Some(true) {
            out.last_mut().unwrap().items.push(m);
        } else {
            out.push(Group {
                key: format!("{}", m.seq),
                day: new_day.then(|| fmt_day(m.ts)),
                system,
                items: vec![m],
            });
        }
    }
    out
}

#[component]
fn MessageGroup(g: Group) -> impl IntoView {
    let c = ctx();
    let is_admin = move || c.ui.get().is_admin;
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
                    MsgBody::Undecryptable => (
                        ic::ALERT,
                        "A message couldn't be decrypted on this device".to_string(),
                    ),
                    MsgBody::Text(t) => (ic::INFO, t.clone()),
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
        .map(|m| {
            let seq = m.seq;
            let text = match m.body {
                MsgBody::Text(t) => t,
                _ => String::new(),
            };
            let del = move |_| {
                let http = c.http.get_value();
                let t = toasts();
                spawn_local(async move {
                    match bunkr_core::call_ok::<()>(&http, "DELETE", &format!("/api/admin/log/{seq}"), bunkr_core::NO_BODY).await {
                        Ok(()) => t.ok("Message deleted"),
                        Err(e) => t.err(e.to_string()),
                    }
                });
            };
            view! {
                <div class="line">
                    <span class="line-time mono">{fmt_time(m.ts)}</span>
                    <div class="line-text">{linkify(&text)}</div>
                    <Show when=is_admin>
                        <button class="line-del icon-btn sm" title="Delete for everyone" on:click=del>
                            <Icon svg=ic::DELETE size=16/>
                        </button>
                    </Show>
                </div>
            }
        })
        .collect_view();
    view! {
        {day}
        <article class="group" class:mine=first.mine>
            <Avatar name=first.username.clone() size=38/>
            <div class="group-body">
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

/// Turn http(s) URLs into links (rel=noopener noreferrer), everything else text.
fn linkify(text: &str) -> impl IntoView {
    let mut parts = vec![];
    for (i, word) in text.split_inclusive(char::is_whitespace).enumerate() {
        let trimmed = word.trim_end();
        let tail = &word[trimmed.len()..];
        if (trimmed.starts_with("https://") || trimmed.starts_with("http://")) && trimmed.len() > 10
        {
            parts.push(
                view! {
                    <a href=trimmed.to_string() target="_blank" rel="noopener noreferrer nofollow">{trimmed.to_string()}</a>
                    {tail.to_string()}
                }
                .into_any(),
            );
        } else {
            let _ = i;
            parts.push(view! { {word.to_string()} }.into_any());
        }
    }
    parts
}

#[component]
fn Composer() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let text = RwSignal::new(String::new());
    let sending = RwSignal::new(false);
    let area: NodeRef<leptos::html::Textarea> = NodeRef::new();
    let joined = move || {
        let sel = v.selected.get();
        c.ui.get()
            .channels
            .iter()
            .find(|ch| Some(ch.id) == sel)
            .map(|ch| ch.joined)
            .unwrap_or(false)
    };
    let name = move || {
        let sel = v.selected.get();
        c.ui.get()
            .channels
            .iter()
            .find(|ch| Some(ch.id) == sel)
            .map(|ch| ch.name.clone())
            .unwrap_or_default()
    };
    let resize = move || {
        if let Some(el) = area.try_get_untracked().flatten() {
            let el: web_sys::HtmlElement = el.unchecked_into();
            let _ = el.style().set_property("height", "auto");
            let h = el.scroll_height().min(220);
            let _ = el.style().set_property("height", &format!("{h}px"));
        }
    };
    let send = move || {
        let body = text.get_untracked();
        if body.trim().is_empty() || sending.get_untracked() {
            return;
        }
        let Some(cid) = v.selected.get_untracked() else {
            return;
        };
        let (tx, rx) = oneshot::channel();
        v.handle.get_value().send(Cmd::Send(cid, body, tx));
        text.set(String::new());
        request_animation_frame(resize);
        sending.set(true);
        let t = toasts();
        spawn_local(async move {
            if let Ok(Err(e)) = rx.await {
                t.err(e);
            }
            sending.set(false);
        });
    };
    view! {
        <div class="composer-wrap">
            <Show
                when=joined
                fallback=|| view! {
                    <div class="composer-wait">
                        <span class="spinner sm"></span>
                        <span>"Securing this device… a member's app will add you to the encrypted group automatically."</span>
                    </div>
                }
            >
                <form class="composer" on:submit=move |e| { e.prevent_default(); send(); }>
                    <textarea
                        node_ref=area
                        rows="1"
                        maxlength="4000"
                        placeholder=move || format!("Message #{}", name())
                        prop:value=move || text.get()
                        on:input=move |e| { text.set(event_target_value(&e)); resize(); }
                        on:keydown=move |e: web_sys::KeyboardEvent| {
                            if e.key() == "Enter" && !e.shift_key() && !e.is_composing() {
                                e.prevent_default();
                                send();
                            }
                        }
                    ></textarea>
                    <button
                        type="submit"
                        class="send"
                        aria-label="Send"
                        disabled=move || text.get().trim().is_empty()
                    >
                        <Icon svg=ic::SEND size=20/>
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

#[component]
fn MembersPanel() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let rows = move || {
        let ui = c.ui.get();
        let Some(sel) = v.selected.get() else {
            return vec![];
        };
        let devs = ui.members.get(&sel).cloned().unwrap_or_default();
        let mut users: Vec<_> = ui
            .users
            .iter()
            .map(|u| {
                let mine: Vec<_> = devs.iter().filter(|(uid, _, _)| *uid == u.id).collect();
                let verified = !mine.is_empty() && mine.iter().all(|(_, _, ok)| *ok);
                (u.clone(), mine.len(), verified)
            })
            .collect();
        users.sort_by_key(|(u, n, _)| (*n == 0, !u.is_admin, u.username.clone()));
        users
    };
    view! {
        <aside class="members">
            <header class="members-head">
                <span>"Members"</span>
                <button class="icon-btn" aria-label="Close" on:click=move |_| v.members.set(false)><Icon svg=ic::CLOSE size=18/></button>
            </header>
            <ul>
                <For each=rows key=|(u, n, ok)| (u.id, *n, *ok, u.key_changed, u.is_admin) let:row>
                    {
                        let (u, n, ok) = row;
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
                                    <div class="member-sub mono" title="Account key fingerprint — compare in person to verify">
                                        {fp.split(' ').take(3).collect::<Vec<_>>().join(" ")}
                                    </div>
                                    {u.key_changed.then(|| view! {
                                        <button class="tag tag-warn" title="This user's identity key changed (they reset their password). Click to acknowledge." on:click=move |_| v.handle.get_value().send(Cmd::AckKeyChange(uid))>
                                            <Icon svg=ic::ALERT size=12/>"new identity"
                                        </button>
                                    })}
                                </div>
                                <span class="member-state" title=move || if n == 0 { "No device in this channel".to_string() } else if ok { format!("{n} verified device(s)") } else { "Unverified device!".to_string() }>
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
