use bunkr_core::{call_ok, NO_BODY};
use bunkr_proto::{AdminUsersResp, ChannelUpsert, SettingsReq};
use futures::channel::oneshot;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::app::{ctx, PasswordInput, StrengthMeter};
use crate::chat::view_ctx;
use crate::engine::Cmd;
use crate::icons as ic;
use crate::net;
use crate::util::{toasts, ttl_label, ttl_options, Avatar, Dropdown, Icon};

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Account,
    Notifications,
    Security,
    Users,
    Channels,
}

#[component]
pub fn Settings() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let tab = RwSignal::new(Tab::Account);
    let close = move |_| v.settings.set(false);
    let tab_btn = move |t: Tab, label: &'static str, icon: &'static str| {
        view! {
            <button class="tab" class:active=move || tab.get() == t on:click=move |_| tab.set(t)>
                <Icon svg=icon size=18/>
                <span>{label}</span>
            </button>
        }
    };
    view! {
        <div class="modal-backdrop" on:click=close>
            <div class="modal settings" on:click=|e| e.stop_propagation() role="dialog" aria-modal="true">
                <aside class="settings-nav">
                    <div class="settings-title">"Settings"</div>
                    {tab_btn(Tab::Account, "Account", ic::USER)}
                    {tab_btn(Tab::Notifications, "Notifications", ic::BELL)}
                    {tab_btn(Tab::Security, "Security", ic::SHIELD_KEY)}
                    <Show when=move || c.ui.get().is_admin>
                        <div class="settings-title">"Admin"</div>
                        {tab_btn(Tab::Users, "Users", ic::USERS)}
                        {tab_btn(Tab::Channels, "Channels", ic::HASHTAG)}
                    </Show>
                </aside>
                <div class="settings-body">
                    <button class="icon-btn modal-close" aria-label="Close" on:click=close><Icon svg=ic::CLOSE size=20/></button>
                    {move || match tab.get() {
                        Tab::Account => view! { <AccountTab/> }.into_any(),
                        Tab::Notifications => view! { <NotificationsTab/> }.into_any(),
                        Tab::Security => view! { <SecurityTab/> }.into_any(),
                        Tab::Users => view! { <UsersTab/> }.into_any(),
                        Tab::Channels => view! { <ChannelsTab/> }.into_any(),
                    }}
                </div>
            </div>
        </div>
    }
}

#[component]
fn AccountTab() -> impl IntoView {
    let c = ctx();
    let v = view_ctx();
    let t = toasts();
    let current = RwSignal::new(String::new());
    let new = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let understood = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let change = move |e: leptos::ev::SubmitEvent| {
        e.prevent_default();
        let n = new.get_untracked();
        if let Err(e) = bunkr_core::session::check_password_strength(&n) {
            t.err(e);
            return;
        }
        if n != confirm.get_untracked() {
            t.err("New passwords don't match");
            return;
        }
        if !understood.get_untracked() {
            t.err("Tick the box: you understand everything will be reset");
            return;
        }
        busy.set(true);
        let (tx, rx) = oneshot::channel();
        v.handle.get_value().send(Cmd::ChangePassword {
            current: current.get_untracked(),
            new: n,
            reply: tx,
        });
        spawn_local(async move {
            if let Ok(Err(e)) = rx.await {
                t.err(e);
                busy.set(false);
            }
        });
    };
    let fp = move || c.ui.get().fingerprint;
    view! {
        <h2>"Account"</h2>
        <div class="card row gap-12">
            <Avatar name=c.ui.get_untracked().username size=52/>
            <div class="grow">
                <div class="big-name">{move || format!("@{}", c.ui.get().username)}</div>
                <div class="muted mono small">{move || format!("user #{} · device #{}", c.ui.get().user_id, c.ui.get().device_id)}</div>
            </div>
            <button class="btn btn-ghost" on:click=move |_| v.handle.get_value().send(Cmd::Logout)>
                <Icon svg=ic::LOGOUT size=18/>
                <span>"Log out"</span>
            </button>
        </div>

        <h3>"Your identity fingerprint"</h3>
        <div class="card">
            <p class="muted small">"Compare this with the people you talk to (in person or on a call). If it matches what they see for you, nobody is in the middle."</p>
            <div class="fingerprint mono">{fp}</div>
            <button class="btn btn-ghost sm" on:click=move |_| { net::copy_to_clipboard(&c.ui.get_untracked().fingerprint); t.ok("Copied"); }>
                <Icon svg=ic::COPY size=16/><span>"Copy"</span>
            </button>
        </div>

        <h3 class="danger-title"><Icon svg=ic::FIRE size=18/>"Change password = total reset"</h3>
        <form class="card card-danger" on:submit=change>
            <p class="small">
                "Changing your password destroys your current identity keys and creates new ones. "
                "Every device is logged out, you are removed from every encrypted channel and rejoin as a new identity. "
                "Your message history on every device is wiped. This cannot be undone."
            </p>
            <label class="field">
                <span class="label">"Current password"</span>
                <PasswordInput value=current placeholder="Current password"/>
            </label>
            <label class="field">
                <span class="label">"New password"</span>
                <PasswordInput value=new placeholder="New password" autocomplete="new-password"/>
                <StrengthMeter pw=new/>
            </label>
            <label class="field">
                <span class="label">"Confirm new password"</span>
                <PasswordInput value=confirm placeholder="Type it again" autocomplete="new-password"/>
            </label>
            <label class="check">
                <input type="checkbox" prop:checked=move || understood.get() on:change=move |e| understood.set(event_target_checked(&e))/>
                <span>"I understand: everything gets wiped and reset."</span>
            </label>
            <button class="btn btn-danger" type="submit" disabled=move || busy.get()>
                {move || if busy.get() { view! { <span class="spinner sm"></span><span>"Resetting…"</span> }.into_any() } else { view! { <Icon svg=ic::FIRE size=18/><span>"Change password & reset everything"</span> }.into_any() }}
            </button>
        </form>

        <h3 class="danger-title"><Icon svg=ic::ALERT size=18/>"Panic"</h3>
        <div class="card card-danger row gap-12">
            <p class="small grow">"Instantly log this device out and wipe all local keys and messages."</p>
            <button class="btn btn-danger" on:click=move |_| {
                net::store_del(net::VAULT_KEY);
                v.handle.get_value().send(Cmd::Logout);
            }>
                <Icon svg=ic::FIRE size=18/><span>"Wipe now"</span>
            </button>
        </div>
    }
}

#[component]
fn SecurityTab() -> impl IntoView {
    let c = ctx();
    let item = |icon: &'static str, title: &'static str, body: &'static str| {
        view! {
            <div class="sec-item">
                <div class="sec-icon"><Icon svg=icon size=20/></div>
                <div>
                    <div class="sec-title">{title}</div>
                    <div class="muted small">{body}</div>
                </div>
            </div>
        }
    };
    view! {
        <h2>"How Bunkr protects you"</h2>
        <div class="sec-grid">
            {item(ic::QUANTUM, "Post-quantum MLS", "Channels are MLS (RFC 9420) groups using a hybrid ML-KEM-768 + X25519 key exchange, AES-256-GCM and Ed25519. Forward secrecy and post-compromise security come built in.")}
            {item(ic::SERVER, "Zero-knowledge server", "The server stores ciphertext only. It does not store who sent a message, IP addresses, emails or exact timestamps (only the hour, for retention).")}
            {item(ic::LOCK_PASSWORD, "Password never leaves the device", "Argon2id (64 MiB, 3 passes) turns your password into two keys: one proves who you are, the other encrypts your keys and stays here.")}
            {item(ic::FINGERPRINT, "Signed devices", "Every device is signed by your account key. Members refuse to add a device whose signature doesn't check out, so the server can't sneak one in.")}
            {item(ic::FIRE, "Reset on password change", "A new password means new identity keys, all devices logged out and all local history wiped.")}
        </div>
        <p class="muted small mono">{move || format!("Server retention: messages are deleted after {} days (or sooner in channels with disappearing messages).", c.ui.get().retention_days)}</p>
        <div class="notice">
            <Icon svg=ic::INFO size=18/>
            <span>"Bunkr has not had an independent security audit yet. It uses well-reviewed libraries (OpenMLS, RustCrypto) but treat it accordingly."</span>
        </div>
    }
}

#[component]
fn UsersTab() -> impl IntoView {
    let c = ctx();
    let t = toasts();
    let data = RwSignal::new(None::<AdminUsersResp>);
    let reload = move || {
        let http = c.http.get_value();
        spawn_local(async move {
            match call_ok::<AdminUsersResp>(&http, "GET", "/api/admin/users", NO_BODY).await {
                Ok(d) => data.set(Some(d)),
                Err(e) => t.err(e.to_string()),
            }
        });
    };
    reload();
    let act = move |method: &'static str, path: String, ok: &'static str| {
        let http = c.http.get_value();
        spawn_local(async move {
            match call_ok::<()>(&http, method, &path, NO_BODY).await {
                Ok(()) => {
                    t.ok(ok);
                    reload();
                }
                Err(e) => t.err(e.to_string()),
            }
        });
    };
    let toggle_reg = move |open: bool| {
        let http = c.http.get_value();
        spawn_local(async move {
            match call_ok::<()>(
                &http,
                "POST",
                "/api/admin/settings",
                Some(&SettingsReq {
                    registration_open: open,
                }),
            )
            .await
            {
                Ok(()) => {
                    t.ok(if open {
                        "Registration opened"
                    } else {
                        "Registration closed"
                    });
                    reload();
                }
                Err(e) => t.err(e.to_string()),
            }
        });
    };
    let me = move || c.ui.get().user_id;
    view! {
        <h2>"Users"</h2>
        {move || data.get().map(|d| {
            let open = d.registration_open;
            view! {
                <div class="card row gap-12">
                    <div class="grow">
                        <div class="sec-title">"Open registration"</div>
                        <div class="muted small">"When off, nobody new can create an account."</div>
                    </div>
                    <button class="switch" class:on=open role="switch" aria-checked=open.to_string() on:click=move |_| toggle_reg(!open)><span></span></button>
                </div>
            }
        })}
        <div class="table">
            {move || data.get().map(|d| d.users.into_iter().map(|u| {
                let id = u.id;
                let is_me = id == me();
                view! {
                    <div class="trow" class:banned=u.banned>
                        <Avatar name=u.username.clone() size=30/>
                        <div class="grow">
                            <div class="member-name">
                                {u.username.clone()}
                                {u.is_admin.then(|| view! { <span class="crown"><Icon svg=ic::CROWN size=13/></span> })}
                                {u.banned.then(|| view! { <span class="tag tag-bad">"banned"</span> })}
                            </div>
                            <div class="muted small mono">{format!("#{id} · {} device(s)", u.devices)}</div>
                        </div>
                        <Show when=move || !is_me>
                            <div class="row gap-4">
                                <button class="icon-btn" title=if u.is_admin { "Remove admin" } else { "Make admin" } on:click=move |_| act("POST", format!("/api/admin/users/{id}/admin"), "Updated")>
                                    <Icon svg=ic::CROWN size=18/>
                                </button>
                                {if u.banned {
                                    view! { <button class="icon-btn" title="Unban" on:click=move |_| act("POST", format!("/api/admin/users/{id}/unban"), "Unbanned")><Icon svg=ic::UNBLOCK size=18/></button> }.into_any()
                                } else {
                                    view! { <button class="icon-btn warn" title="Ban (kicks every device)" on:click=move |_| act("POST", format!("/api/admin/users/{id}/ban"), "Banned")><Icon svg=ic::BLOCK size=18/></button> }.into_any()
                                }}
                                <button class="icon-btn danger" title="Delete account" on:click=move |_| act("DELETE", format!("/api/admin/users/{id}"), "Deleted")>
                                    <Icon svg=ic::DELETE size=18/>
                                </button>
                            </div>
                        </Show>
                    </div>
                }
            }).collect_view())}
        </div>
    }
}

#[component]
fn ChannelsTab() -> impl IntoView {
    let c = ctx();
    let t = toasts();
    let name = RwSignal::new(String::new());
    let topic = RwSignal::new(String::new());
    let ttl = RwSignal::new(0i64);
    let editing = RwSignal::new(None::<i64>);
    let save = move |e: leptos::ev::SubmitEvent| {
        e.prevent_default();
        let http = c.http.get_value();
        let body = ChannelUpsert {
            name: name.get_untracked(),
            topic: topic.get_untracked(),
            ttl_hours: ttl.get_untracked(),
        };
        let (method, path) = match editing.get_untracked() {
            Some(id) => ("PUT", format!("/api/admin/channels/{id}")),
            None => ("POST", "/api/admin/channels".to_string()),
        };
        spawn_local(async move {
            match call_ok::<()>(&http, method, &path, Some(&body)).await {
                Ok(()) => {
                    t.ok("Saved");
                    name.set(String::new());
                    topic.set(String::new());
                    ttl.set(0);
                    editing.set(None);
                }
                Err(e) => t.err(e.to_string()),
            }
        });
    };
    let del = move |id: i64| {
        let http = c.http.get_value();
        spawn_local(async move {
            match call_ok::<()>(
                &http,
                "DELETE",
                &format!("/api/admin/channels/{id}"),
                NO_BODY,
            )
            .await
            {
                Ok(()) => t.ok("Channel deleted"),
                Err(e) => t.err(e.to_string()),
            }
        });
    };
    let public = move || {
        let mut v = c.ui.get().channels;
        v.retain(|ch| !ch.dm);
        v
    };
    view! {
        <h2>"Channels"</h2>
        <p class="muted small">"Everyone on the server is in every channel. Direct messages are private and not listed here."</p>
        <div class="table">
            <For each=public key=|ch| (ch.id, ch.name.clone(), ch.topic.clone(), ch.ttl_hours) let:ch>
                {
                    let id = ch.id;
                    let ch2 = ch.clone();
                    view! {
                        <div class="trow">
                            <Icon svg=ic::HASHTAG size=18 class="muted"/>
                            <div class="grow">
                                <div class="member-name">
                                    {ch.name.clone()}
                                    {ttl_label(ch.ttl_hours).map(|l| view! { <span class="tag"><Icon svg=ic::TIMER size=12/>{l}</span> })}
                                </div>
                                <div class="muted small">{ch.topic.clone()}</div>
                            </div>
                            <button class="icon-btn" title="Edit" on:click=move |_| {
                                editing.set(Some(id));
                                name.set(ch2.name.clone());
                                topic.set(ch2.topic.clone());
                                ttl.set(ch2.ttl_hours);
                            }><Icon svg=ic::EDIT size=18/></button>
                            <button class="icon-btn danger" title="Delete channel" on:click=move |_| del(id)><Icon svg=ic::DELETE size=18/></button>
                        </div>
                    }
                }
            </For>
        </div>
        <h3>{move || if editing.get().is_some() { "Edit channel" } else { "New channel" }}</h3>
        <form class="card" on:submit=save>
            <div class="grid-2">
                <label class="field">
                    <span class="label">"Name"</span>
                    <input class="input" placeholder="announcements" prop:value=move || name.get() on:input=move |e| name.set(event_target_value(&e))/>
                </label>
                <div class="field">
                    <span class="label">"Disappearing messages"</span>
                    <Dropdown
                        options=ttl_options()
                        value=ttl
                        on_pick=move |h| ttl.set(h)
                        label="Disappearing messages"
                    />
                </div>
            </div>
            <label class="field">
                <span class="label">"Topic"</span>
                <input class="input" placeholder="What's this channel about?" prop:value=move || topic.get() on:input=move |e| topic.set(event_target_value(&e))/>
            </label>
            <div class="row gap-8">
                <button class="btn btn-primary" type="submit"><Icon svg=ic::ADD size=18/><span>{move || if editing.get().is_some() { "Save" } else { "Create channel" }}</span></button>
                <Show when=move || editing.get().is_some()>
                    <button class="btn btn-ghost" type="button" on:click=move |_| { editing.set(None); name.set(String::new()); topic.set(String::new()); ttl.set(0); }>"Cancel"</button>
                </Show>
            </div>
        </form>
    }
}

#[component]
fn NotificationsTab() -> impl IntoView {
    use crate::notify;
    let c = ctx();
    let t = toasts();
    let pref = RwSignal::new(notify::pref());
    let previews = RwSignal::new(notify::previews());
    let perm = RwSignal::new(notify::permission());
    let push = RwSignal::new(net::store_get(notify::PUSH_KEY).unwrap_or_else(|| "off".into()));
    let push_busy = RwSignal::new(false);
    let server_push = move || c.info.get().map(|i| i.push).unwrap_or(false);
    let set_pref = move |v: &'static str| {
        net::store_set(notify::PREF_KEY, v);
        pref.set(v.to_string());
        if v != "off" && perm.get_untracked() != "granted" {
            spawn_local(async move {
                let p = notify::request_permission().await;
                perm.set(p);
            });
        }
    };
    let set_push = move |scope: &'static str| {
        if push_busy.get_untracked() {
            return;
        }
        push_busy.set(true);
        let http = c.http.get_value();
        spawn_local(async move {
            let res: Result<(), String> = async {
                if scope == "off" {
                    let _ =
                        bunkr_core::call_ok::<()>(&http, "DELETE", "/api/push/subscribe", NO_BODY)
                            .await;
                    notify::push_unsubscribe().await;
                    return Ok(());
                }
                if notify::permission() != "granted"
                    && notify::request_permission().await != "granted"
                {
                    return Err("Notifications are blocked for this site".into());
                }
                let vapid: bunkr_proto::VapidResp =
                    call_ok(&http, "GET", "/api/push/vapid", NO_BODY)
                        .await
                        .map_err(|e| e.to_string())?;
                let endpoint = notify::push_subscribe(&vapid.public_key).await?;
                call_ok::<()>(
                    &http,
                    "POST",
                    "/api/push/subscribe",
                    Some(&bunkr_proto::PushSubscribeReq {
                        endpoint,
                        scope: scope.into(),
                    }),
                )
                .await
                .map_err(|e| e.to_string())
            }
            .await;
            match res {
                Ok(()) => {
                    net::store_set(notify::PUSH_KEY, scope);
                    push.set(scope.into());
                    t.ok(if scope == "off" {
                        "Push turned off"
                    } else {
                        "Push turned on"
                    });
                }
                Err(e) => t.err(e),
            }
            perm.set(notify::permission());
            push_busy.set(false);
        });
    };
    view! {
        <h2>"Notifications"</h2>
        <h3>"While Bunkr is open"</h3>
        <div class="card">
            <div class="seg seg-3">
                <button type="button" class:active=move || pref.get() == "all" on:click=move |_| set_pref("all")>"All messages"</button>
                <button type="button" class:active=move || pref.get() == "important" on:click=move |_| set_pref("important")>"DMs & @mentions"</button>
                <button type="button" class:active=move || pref.get() == "off" on:click=move |_| set_pref("off")>"Off"</button>
            </div>
            <Show when=move || perm.get() == "denied">
                <div class="notice notice-warn"><Icon svg=ic::ALERT size=18/><span>"Notifications are blocked in your browser settings for this site."</span></div>
            </Show>
            <label class="check">
                <input type="checkbox" prop:checked=move || previews.get() on:change=move |e| {
                    let on = event_target_checked(&e);
                    net::store_set(notify::PREVIEW_KEY, if on { "1" } else { "0" });
                    previews.set(on);
                }/>
                <span>"Show message text in notifications"</span>
            </label>
            <p class="muted small">"Off by default: your OS may show notification text on the lock screen and keep it in its notification history, outside Bunkr's encryption."</p>
        </div>
        <h3>"When Bunkr is closed (web push)"</h3>
        <div class="card">
            {move || if !notify::push_supported() {
                view! { <p class="muted small">"Web push works in the browser version (installed to your home screen on iPhone). The desktop app notifies you while it's running."</p> }.into_any()
            } else if !server_push() {
                view! { <p class="muted small">"Push is disabled on this server."</p> }.into_any()
            } else {
                view! {
                    <div class="seg seg-3">
                        <button type="button" disabled=move || push_busy.get() class:active=move || push.get() == "all" on:click=move |_| set_push("all")>"Everything"</button>
                        <button type="button" disabled=move || push_busy.get() class:active=move || push.get() == "dm" on:click=move |_| set_push("dm")>"DMs only"</button>
                        <button type="button" disabled=move || push_busy.get() class:active=move || push.get() == "off" on:click=move |_| set_push("off")>"Off"</button>
                    </div>
                }.into_any()
            }}
            <p class="muted small">"Pushes are empty wake-up signals: they contain no text, sender or channel. Your device then shows a generic “new encrypted messages” notice. The push provider (Google, Mozilla, Apple or Microsoft) only learns that something arrived, and roughly when."</p>
        </div>
    }
}
