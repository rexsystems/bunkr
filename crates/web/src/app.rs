use bunkr_core::{session, Http};
use bunkr_proto::ServerInfo;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::engine::{Ended, Engine, EngineHandle, Live, Ui};
use crate::icons as ic;
use crate::net::{self, WebHttp};
use crate::util::{toasts, Icon, Logo, ToastHost, Toasts};

#[derive(Clone)]
pub enum Phase {
    Boot,
    Auth { notice: Option<String> },
    Unlock { username: String },
    Main(EngineHandle),
}

#[derive(Clone, Copy)]
pub struct Ctx {
    pub phase: RwSignal<Phase>,
    pub info: RwSignal<Option<ServerInfo>>,
    pub ui: RwSignal<Ui>,
    pub live: Live,
    pub http: StoredValue<WebHttp, LocalStorage>,
}

pub fn ctx() -> Ctx {
    expect_context::<Ctx>()
}

#[component]
pub fn App() -> impl IntoView {
    let c = Ctx {
        phase: RwSignal::new(Phase::Boot),
        info: RwSignal::new(None),
        ui: RwSignal::new(Ui::default()),
        live: Live {
            typing: RwSignal::new(Default::default()),
            selected: RwSignal::new(None),
        },
        http: StoredValue::new_local(WebHttp::new(&net::server_base())),
    };
    provide_context(c);
    provide_context(Toasts(RwSignal::new(vec![])));

    net::install_link_handler();
    spawn_local(async move { boot(c).await });

    view! {
        {move || match c.phase.get() {
            Phase::Boot => view! { <Splash/> }.into_any(),
            Phase::Auth { notice } => view! { <AuthScreen notice/> }.into_any(),
            Phase::Unlock { username } => view! { <UnlockScreen username/> }.into_any(),
            Phase::Main(h) => view! { <crate::chat::MainView handle=h/> }.into_any(),
        }}
        <ToastHost/>
    }
}

async fn load_info(c: Ctx) -> Result<ServerInfo, String> {
    let http = c.http.get_value();
    if net::is_desktop() && http.base.is_empty() {
        return Err("Enter your Bunkr server address".into());
    }
    let r: ServerInfo = bunkr_core::call_ok(&http, "GET", "/api/info", bunkr_core::NO_BODY)
        .await
        .map_err(|e| e.to_string())?;
    c.info.set(Some(r.clone()));
    Ok(r)
}

async fn boot(c: Ctx) {
    let _ = load_info(c).await;
    let vault = net::store_get(net::VAULT_KEY)
        .and_then(|s| serde_json::from_str::<session::Vault>(&s).ok());
    match vault {
        Some(v) => c.phase.set(Phase::Unlock {
            username: v.username,
        }),
        None => c.phase.set(Phase::Auth { notice: None }),
    }
}

fn start_engine(
    c: Ctx,
    keys: bunkr_core::crypto::PasswordKeys,
    vault: session::Vault,
    dev: bunkr_core::Device,
) {
    let info = c.info.get_untracked();
    let engine = Engine::new(
        c.http.get_value(),
        dev,
        keys,
        vault,
        c.ui,
        c.live,
        info.as_ref()
            .map(|i| i.name.clone())
            .unwrap_or_else(|| "Bunkr".into()),
        info.map(|i| i.retention_days).unwrap_or(30),
    );
    let phase = c.phase;
    let ui = c.ui;
    let handle = engine.start(move |ended| {
        let notice = match ended {
            Ended::Revoked => Some(
                "Session ended: the password was changed, you were logged out elsewhere, or the account was banned. All local data on this device was wiped.".to_string(),
            ),
            Ended::PasswordChanged => Some(
                "Password changed. Everything was reset: new identity keys, every device logged out. Log in with your new password.".to_string(),
            ),
            Ended::LoggedOut => None,
        };
        phase.set(Phase::Auth { notice });
        ui.set(Ui::default());
    });
    c.phase.set(Phase::Main(handle));
}

#[component]
fn Splash() -> impl IntoView {
    view! {
        <div class="splash">
            <div class="logo-mark big"><Logo size=48/></div>
            <div class="spinner"></div>
        </div>
    }
}

#[component]
fn Brand() -> impl IntoView {
    view! {
        <aside class="brand">
            <div class="brand-top">
                <div class="logo">
                    <div class="logo-mark"><Logo/></div>
                    <span>"bunkr"</span>
                </div>
            </div>
            <div class="brand-copy">
                <h1>"Talk like nobody's listening."<br/><em>"Because nobody is."</em></h1>
                <ul class="brand-points">
                    <li><Icon svg=ic::CHAT_LOCK size=18/><span>"Messages, files and calls are end-to-end encrypted"</span></li>
                    <li><Icon svg=ic::SERVER size=18/><span>"The server can't read anything you send"</span></li>
                    <li><Icon svg=ic::FINGERPRINT size=18/><span>"Your password never leaves this device"</span></li>
                </ul>
            </div>
        </aside>
    }
}

#[component]
pub fn PasswordInput(
    value: RwSignal<String>,
    #[prop(into)] placeholder: String,
    #[prop(default = "current-password")] autocomplete: &'static str,
) -> impl IntoView {
    let show = RwSignal::new(false);
    view! {
        <div class="input-wrap">
            <Icon svg=ic::LOCK_PASSWORD size=18 class="input-icon"/>
            <input
                class="input has-icon"
                type=move || if show.get() { "text" } else { "password" }
                placeholder=placeholder
                autocomplete=autocomplete
                prop:value=move || value.get()
                on:input=move |e| value.set(event_target_value(&e))
                spellcheck="false"
            />
            <button
                type="button"
                class="input-btn"
                aria-label="Show password"
                on:click=move |_| show.update(|s| *s = !*s)
            >
                {move || {
                    if show.get() {
                        view! { <Icon svg=ic::VIEW_OFF size=18/> }
                    } else {
                        view! { <Icon svg=ic::VIEW size=18/> }
                    }
                }}
            </button>
        </div>
    }
}

fn strength(pw: &str) -> (u8, &'static str) {
    if pw.is_empty() {
        return (0, "");
    }
    let len = pw.chars().count();
    let classes = [
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    let score = match (len, classes) {
        (l, _) if l < 10 => 1,
        (l, c) if l >= 20 || (l >= 14 && c >= 3) => 4,
        (l, c) if l >= 12 && c >= 2 => 3,
        _ => 2,
    };
    (
        score,
        ["", "Too short", "Okay", "Strong", "Bunker-grade"][score as usize],
    )
}

#[component]
pub fn StrengthMeter(pw: RwSignal<String>) -> impl IntoView {
    view! {
        <div class="strength" class:hidden=move || pw.get().is_empty()>
            <div class="strength-bars">
                {(1..=4u8)
                    .map(|i| {
                        view! {
                            <span class:on={move || strength(&pw.get()).0 >= i} data-level={move || strength(&pw.get()).0.to_string()}></span>
                        }
                    })
                    .collect_view()}
            </div>
            <span class="strength-label">{move || strength(&pw.get()).1}</span>
        </div>
    }
}

#[component]
fn AuthScreen(notice: Option<String>) -> impl IntoView {
    let c = ctx();
    let t = toasts();
    let register = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let setup_code = RwSignal::new(String::new());
    let server = RwSignal::new(net::store_get(net::SERVER_KEY).unwrap_or_default());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let desktop = net::is_desktop();

    let needs_setup = move || c.info.get().map(|i| i.needs_setup).unwrap_or(false);
    let reg_open = move || c.info.get().map(|i| i.registration_open).unwrap_or(false);
    Effect::new(move |_| {
        if needs_setup() {
            register.set(true);
        }
    });

    let connect_server = move || {
        let url = server
            .get_untracked()
            .trim()
            .trim_end_matches('/')
            .to_string();
        let url = if url.is_empty() || url.starts_with("http") {
            url
        } else {
            format!("https://{url}")
        };
        net::store_set(net::SERVER_KEY, &url);
        c.http.set_value(WebHttp::new(&url));
        spawn_local(async move {
            match load_info(c).await {
                Ok(i) => t.ok(format!("Connected to {}", i.name)),
                Err(e) => t.err(e),
            }
        });
    };

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        error.set(None);
        let is_reg = register.get_untracked();
        let u = username.get_untracked();
        let p = password.get_untracked();
        if is_reg {
            if let Err(e) = session::check_password_strength(&p) {
                error.set(Some(e));
                return;
            }
            if p != confirm.get_untracked() {
                error.set(Some("Passwords don't match".into()));
                return;
            }
        }
        let code = needs_setup().then(|| setup_code.get_untracked());
        busy.set(true);
        spawn_local(async move {
            // Let the spinner paint before Argon2 blocks the thread.
            net::sleep(60).await;
            let http = c.http.get_value();
            let res = if is_reg {
                session::register(&http, &u, &p, code).await
            } else {
                session::login(&http, &u, &p).await
            };
            match res {
                Ok((keys, salt, dev)) => {
                    let vault = session::Vault::seal(&http.base, &keys, &salt, &dev);
                    if let Ok(s) = serde_json::to_string(&vault) {
                        net::store_set(net::VAULT_KEY, &s);
                    }
                    let _ = load_info(c).await;
                    start_engine(c, keys, vault, dev);
                }
                Err(e) => {
                    http.set_token(None);
                    error.set(Some(e.to_string()));
                    busy.set(false);
                }
            }
        });
    };

    view! {
        <div class="auth">
            <Brand/>
            <main class="auth-main">
                <form class="auth-card" on:submit=submit>
                    <div class="auth-logo-sm logo">
                        <div class="logo-mark"><Logo/></div>
                        <span>"bunkr"</span>
                    </div>
                    {notice.map(|n| view! {
                        <div class="notice notice-warn">
                            <Icon svg=ic::FIRE size=18/>
                            <span>{n}</span>
                        </div>
                    })}
                    <Show when=move || desktop>
                        <label class="field">
                            <span class="label">"Server"</span>
                            <div class="row gap-8">
                                <div class="input-wrap grow">
                                    <Icon svg=ic::SERVER size=18 class="input-icon"/>
                                    <input
                                        class="input has-icon mono"
                                        placeholder="chat.example.com"
                                        prop:value=move || server.get()
                                        on:input=move |e| server.set(event_target_value(&e))
                                        on:keydown=move |e: web_sys::KeyboardEvent| {
                                            if e.key() == "Enter" {
                                                e.prevent_default();
                                                connect_server();
                                            }
                                        }
                                    />
                                </div>
                                <button type="button" class="btn btn-ghost" on:click=move |_| connect_server()>"Connect"</button>
                            </div>
                        </label>
                    </Show>
                    <div class="auth-head">
                        <h2>
                            {move || {
                                if needs_setup() {
                                    "Set up your bunker"
                                } else if register.get() {
                                    "Create account"
                                } else {
                                    "Welcome back"
                                }
                            }}
                        </h2>
                        <p class="muted">
                            {move || {
                                if needs_setup() {
                                    "First account becomes the admin. Grab the setup code from the server logs."
                                        .to_string()
                                } else {
                                    format!(
                                        "Sign in to {}",
                                        c.info.get().map(|i| i.name).unwrap_or_else(|| "Bunkr".into()),
                                    )
                                }
                            }}
                        </p>
                    </div>
                    <Show when=move || !needs_setup() && reg_open()>
                        <div class="seg">
                            <button type="button" class:active=move || !register.get() on:click=move |_| register.set(false)>"Log in"</button>
                            <button type="button" class:active=move || register.get() on:click=move |_| register.set(true)>"Register"</button>
                        </div>
                    </Show>
                    <Show when=needs_setup>
                        <label class="field">
                            <span class="label">"Setup code"</span>
                            <div class="input-wrap">
                                <Icon svg=ic::KEY size=18 class="input-icon"/>
                                <input
                                    class="input has-icon mono upper"
                                    placeholder="docker logs bunkr"
                                    autocomplete="off"
                                    prop:value=move || setup_code.get()
                                    on:input=move |e| setup_code.set(event_target_value(&e))
                                />
                            </div>
                        </label>
                    </Show>
                    <label class="field">
                        <span class="label">"Username"</span>
                        <div class="input-wrap">
                            <Icon svg=ic::USER size=18 class="input-icon"/>
                            <input
                                class="input has-icon"
                                placeholder="ghost"
                                autocomplete="username"
                                autocapitalize="none"
                                spellcheck="false"
                                prop:value=move || username.get()
                                on:input=move |e| username.set(event_target_value(&e))
                            />
                        </div>
                    </label>
                    <label class="field">
                        <span class="label">"Password"</span>
                        <PasswordInput
                            value=password
                            placeholder="••••••••••••"
                            autocomplete=if needs_setup() { "new-password" } else { "current-password" }
                        />
                        <Show when=move || register.get()>
                            <StrengthMeter pw=password/>
                        </Show>
                    </label>
                    <Show when=move || register.get()>
                        <label class="field">
                            <span class="label">"Confirm password"</span>
                            <PasswordInput value=confirm placeholder="Type it again" autocomplete="new-password"/>
                        </label>
                        <div class="notice">
                            <Icon svg=ic::ALERT size=18/>
                            <span>
                                "There is no password recovery. Lose it and your account is gone. "
                                "Change it and everything resets."
                            </span>
                        </div>
                    </Show>
                    {move || error.get().map(|e| view! { <div class="form-error"><Icon svg=ic::ALERT size=16/><span>{e}</span></div> })}
                    <button class="btn btn-primary btn-lg" type="submit" disabled=move || busy.get()>
                        {move || {
                            if busy.get() {
                                view! {
                                    <span class="spinner sm"></span>
                                    <span>"Hardening password…"</span>
                                }
                                    .into_any()
                            } else if register.get() {
                                view! {
                                    <Icon svg=ic::SHIELD_KEY size=18/>
                                    <span>{if needs_setup() { "Create admin account" } else { "Create account" }}</span>
                                }
                                    .into_any()
                            } else {
                                view! {
                                    <Icon svg=ic::LOCK size=18/>
                                    <span>"Enter the bunker"</span>
                                }
                                    .into_any()
                            }
                        }}
                    </button>
                    <p class="fineprint">"Your keys are created on this device and never leave it."</p>
                </form>
            </main>
        </div>
    }
}

#[component]
fn UnlockScreen(username: String) -> impl IntoView {
    let c = ctx();
    let password = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let name = username.clone();

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        error.set(None);
        let pw = password.get_untracked();
        spawn_local(async move {
            net::sleep(60).await;
            let vault = net::store_get(net::VAULT_KEY)
                .and_then(|s| serde_json::from_str::<session::Vault>(&s).ok());
            let Some(vault) = vault else {
                c.phase.set(Phase::Auth { notice: None });
                return;
            };
            match vault.open(&pw) {
                Ok((keys, dev)) => {
                    if !vault.server.is_empty() {
                        c.http.set_value(WebHttp::new(&vault.server));
                    }
                    start_engine(c, keys, vault, dev);
                }
                Err(_) => {
                    error.set(Some("Wrong password".into()));
                    busy.set(false);
                }
            }
        });
    };
    let forget = move |_| {
        net::store_del(net::VAULT_KEY);
        c.phase.set(Phase::Auth {
            notice: Some("This device was wiped.".into()),
        });
    };

    view! {
        <div class="auth">
            <Brand/>
            <main class="auth-main">
                <form class="auth-card" on:submit=submit>
                    <div class="auth-logo-sm logo">
                        <div class="logo-mark"><Logo/></div>
                        <span>"bunkr"</span>
                    </div>
                    <div class="unlock-who">
                        <crate::util::Avatar name=name.clone() size=56/>
                        <div>
                            <h2>{format!("@{username}")}</h2>
                            <p class="muted">"Your vault is locked on this device."</p>
                        </div>
                    </div>
                    <label class="field">
                        <span class="label">"Password"</span>
                        <PasswordInput value=password placeholder="Unlock vault"/>
                    </label>
                    {move || error.get().map(|e| view! { <div class="form-error"><Icon svg=ic::ALERT size=16/><span>{e}</span></div> })}
                    <button class="btn btn-primary btn-lg" type="submit" disabled=move || busy.get()>
                        {move || {
                            if busy.get() {
                                view! { <span class="spinner sm"></span><span>"Decrypting vault…"</span> }.into_any()
                            } else {
                                view! { <Icon svg=ic::LOCK size=18/><span>"Unlock"</span> }.into_any()
                            }
                        }}
                    </button>
                    <button type="button" class="btn btn-ghost btn-danger-text" on:click=forget>
                        <Icon svg=ic::FIRE size=18/>
                        <span>"Not you? Wipe this device"</span>
                    </button>
                </form>
            </main>
        </div>
    }
}
