//! The engine owns the device keys and runs every crypto/network operation
//! one at a time. The UI only ever sees plain snapshots (`Ui`).

use std::collections::{BTreeSet, HashMap};

use bunkr_core::{crypto::PasswordKeys, session, Device, Error, MsgBody};
use bunkr_proto::{ChannelId, DeviceId, Seq, ServerWs, UserId};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use wasm_bindgen::{prelude::*, JsCast};

use crate::net::{self, WebHttp};

#[derive(Clone, Debug, PartialEq)]
pub struct MsgView {
    pub seq: Seq,
    pub user_id: UserId,
    pub username: String,
    pub ts: i64,
    pub body: MsgBody,
    pub unverified: bool,
    pub mine: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChanView {
    pub id: ChannelId,
    pub name: String,
    pub topic: String,
    pub ttl_hours: i64,
    pub joined: bool,
    pub last_seq: Seq,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UserView {
    pub id: UserId,
    pub username: String,
    pub is_admin: bool,
    pub fingerprint: String,
    pub key_changed: bool,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Ui {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub username: String,
    pub is_admin: bool,
    pub fingerprint: String,
    pub channels: Vec<ChanView>,
    pub messages: HashMap<ChannelId, Vec<MsgView>>,
    pub users: Vec<UserView>,
    /// channel -> (user, device, verified)
    pub members: HashMap<ChannelId, Vec<(UserId, DeviceId, bool)>>,
    pub epoch_codes: HashMap<ChannelId, String>,
    pub online: bool,
    pub server_name: String,
    pub retention_days: u32,
}

pub enum Cmd {
    Tick,
    Event(ServerWs),
    Send(ChannelId, String, oneshot::Sender<Result<(), String>>),
    Online(bool),
    AckKeyChange(UserId),
    ChangePassword {
        current: String,
        new: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Logout,
}

/// How the engine ended.
#[derive(Clone, Debug, PartialEq)]
pub enum Ended {
    /// Session killed by the server (password change, ban, logout elsewhere).
    Revoked,
    PasswordChanged,
    LoggedOut,
}

pub struct Engine {
    pub http: WebHttp,
    pub dev: Device,
    pub keys: PasswordKeys,
    pub vault: session::Vault,
    pub ui: RwSignal<Ui>,
    pub retention_days: u32,
    pub server_name: String,
    online: bool,
    waiting: std::rc::Rc<std::cell::Cell<bool>>,
}

#[derive(Clone)]
pub struct EngineHandle {
    pub tx: mpsc::UnboundedSender<Cmd>,
}

impl EngineHandle {
    pub fn send(&self, c: Cmd) {
        let _ = self.tx.unbounded_send(c);
    }
}

impl Engine {
    pub fn new(
        http: WebHttp,
        dev: Device,
        keys: PasswordKeys,
        vault: session::Vault,
        ui: RwSignal<Ui>,
        server_name: String,
        retention_days: u32,
    ) -> Self {
        http_set_token(&http, &dev);
        Engine {
            http,
            dev,
            keys,
            vault,
            ui,
            retention_days,
            server_name,
            online: false,
            waiting: Default::default(),
        }
    }

    /// Start the engine loop and its WebSocket. `on_end` fires once.
    pub fn start(self, on_end: impl Fn(Ended) + 'static) -> EngineHandle {
        let (tx, rx) = mpsc::unbounded();
        let handle = EngineHandle { tx: tx.clone() };
        let alive = std::rc::Rc::new(std::cell::Cell::new(true));
        spawn_ws(self.http.clone(), tx.clone(), alive.clone());
        // Periodic safety-net reconcile.
        {
            let tx = tx.clone();
            let alive = alive.clone();
            let waiting = self.waiting.clone();
            spawn_local(async move {
                let mut since = 0;
                while alive.get() {
                    net::sleep(3_000).await;
                    since += 3_000;
                    // Poll faster while a channel still waits to be joined.
                    if since >= 45_000 || (waiting.get() && since >= 6_000) {
                        since = 0;
                        let _ = tx.unbounded_send(Cmd::Tick);
                    }
                }
            });
        }
        let _ = tx.unbounded_send(Cmd::Tick);
        spawn_local(async move {
            let ended = self.run(rx).await;
            alive.set(false);
            on_end(ended);
        });
        handle
    }

    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<Cmd>) -> Ended {
        self.publish();
        while let Some(first) = rx.next().await {
            // Drain and coalesce whatever queued up meanwhile.
            let mut batch = vec![first];
            while let Ok(Some(c)) = rx.try_recv().map(Some) {
                batch.push(c);
            }
            let mut tick = false;
            let mut syncs: BTreeSet<ChannelId> = BTreeSet::new();
            let mut pendings: BTreeSet<ChannelId> = BTreeSet::new();
            let mut welcomes = false;
            let mut others = vec![];
            for c in batch {
                match c {
                    Cmd::Tick => tick = true,
                    Cmd::Event(ServerWs::State) | Cmd::Event(ServerWs::Ready) => tick = true,
                    Cmd::Event(ServerWs::Log { channel_id, .. }) => {
                        syncs.insert(channel_id);
                    }
                    Cmd::Event(ServerWs::Pending { channel_id }) => {
                        pendings.insert(channel_id);
                    }
                    Cmd::Event(ServerWs::Welcome { .. }) => welcomes = true,
                    Cmd::Event(ServerWs::Deleted { channel_id, seq }) => {
                        self.dev.delete_local(channel_id, seq)
                    }
                    Cmd::Event(ServerWs::Revoked) => {
                        self.wipe();
                        return Ended::Revoked;
                    }
                    Cmd::Event(ServerWs::Pong) => {}
                    other => others.push(other),
                }
            }
            let now = net::now_ms();
            let mut result: Result<(), Error> = Ok(());
            if tick {
                result = self.dev.tick(&self.http, now).await.map(|st| {
                    let _ = st;
                });
            } else {
                if welcomes {
                    result = self.dev.process_welcomes(&self.http, now).await;
                }
                for cid in &syncs {
                    if result.is_ok() && self.dev.is_joined(*cid) {
                        result = self.dev.sync_channel(&self.http, *cid, now).await;
                    }
                }
                for cid in &pendings {
                    if result.is_ok() {
                        result = self.dev.handle_pending(&self.http, *cid, now).await;
                    }
                }
            }
            if let Err(Error::Revoked) = result {
                self.wipe();
                return Ended::Revoked;
            }
            for c in others {
                match c {
                    Cmd::Send(cid, text, reply) => {
                        let r = self.dev.send_text(&self.http, cid, &text, now).await;
                        if let Err(Error::Revoked) = r {
                            self.wipe();
                            return Ended::Revoked;
                        }
                        let _ = reply.send(r.map_err(|e| e.to_string()));
                    }
                    Cmd::Online(o) => self.online = o,
                    Cmd::AckKeyChange(u) => {
                        self.dev.changed.remove(&u);
                    }
                    Cmd::ChangePassword {
                        current,
                        new,
                        reply,
                    } => {
                        // Re-check the current password locally first.
                        let ok =
                            bunkr_core::crypto::derive_password_keys(&current, &self.vault.salt.0)
                                .map(|k| k.auth_key == self.keys.auth_key)
                                .unwrap_or(false);
                        if !ok {
                            let _ = reply.send(Err("Current password is wrong".into()));
                            continue;
                        }
                        match session::change_password(&self.http, &self.keys, &new).await {
                            Ok(()) => {
                                self.wipe();
                                let _ = reply.send(Ok(()));
                                return Ended::PasswordChanged;
                            }
                            Err(e) => {
                                let _ = reply.send(Err(e.to_string()));
                            }
                        }
                    }
                    Cmd::Logout => {
                        let _ = session::logout(&self.http).await;
                        self.wipe();
                        return Ended::LoggedOut;
                    }
                    _ => {}
                }
            }
            self.dev.purge(now, self.retention_days);
            self.persist();
            self.publish();
        }
        Ended::LoggedOut
    }

    fn persist(&mut self) {
        self.vault.reseal(&self.keys, &self.dev);
        if let Ok(s) = serde_json::to_string(&self.vault) {
            net::store_set(net::VAULT_KEY, &s);
        }
    }

    fn wipe(&mut self) {
        net::store_del(net::VAULT_KEY);
    }

    fn publish(&self) {
        let d = &self.dev;
        let mut messages = HashMap::new();
        let mut members = HashMap::new();
        let mut epoch_codes = HashMap::new();
        for c in &d.channels {
            let msgs = d
                .chans
                .get(&c.id)
                .map(|ch| {
                    let mut v: Vec<MsgView> = ch
                        .messages
                        .iter()
                        .map(|m| MsgView {
                            seq: m.seq,
                            user_id: m.user_id,
                            username: d.username_of(m.user_id),
                            ts: m.ts,
                            body: m.body.clone(),
                            unverified: m.unverified,
                            mine: m.user_id == d.user_id && m.device_id == d.device_id,
                        })
                        .collect();
                    v.sort_by_key(|m| m.seq);
                    v
                })
                .unwrap_or_default();
            messages.insert(c.id, msgs);
            members.insert(c.id, d.member_devices(c.id));
            if let Some(code) = d.epoch_code(c.id) {
                epoch_codes.insert(c.id, code);
            }
        }
        let ui = Ui {
            user_id: d.user_id,
            device_id: d.device_id,
            username: d.username.clone(),
            is_admin: d.is_admin,
            fingerprint: d.own_fingerprint(),
            channels: d
                .channels
                .iter()
                .map(|c| ChanView {
                    id: c.id,
                    name: c.name.clone(),
                    topic: c.topic.clone(),
                    ttl_hours: c.ttl_hours,
                    joined: d.is_joined(c.id),
                    last_seq: d.chans.get(&c.id).map(|x| x.last_seq).unwrap_or(0),
                })
                .collect(),
            messages,
            users: d
                .users
                .values()
                .map(|u| UserView {
                    id: u.id,
                    username: u.username.clone(),
                    is_admin: u.is_admin,
                    fingerprint: d.fingerprint_of(u.id).unwrap_or_default(),
                    key_changed: d.changed.contains_key(&u.id),
                })
                .collect(),
            members,
            epoch_codes,
            online: self.online,
            server_name: self.server_name.clone(),
            retention_days: self.retention_days,
        };
        self.waiting.set(ui.channels.iter().any(|c| !c.joined));
        self.ui.set(ui);
    }
}

fn http_set_token(http: &WebHttp, dev: &Device) {
    use bunkr_core::Http;
    http.set_token(Some(dev.token.clone()));
}

/// Keep a WebSocket open with reconnect + backoff.
fn spawn_ws(
    http: WebHttp,
    tx: mpsc::UnboundedSender<Cmd>,
    alive: std::rc::Rc<std::cell::Cell<bool>>,
) {
    spawn_local(async move {
        let mut backoff = 500;
        while alive.get() {
            let (closed_tx, closed_rx) = oneshot::channel::<()>();
            let closed_tx = std::rc::Rc::new(std::cell::RefCell::new(Some(closed_tx)));
            let Ok(ws) = web_sys::WebSocket::new(&http.ws_url()) else {
                net::sleep(backoff).await;
                continue;
            };
            let token = http.token().unwrap_or_default();
            let ws2 = ws.clone();
            let onopen = Closure::<dyn FnMut()>::new(move || {
                let auth = serde_json::to_string(&bunkr_proto::ClientWs::Auth {
                    token: token.clone(),
                })
                .unwrap();
                let _ = ws2.send_with_str(&auth);
            });
            let tx2 = tx.clone();
            let onmsg = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(
                move |e: web_sys::MessageEvent| {
                    if let Some(s) = e.data().as_string() {
                        if let Ok(ev) = serde_json::from_str::<ServerWs>(&s) {
                            if matches!(ev, ServerWs::Ready) {
                                let _ = tx2.unbounded_send(Cmd::Online(true));
                            }
                            let _ = tx2.unbounded_send(Cmd::Event(ev));
                        }
                    }
                },
            );
            let ct = closed_tx.clone();
            let onclose = Closure::<dyn FnMut()>::new(move || {
                if let Some(t) = ct.borrow_mut().take() {
                    let _ = t.send(());
                }
            });
            ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            ws.set_onmessage(Some(onmsg.as_ref().unchecked_ref()));
            ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
            ws.set_onerror(Some(onclose.as_ref().unchecked_ref()));
            // Keepalive pings while open.
            let ws_ping = ws.clone();
            let alive_ping = alive.clone();
            let ping_alive = std::rc::Rc::new(std::cell::Cell::new(true));
            let pa = ping_alive.clone();
            spawn_local(async move {
                while pa.get() && alive_ping.get() {
                    net::sleep(25_000).await;
                    if ws_ping.ready_state() == web_sys::WebSocket::OPEN {
                        let _ = ws_ping.send_with_str(r#"{"t":"ping"}"#);
                    }
                }
            });
            let opened_at = net::now_ms();
            let _ = closed_rx.await;
            ping_alive.set(false);
            ws.set_onopen(None);
            ws.set_onmessage(None);
            ws.set_onclose(None);
            ws.set_onerror(None);
            let _ = ws.close();
            drop((onopen, onmsg, onclose));
            let _ = tx.unbounded_send(Cmd::Online(false));
            if net::now_ms() - opened_at > 10_000 {
                backoff = 500;
            }
            net::sleep(backoff).await;
            backoff = (backoff * 2).min(15_000);
            let _ = tx.unbounded_send(Cmd::Tick);
        }
    });
}
