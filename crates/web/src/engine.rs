//! The engine owns the device keys and runs every crypto/network operation
//! one at a time. The UI only ever sees plain snapshots (`Ui`).

use std::collections::{BTreeSet, HashMap};

use bunkr_core::{
    crypto::PasswordKeys,
    device::{Eph, FileRef},
    session, Device, Error, MsgBody,
};
use bunkr_proto::{ChannelId, ChannelKind, DeviceId, Seq, ServerWs, UserId};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use wasm_bindgen::{prelude::*, JsCast};

use crate::net::{self, WebHttp};

#[derive(Clone, Debug, PartialEq)]
pub struct ReplyView {
    pub id: String,
    pub username: String,
    pub snippet: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MsgView {
    pub seq: Seq,
    pub id: String,
    pub user_id: UserId,
    pub username: String,
    pub ts: i64,
    pub body: MsgBody,
    pub unverified: bool,
    pub mine: bool,
    pub edited: bool,
    pub reply: Option<ReplyView>,
    /// (emoji, count, reacted by me)
    pub reactions: Vec<(String, usize, bool)>,
    pub files: Vec<FileRef>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChanView {
    pub id: ChannelId,
    pub name: String,
    pub topic: String,
    pub ttl_hours: i64,
    pub joined: bool,
    pub last_seq: Seq,
    pub dm: bool,
    pub dm_peer: Option<UserId>,
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

impl Ui {
    pub fn chan(&self, id: ChannelId) -> Option<&ChanView> {
        self.channels.iter().find(|c| c.id == id)
    }
    pub fn username(&self, u: UserId) -> String {
        self.users
            .iter()
            .find(|x| x.id == u)
            .map(|x| x.username.clone())
            .unwrap_or_else(|| format!("user#{u}"))
    }
    /// What to show as a channel's title.
    pub fn title(&self, c: &ChanView) -> String {
        match c.dm_peer {
            Some(p) if c.dm => self.username(p),
            _ => c.name.clone(),
        }
    }
}

/// A file picked in the composer, not yet encrypted.
pub struct Outgoing {
    pub bytes: Vec<u8>,
    pub name: String,
    pub mime: String,
    pub dims: Option<(u32, u32)>,
}

pub type Reply<T> = oneshot::Sender<Result<T, String>>;

pub enum Cmd {
    Tick,
    Event(ServerWs),
    Send {
        cid: ChannelId,
        text: String,
        reply_to: Option<String>,
        files: Vec<Outgoing>,
        reply: Reply<()>,
    },
    Edit {
        cid: ChannelId,
        id: String,
        text: String,
        reply: Reply<()>,
    },
    Delete {
        cid: ChannelId,
        id: String,
        reply: Reply<()>,
    },
    React {
        cid: ChannelId,
        id: String,
        emoji: String,
    },
    Typing(ChannelId),
    /// Encrypted call signalling, sent by the call manager.
    Signal(ChannelId, Eph),
    OpenDm(UserId, Reply<ChannelId>),
    Online(bool),
    AckKeyChange(UserId),
    ChangePassword {
        current: String,
        new: String,
        reply: Reply<()>,
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

/// Realtime signals the UI subscribes to.
#[derive(Clone, Copy)]
pub struct Live {
    /// channel -> users typing (with expiry ms)
    pub typing: RwSignal<HashMap<ChannelId, Vec<(UserId, i64)>>>,
    pub selected: RwSignal<Option<ChannelId>>,
}

pub struct Engine {
    pub http: WebHttp,
    pub dev: Device,
    pub keys: PasswordKeys,
    pub vault: session::Vault,
    pub ui: RwSignal<Ui>,
    pub live: Live,
    pub retention_days: u32,
    pub server_name: String,
    online: bool,
    waiting: std::rc::Rc<std::cell::Cell<bool>>,
    /// Highest seq already considered for notifications, per channel.
    notified: HashMap<ChannelId, Seq>,
    started: bool,
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

thread_local! {
    /// Call signals from the engine to the call manager.
    pub static CALL_SINK: std::cell::RefCell<Option<Box<dyn Fn(ChannelId, UserId, DeviceId, bool, Eph)>>> = const { std::cell::RefCell::new(None) };
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        http: WebHttp,
        dev: Device,
        keys: PasswordKeys,
        vault: session::Vault,
        ui: RwSignal<Ui>,
        live: Live,
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
            live,
            retention_days,
            server_name,
            online: false,
            waiting: Default::default(),
            notified: HashMap::new(),
            started: false,
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
            let typing = self.live.typing;
            spawn_local(async move {
                let mut since = 0;
                while alive.get() {
                    net::sleep(3_000).await;
                    since += 3_000;
                    // Expire typing indicators.
                    let now = net::now_ms();
                    typing.update(|m| {
                        for v in m.values_mut() {
                            v.retain(|(_, exp)| *exp > now);
                        }
                        m.retain(|_, v| !v.is_empty());
                    });
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
            while let Ok(c) = rx.try_recv() {
                batch.push(c);
            }
            let mut tick = false;
            let mut syncs: BTreeSet<ChannelId> = BTreeSet::new();
            let mut pendings: BTreeSet<ChannelId> = BTreeSet::new();
            let mut welcomes = false;
            let mut ephemerals = vec![];
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
                    Cmd::Event(ServerWs::Ephemeral { channel_id, data }) => {
                        ephemerals.push((channel_id, data))
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
                result = self.dev.tick(&self.http, now).await.map(|_| ());
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
            for (cid, data) in ephemerals {
                if let Some((u, d, trusted, e)) = self.dev.open_ephemeral(cid, &data.0) {
                    match e {
                        Eph::Typing => {
                            if u != self.dev.user_id {
                                self.live.typing.update(|m| {
                                    let v = m.entry(cid).or_default();
                                    v.retain(|(x, _)| *x != u);
                                    v.push((u, now + 6_000));
                                });
                            }
                        }
                        call @ Eph::Call { .. } => CALL_SINK.with(|s| {
                            if let Some(f) = s.borrow().as_ref() {
                                f(cid, u, d, trusted, call);
                            }
                        }),
                    }
                }
            }
            for c in others {
                let r = self.command(c, now).await;
                match r {
                    Some(end) => return end,
                    None => continue,
                }
            }
            self.dev.purge(now, self.retention_days);
            self.persist();
            self.notify();
            self.publish();
        }
        Ended::LoggedOut
    }

    /// Run one user command. Returns Some(..) when the session ends.
    async fn command(&mut self, c: Cmd, now: i64) -> Option<Ended> {
        macro_rules! done {
            ($reply:expr, $r:expr) => {{
                let r = $r;
                if let Err(Error::Revoked) = &r {
                    self.wipe();
                    return Some(Ended::Revoked);
                }
                let _ = $reply.send(r.map_err(|e| e.to_string()));
            }};
        }
        match c {
            Cmd::Send {
                cid,
                text,
                reply_to,
                files,
                reply,
            } => {
                let mut refs = vec![];
                let mut tokens = vec![];
                for f in files {
                    match self
                        .dev
                        .upload_file(&self.http, cid, &f.bytes, &f.name, &f.mime, f.dims)
                        .await
                    {
                        Ok((r, t)) => {
                            refs.push(r);
                            tokens.push(t);
                        }
                        Err(e) => {
                            done!(reply, Err::<(), _>(e));
                            return None;
                        }
                    }
                }
                done!(
                    reply,
                    self.dev
                        .send_message(&self.http, cid, &text, reply_to, refs, tokens, now)
                        .await
                        .map(|_| ())
                );
            }
            Cmd::Edit {
                cid,
                id,
                text,
                reply,
            } => done!(
                reply,
                self.dev
                    .edit_message(&self.http, cid, &id, &text, now)
                    .await
            ),
            Cmd::Delete { cid, id, reply } => done!(
                reply,
                self.dev.delete_message(&self.http, cid, &id, now).await
            ),
            Cmd::React { cid, id, emoji } => {
                if let Err(Error::Revoked) = self.dev.react(&self.http, cid, &id, &emoji, now).await
                {
                    self.wipe();
                    return Some(Ended::Revoked);
                }
            }
            Cmd::Typing(cid) => {
                let _ = self
                    .dev
                    .send_ephemeral(&self.http, cid, &Eph::Typing, now)
                    .await;
            }
            Cmd::Signal(cid, e) => {
                let _ = self.dev.send_ephemeral(&self.http, cid, &e, now).await;
            }
            Cmd::OpenDm(u, reply) => done!(reply, self.dev.open_dm(&self.http, u, now).await),
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
                let ok = bunkr_core::crypto::derive_password_keys(&current, &self.vault.salt.0)
                    .map(|k| k.auth_key == self.keys.auth_key)
                    .unwrap_or(false);
                if !ok {
                    let _ = reply.send(Err("Current password is wrong".into()));
                    return None;
                }
                match session::change_password(&self.http, &self.keys, &new).await {
                    Ok(()) => {
                        self.wipe();
                        let _ = reply.send(Ok(()));
                        return Some(Ended::PasswordChanged);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e.to_string()));
                    }
                }
            }
            Cmd::Logout => {
                let _ = session::logout(&self.http).await;
                self.wipe();
                return Some(Ended::LoggedOut);
            }
            Cmd::Tick | Cmd::Event(_) => {}
        }
        None
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

    /// Local notifications for new messages from others.
    fn notify(&mut self) {
        let d = &self.dev;
        let first = !self.started;
        self.started = true;
        let selected = self.live.selected.get_untracked();
        let visible = crate::notify::page_visible();
        for c in &d.channels {
            let Some(ch) = d.chans.get(&c.id) else {
                continue;
            };
            let seen = self.notified.get(&c.id).copied().unwrap_or(0);
            let newest = ch.messages.last().map(|m| m.seq).unwrap_or(0);
            self.notified.insert(c.id, newest.max(seen));
            if first || newest <= seen {
                continue;
            }
            if visible && selected == Some(c.id) {
                continue;
            }
            let dm = c.kind == ChannelKind::Dm;
            let fresh: Vec<_> = ch
                .messages
                .iter()
                .filter(|m| {
                    m.seq > seen && m.user_id != d.user_id && matches!(m.body, MsgBody::Text(_))
                })
                .collect();
            let Some(m) = fresh.last() else { continue };
            let mention =
                matches!(&m.body, MsgBody::Text(t) if t.contains(&format!("@{}", d.username)));
            let who = d.username_of(m.user_id);
            let place = if dm {
                who.clone()
            } else {
                format!("{who} in #{}", c.name)
            };
            let text = match &m.body {
                MsgBody::Text(t) if t.is_empty() && !m.files.is_empty() => {
                    "sent a file".to_string()
                }
                MsgBody::Text(t) => t.clone(),
                _ => String::new(),
            };
            crate::notify::message(&place, &text, dm || mention, fresh.len(), c.id);
        }
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
                    let by_id: HashMap<&str, &bunkr_core::Msg> =
                        ch.messages.iter().map(|m| (m.id.as_str(), m)).collect();
                    let mut v: Vec<MsgView> = ch
                        .messages
                        .iter()
                        .map(|m| MsgView {
                            seq: m.seq,
                            id: m.id.clone(),
                            user_id: m.user_id,
                            username: d.username_of(m.user_id),
                            ts: m.ts,
                            body: m.body.clone(),
                            unverified: m.unverified,
                            mine: m.user_id == d.user_id,
                            edited: m.edited.is_some(),
                            reply: m.reply_to.as_ref().map(|r| {
                                let target = by_id.get(r.as_str());
                                ReplyView {
                                    id: r.clone(),
                                    username: target
                                        .map(|t| d.username_of(t.user_id))
                                        .unwrap_or_default(),
                                    snippet: match target.map(|t| &t.body) {
                                        Some(MsgBody::Text(t)) if !t.is_empty() => {
                                            t.chars().take(120).collect()
                                        }
                                        Some(MsgBody::Text(_)) => "📎 attachment".into(),
                                        Some(MsgBody::Deleted) => "message deleted".into(),
                                        _ => "original message unavailable".into(),
                                    },
                                }
                            }),
                            reactions: m
                                .reactions
                                .iter()
                                .map(|(e, s)| (e.clone(), s.len(), s.contains(&d.user_id)))
                                .collect(),
                            files: m.files.clone(),
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
                    dm: c.kind == ChannelKind::Dm,
                    dm_peer: d.dm_peer(c.id),
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
