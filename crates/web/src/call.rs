//! Voice / video calls: a small WebRTC mesh per channel.
//!
//! Security: all signalling (SDP offers/answers, ICE) travels as MLS-encrypted
//! ephemeral messages, so the DTLS fingerprints inside the SDP are
//! authenticated by MLS. Media is DTLS-SRTP peer-to-peer; a TURN relay (if
//! configured) only ever sees encrypted packets and cannot MITM. Signals
//! from devices that aren't verified against their account key are ignored.

use std::cell::RefCell;
use std::collections::HashMap;

use bunkr_core::device::Eph;
use bunkr_proto::{ChannelId, DeviceId, TurnResp, UserId};
use leptos::prelude::*;
use leptos::task::spawn_local;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    MediaStream, MediaStreamConstraints, MediaStreamTrack, RtcConfiguration, RtcIceCandidateInit,
    RtcPeerConnection, RtcPeerConnectionIceEvent, RtcSdpType, RtcSessionDescriptionInit,
    RtcTrackEvent,
};

use crate::engine::{Cmd, EngineHandle};
use crate::net::{self, WebHttp};

pub const MAX_PEERS: usize = 8;
const PRESENCE_MS: i64 = 25_000;

#[derive(Clone, Debug, PartialEq)]
pub struct PeerView {
    pub device: DeviceId,
    pub user: UserId,
    pub state: String,
    pub video: bool,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct CallUi {
    pub active: Option<ChannelId>,
    pub joining: bool,
    pub video: bool,
    pub muted: bool,
    pub cam_off: bool,
    pub sharing: bool,
    pub peers: Vec<PeerView>,
    /// Who is in a call, per channel: (user, device, expires_at_ms).
    pub presence: HashMap<ChannelId, Vec<(UserId, DeviceId, i64)>>,
    /// Bumped whenever a media stream is attached, to re-render tiles.
    pub streams_rev: u64,
}

struct Peer {
    pc: RtcPeerConnection,
    user: UserId,
    has_remote: bool,
    queued_ice: Vec<String>,
    _closures: Vec<Box<dyn std::any::Any>>,
}

struct Mgr {
    cid: ChannelId,
    me: DeviceId,
    local: MediaStream,
    camera: Option<MediaStreamTrack>,
    screen: Option<MediaStream>,
    peers: HashMap<DeviceId, Peer>,
    ice: js_sys::Array,
    engine: EngineHandle,
    alive: std::rc::Rc<std::cell::Cell<bool>>,
}

thread_local! {
    static MGR: RefCell<Option<Mgr>> = const { RefCell::new(None) };
    /// device -> media stream (0 = local).
    pub static STREAMS: RefCell<HashMap<DeviceId, MediaStream>> = RefCell::new(HashMap::new());
}

#[derive(Clone, Copy)]
pub struct Calls(pub RwSignal<CallUi>);

pub fn calls() -> Calls {
    expect_context::<Calls>()
}

fn signal(
    engine: &EngineHandle,
    cid: ChannelId,
    op: &str,
    to: Option<DeviceId>,
    data: String,
    video: bool,
) {
    engine.send(Cmd::Signal(
        cid,
        Eph::Call {
            op: op.into(),
            to,
            data,
            video,
        },
    ));
}

fn bump(ui: RwSignal<CallUi>) {
    ui.update(|u| u.streams_rev += 1);
}

fn sync_peers(ui: RwSignal<CallUi>) {
    let peers = MGR.with(|m| {
        m.borrow()
            .as_ref()
            .map(|m| {
                m.peers
                    .iter()
                    .map(|(d, p)| PeerView {
                        device: *d,
                        user: p.user,
                        state: format!("{:?}", p.pc.connection_state()).to_lowercase(),
                        video: STREAMS.with(|s| {
                            s.borrow()
                                .get(d)
                                .map(|st| st.get_video_tracks().length() > 0)
                                .unwrap_or(false)
                        }),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });
    ui.update(|u| u.peers = peers);
}

async fn ice_servers(http: &WebHttp) -> js_sys::Array {
    let arr = js_sys::Array::new();
    if let Ok(t) =
        bunkr_core::call_ok::<TurnResp>(http, "GET", "/api/turn", bunkr_core::NO_BODY).await
    {
        for s in t.ice_servers {
            let o = js_sys::Object::new();
            let urls = js_sys::Array::new();
            for u in s.urls {
                urls.push(&u.into());
            }
            let _ = js_sys::Reflect::set(&o, &"urls".into(), &urls);
            if let Some(u) = s.username {
                let _ = js_sys::Reflect::set(&o, &"username".into(), &u.into());
            }
            if let Some(c) = s.credential {
                let _ = js_sys::Reflect::set(&o, &"credential".into(), &c.into());
            }
            arr.push(&o);
        }
    }
    arr
}

async fn get_media(video: bool) -> Result<MediaStream, String> {
    let w = web_sys::window().ok_or("no window")?;
    let md = w
        .navigator()
        .media_devices()
        .map_err(|_| "Calls need HTTPS (or localhost) and a browser with WebRTC")?;
    let c = MediaStreamConstraints::new();
    let audio = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&audio, &"echoCancellation".into(), &true.into());
    let _ = js_sys::Reflect::set(&audio, &"noiseSuppression".into(), &true.into());
    c.set_audio(&audio);
    if video {
        let v = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&v, &"width".into(), &1280.into());
        let _ = js_sys::Reflect::set(&v, &"height".into(), &720.into());
        c.set_video(&v);
    }
    let p = md
        .get_user_media_with_constraints(&c)
        .map_err(|_| "Microphone/camera unavailable")?;
    JsFuture::from(p)
        .await
        .map_err(|_| "Microphone/camera permission denied".to_string())?
        .dyn_into()
        .map_err(|_| "bad media stream".to_string())
}

/// Join the call in `cid`.
pub fn join(
    cid: ChannelId,
    video: bool,
    me: DeviceId,
    http: WebHttp,
    engine: EngineHandle,
    ui: RwSignal<CallUi>,
    on_err: impl Fn(String) + 'static,
) {
    if MGR.with(|m| m.borrow().is_some()) {
        leave(ui);
    }
    ui.update(|u| {
        u.joining = true;
        u.active = Some(cid);
        u.video = video;
        u.muted = false;
        u.cam_off = false;
        u.sharing = false;
    });
    spawn_local(async move {
        let local = match get_media(video).await {
            Ok(s) => s,
            Err(e) => {
                ui.update(|u| {
                    u.joining = false;
                    u.active = None;
                });
                on_err(e);
                return;
            }
        };
        let ice = ice_servers(&http).await;
        let camera = local
            .get_video_tracks()
            .get(0)
            .dyn_into::<MediaStreamTrack>()
            .ok();
        STREAMS.with(|s| s.borrow_mut().insert(0, local.clone()));
        let alive = std::rc::Rc::new(std::cell::Cell::new(true));
        MGR.with(|m| {
            *m.borrow_mut() = Some(Mgr {
                cid,
                me,
                local,
                camera,
                screen: None,
                peers: HashMap::new(),
                ice,
                engine: engine.clone(),
                alive: alive.clone(),
            })
        });
        ui.update(|u| u.joining = false);
        bump(ui);
        signal(&engine, cid, "join", None, String::new(), video);
        // Heartbeat + expiry.
        spawn_local(async move {
            while alive.get() {
                net::sleep(8_000).await;
                if !alive.get() {
                    break;
                }
                signal(&engine, cid, "here", None, String::new(), video);
                expire(ui);
            }
        });
    });
}

fn expire(ui: RwSignal<CallUi>) {
    let now = net::now_ms();
    let mut gone = vec![];
    ui.update(|u| {
        for v in u.presence.values_mut() {
            v.retain(|(_, d, exp)| {
                let keep = *exp > now;
                if !keep {
                    gone.push(*d);
                }
                keep
            });
        }
        u.presence.retain(|_, v| !v.is_empty());
    });
    for d in gone {
        close_peer(d);
    }
    sync_peers(ui);
}

pub fn leave(ui: RwSignal<CallUi>) {
    let m = MGR.with(|m| m.borrow_mut().take());
    if let Some(m) = m {
        m.alive.set(false);
        signal(&m.engine, m.cid, "leave", None, String::new(), false);
        for (_, p) in m.peers {
            p.pc.close();
        }
        stop_stream(&m.local);
        if let Some(s) = &m.screen {
            stop_stream(s);
        }
    }
    STREAMS.with(|s| s.borrow_mut().clear());
    ui.update(|u| {
        u.active = None;
        u.joining = false;
        u.peers.clear();
        u.sharing = false;
    });
    bump(ui);
}

fn stop_stream(s: &MediaStream) {
    for t in s.get_tracks().iter() {
        if let Ok(t) = t.dyn_into::<MediaStreamTrack>() {
            t.stop();
        }
    }
}

fn close_peer(d: DeviceId) {
    MGR.with(|m| {
        if let Some(m) = m.borrow_mut().as_mut() {
            if let Some(p) = m.peers.remove(&d) {
                p.pc.close();
            }
        }
    });
    STREAMS.with(|s| s.borrow_mut().remove(&d));
}

pub fn toggle_mute(ui: RwSignal<CallUi>) {
    let muted = !ui.get_untracked().muted;
    MGR.with(|m| {
        if let Some(m) = m.borrow().as_ref() {
            for t in m.local.get_audio_tracks().iter() {
                if let Ok(t) = t.dyn_into::<MediaStreamTrack>() {
                    t.set_enabled(!muted);
                }
            }
        }
    });
    ui.update(|u| u.muted = muted);
}

pub fn toggle_cam(ui: RwSignal<CallUi>) {
    let off = !ui.get_untracked().cam_off;
    MGR.with(|m| {
        if let Some(m) = m.borrow().as_ref() {
            if let Some(c) = &m.camera {
                c.set_enabled(!off);
            }
        }
    });
    ui.update(|u| u.cam_off = off);
}

fn replace_video(track: &MediaStreamTrack) {
    MGR.with(|m| {
        if let Some(m) = m.borrow().as_ref() {
            for p in m.peers.values() {
                for s in p.pc.get_senders().iter() {
                    if let Ok(s) = s.dyn_into::<web_sys::RtcRtpSender>() {
                        if s.track().map(|t| t.kind() == "video").unwrap_or(false) {
                            let _ = s.replace_track(Some(track));
                        }
                    }
                }
            }
        }
    });
}

/// Share the screen (video calls): swaps the camera track on every peer.
fn stop_share(ui: RwSignal<CallUi>) {
    {
        let (screen, cam) = MGR.with(|m| {
            m.borrow_mut()
                .as_mut()
                .map(|m| (m.screen.take(), m.camera.clone()))
                .unwrap_or((None, None))
        });
        if let Some(s) = screen {
            stop_stream(&s);
        }
        if let Some(c) = cam {
            replace_video(&c);
        }
        let local = MGR.with(|m| m.borrow().as_ref().map(|m| m.local.clone()));
        if let Some(l) = local {
            STREAMS.with(|s| s.borrow_mut().insert(0, l));
        }
        ui.update(|u| u.sharing = false);
        bump(ui);
    }
}

pub fn toggle_share(ui: RwSignal<CallUi>, on_err: impl Fn(String) + 'static) {
    if ui.get_untracked().sharing {
        stop_share(ui);
        return;
    }
    spawn_local(async move {
        let Some(w) = web_sys::window() else { return };
        let Ok(md) = w.navigator().media_devices() else {
            on_err("Screen sharing isn't available here".into());
            return;
        };
        let Ok(p) = md.get_display_media() else {
            on_err("Screen sharing isn't available here".into());
            return;
        };
        let Ok(stream) = JsFuture::from(p).await else {
            return;
        };
        let stream: MediaStream = stream.unchecked_into();
        let Some(track) = stream
            .get_video_tracks()
            .get(0)
            .dyn_into::<MediaStreamTrack>()
            .ok()
        else {
            return;
        };
        replace_video(&track);
        // Stop sharing when the browser's own "stop" button is used.
        let cb = Closure::<dyn FnMut()>::new(move || {
            if ui.get_untracked().sharing {
                stop_share(ui);
            }
        });
        track.set_onended(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
        STREAMS.with(|s| s.borrow_mut().insert(0, stream.clone()));
        MGR.with(|m| {
            if let Some(m) = m.borrow_mut().as_mut() {
                m.screen = Some(stream);
            }
        });
        ui.update(|u| u.sharing = true);
        bump(ui);
    });
}

fn new_peer(d: DeviceId, user: UserId, ui: RwSignal<CallUi>) -> Option<RtcPeerConnection> {
    MGR.with(|m| {
        let mut b = m.borrow_mut();
        let m = b.as_mut()?;
        if m.peers.len() >= MAX_PEERS && !m.peers.contains_key(&d) {
            return None;
        }
        if let Some(p) = m.peers.remove(&d) {
            p.pc.close();
        }
        let cfg = RtcConfiguration::new();
        cfg.set_ice_servers(&m.ice);
        let pc = RtcPeerConnection::new_with_configuration(&cfg).ok()?;
        for t in m.local.get_tracks().iter() {
            if let Ok(t) = t.dyn_into::<MediaStreamTrack>() {
                pc.add_track_0(&t, &m.local);
            }
        }
        let (engine, cid) = (m.engine.clone(), m.cid);
        let onice = Closure::<dyn FnMut(RtcPeerConnectionIceEvent)>::new(
            move |e: RtcPeerConnectionIceEvent| {
                if let Some(c) = e.candidate() {
                    let json = js_sys::JSON::stringify(&c.to_json())
                        .ok()
                        .and_then(|s| s.as_string())
                        .unwrap_or_default();
                    signal(&engine, cid, "ice", Some(d), json, false);
                }
            },
        );
        pc.set_onicecandidate(Some(onice.as_ref().unchecked_ref()));
        let ontrack = Closure::<dyn FnMut(RtcTrackEvent)>::new(move |e: RtcTrackEvent| {
            if let Ok(s) = e.streams().get(0).dyn_into::<MediaStream>() {
                STREAMS.with(|st| st.borrow_mut().insert(d, s));
                bump(ui);
                sync_peers(ui);
            }
        });
        pc.set_ontrack(Some(ontrack.as_ref().unchecked_ref()));
        let onstate = Closure::<dyn FnMut()>::new(move || sync_peers(ui));
        pc.set_onconnectionstatechange(Some(onstate.as_ref().unchecked_ref()));
        m.peers.insert(
            d,
            Peer {
                pc: pc.clone(),
                user,
                has_remote: false,
                queued_ice: vec![],
                _closures: vec![Box::new(onice), Box::new(ontrack), Box::new(onstate)],
            },
        );
        Some(pc)
    })
}

fn sdp_of(v: &JsValue) -> String {
    js_sys::Reflect::get(v, &"sdp".into())
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_default()
}

async fn make_offer(d: DeviceId, user: UserId, ui: RwSignal<CallUi>) {
    let Some(pc) = new_peer(d, user, ui) else {
        return;
    };
    let Ok(offer) = JsFuture::from(pc.create_offer()).await else {
        return;
    };
    let sdp = sdp_of(&offer);
    let init = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    init.set_sdp(&sdp);
    if JsFuture::from(pc.set_local_description(&init))
        .await
        .is_err()
    {
        return;
    }
    if let Some((engine, cid, video)) = MGR.with(|m| {
        m.borrow()
            .as_ref()
            .map(|m| (m.engine.clone(), m.cid, m.camera.is_some()))
    }) {
        signal(&engine, cid, "offer", Some(d), sdp, video);
    }
    sync_peers(ui);
}

async fn take_offer(d: DeviceId, user: UserId, sdp: String, ui: RwSignal<CallUi>) {
    let Some(pc) = new_peer(d, user, ui) else {
        return;
    };
    let init = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    init.set_sdp(&sdp);
    if JsFuture::from(pc.set_remote_description(&init))
        .await
        .is_err()
    {
        return;
    }
    flush_ice(d).await;
    let Ok(answer) = JsFuture::from(pc.create_answer()).await else {
        return;
    };
    let sdp = sdp_of(&answer);
    let init = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    init.set_sdp(&sdp);
    if JsFuture::from(pc.set_local_description(&init))
        .await
        .is_err()
    {
        return;
    }
    if let Some((engine, cid)) =
        MGR.with(|m| m.borrow().as_ref().map(|m| (m.engine.clone(), m.cid)))
    {
        signal(&engine, cid, "answer", Some(d), sdp, false);
    }
    sync_peers(ui);
}

async fn take_answer(d: DeviceId, sdp: String) {
    let pc = MGR.with(|m| {
        m.borrow()
            .as_ref()
            .and_then(|m| m.peers.get(&d).map(|p| p.pc.clone()))
    });
    let Some(pc) = pc else { return };
    let init = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    init.set_sdp(&sdp);
    if JsFuture::from(pc.set_remote_description(&init))
        .await
        .is_ok()
    {
        flush_ice(d).await;
    }
}

async fn flush_ice(d: DeviceId) {
    let (pc, queued) = MGR.with(|m| {
        let mut b = m.borrow_mut();
        match b.as_mut().and_then(|m| m.peers.get_mut(&d)) {
            Some(p) => {
                p.has_remote = true;
                (Some(p.pc.clone()), std::mem::take(&mut p.queued_ice))
            }
            None => (None, vec![]),
        }
    });
    if let Some(pc) = pc {
        for c in queued {
            add_ice(&pc, &c).await;
        }
    }
}

async fn add_ice(pc: &RtcPeerConnection, json: &str) {
    if let Ok(v) = js_sys::JSON::parse(json) {
        let init: RtcIceCandidateInit = v.unchecked_into();
        let _ =
            JsFuture::from(pc.add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&init))).await;
    }
}

/// Entry point for decrypted call signals (wired to the engine's CALL_SINK).
pub fn on_signal(
    cid: ChannelId,
    user: UserId,
    d: DeviceId,
    trusted: bool,
    e: Eph,
    ui: RwSignal<CallUi>,
) {
    let Eph::Call { op, to, data, .. } = e else {
        return;
    };
    if !trusted {
        return;
    }
    let now = net::now_ms();
    match op.as_str() {
        "join" | "here" => ui.update(|u| {
            let v = u.presence.entry(cid).or_default();
            v.retain(|(_, x, _)| *x != d);
            v.push((user, d, now + PRESENCE_MS));
        }),
        "leave" => {
            ui.update(|u| {
                if let Some(v) = u.presence.get_mut(&cid) {
                    v.retain(|(_, x, _)| *x != d);
                }
            });
            close_peer(d);
            sync_peers(ui);
            bump(ui);
            return;
        }
        _ => {}
    }
    let Some((active, me)) = MGR.with(|m| m.borrow().as_ref().map(|m| (m.cid, m.me))) else {
        return;
    };
    if active != cid || d == me || to.map(|t| t != me).unwrap_or(false) {
        return;
    }
    let known = MGR.with(|m| {
        m.borrow()
            .as_ref()
            .map(|m| m.peers.contains_key(&d))
            .unwrap_or(false)
    });
    match op.as_str() {
        "join" | "here" => {
            if op == "join" {
                if let Some(engine) = MGR.with(|m| m.borrow().as_ref().map(|m| m.engine.clone())) {
                    signal(&engine, cid, "here", None, String::new(), false);
                }
            }
            // The lower device id makes the offer, so there is never glare.
            if !known && me < d {
                spawn_local(make_offer(d, user, ui));
            }
        }
        "offer" => spawn_local(take_offer(d, user, data, ui)),
        "answer" => spawn_local(take_answer(d, data)),
        "ice" => {
            let pc = MGR.with(|m| {
                let mut b = m.borrow_mut();
                let p = b.as_mut()?.peers.get_mut(&d)?;
                if p.has_remote {
                    Some(p.pc.clone())
                } else {
                    p.queued_ice.push(data.clone());
                    None
                }
            });
            if let Some(pc) = pc {
                spawn_local(async move { add_ice(&pc, &data).await });
            }
        }
        _ => {}
    }
}

/// Attach the stream for `device` (0 = local) to a media element.
pub fn attach(el: &web_sys::HtmlMediaElement, device: DeviceId) {
    let s = STREAMS.with(|s| s.borrow().get(&device).cloned());
    el.set_src_object(s.as_ref());
    if let Ok(p) = el.play() {
        // play() rejects harmlessly when an element is replaced; swallow it.
        wasm_bindgen_futures::spawn_local(async move {
            let _ = JsFuture::from(p).await;
        });
    }
}
