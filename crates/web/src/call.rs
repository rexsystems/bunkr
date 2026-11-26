//! Voice / video calls: a small WebRTC mesh per channel.
//!
//! Security: all signalling (SDP offers/answers, ICE) travels as MLS-encrypted
//! ephemeral messages, so the DTLS fingerprints inside the SDP are
//! authenticated by MLS. Media is DTLS-SRTP peer-to-peer; a TURN relay (if
//! configured) only ever sees encrypted packets and cannot MITM. Signals
//! from devices that aren't verified against their account key are ignored.
//!
//! Every peer connection is negotiated once with one audio line and two video
//! lines (camera, then screen). Turning the camera or a screen share on or off
//! only swaps the track on the matching sender, so it works mid-call, in any
//! order, without renegotiating. Who has what switched on travels as a small
//! "media" signal and rides along on the presence heartbeat.

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
    RtcPeerConnection, RtcPeerConnectionIceEvent, RtcRtpTransceiver, RtcRtpTransceiverDirection,
    RtcRtpTransceiverInit, RtcSdpType, RtcSessionDescriptionInit, RtcTrackEvent,
};

use crate::engine::{Cmd, EngineHandle};
use crate::net::{self, WebHttp};

pub const MAX_PEERS: usize = 8;
const PRESENCE_MS: i64 = 25_000;

/// One media source of a call participant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Slot {
    Audio,
    Cam,
    Screen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Media {
    pub cam: bool,
    pub screen: bool,
}

impl Media {
    fn encode(self) -> String {
        format!("c{}s{}", self.cam as u8, self.screen as u8)
    }
    fn decode(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        (b.len() == 4 && b[0] == b'c' && b[2] == b's').then(|| Media {
            cam: b[1] == b'1',
            screen: b[3] == b'1',
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PeerView {
    pub device: DeviceId,
    pub user: UserId,
    pub state: String,
    pub media: Media,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct CallUi {
    pub active: Option<ChannelId>,
    pub joining: bool,
    pub muted: bool,
    /// Our own camera / screen share.
    pub me: Media,
    pub peers: Vec<PeerView>,
    /// Who is in a call, per channel: (user, device, expires_at_ms).
    pub presence: HashMap<ChannelId, Vec<(UserId, DeviceId, i64)>>,
    /// What each remote device has switched on.
    pub media: HashMap<DeviceId, Media>,
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
    mic: MediaStream,
    cam: Option<MediaStreamTrack>,
    screen: Option<MediaStreamTrack>,
    peers: HashMap<DeviceId, Peer>,
    ice: js_sys::Array,
    engine: EngineHandle,
    alive: std::rc::Rc<std::cell::Cell<bool>>,
}

thread_local! {
    static MGR: RefCell<Option<Mgr>> = const { RefCell::new(None) };
    /// (device, slot) -> media stream. Device 0 = this device.
    pub static STREAMS: RefCell<HashMap<(DeviceId, Slot), MediaStream>> = RefCell::new(HashMap::new());
}

#[derive(Clone, Copy)]
pub struct Calls(pub RwSignal<CallUi>);

pub fn calls() -> Calls {
    expect_context::<Calls>()
}

fn signal(engine: &EngineHandle, cid: ChannelId, op: &str, to: Option<DeviceId>, data: String) {
    engine.send(Cmd::Signal(
        cid,
        Eph::Call {
            op: op.into(),
            to,
            data,
            video: false,
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
                    .map(|(d, p)| (*d, p.user, format!("{:?}", p.pc.connection_state()).to_lowercase()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });
    ui.update(|u| {
        let mut v: Vec<PeerView> = peers
            .into_iter()
            .map(|(device, user, state)| PeerView {
                device,
                user,
                state,
                media: u.media.get(&device).copied().unwrap_or_default(),
            })
            .collect();
        v.sort_by_key(|p| p.device);
        u.peers = v;
    });
}

/// Tell everyone in the call what we have switched on.
fn announce(ui: RwSignal<CallUi>) {
    let me = ui.get_untracked().me;
    if let Some((engine, cid)) = MGR.with(|m| m.borrow().as_ref().map(|m| (m.engine.clone(), m.cid))) {
        signal(&engine, cid, "media", None, me.encode());
    }
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

fn media_devices() -> Result<web_sys::MediaDevices, String> {
    web_sys::window()
        .ok_or("no window")?
        .navigator()
        .media_devices()
        .map_err(|_| "Calls need HTTPS (or localhost) and a browser with WebRTC".to_string())
}

async fn get_mic() -> Result<MediaStream, String> {
    let c = MediaStreamConstraints::new();
    let audio = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&audio, &"echoCancellation".into(), &true.into());
    let _ = js_sys::Reflect::set(&audio, &"noiseSuppression".into(), &true.into());
    c.set_audio(&audio);
    let p = media_devices()?
        .get_user_media_with_constraints(&c)
        .map_err(|_| "Microphone unavailable")?;
    JsFuture::from(p)
        .await
        .map_err(|_| "Microphone permission denied".to_string())?
        .dyn_into()
        .map_err(|_| "bad media stream".to_string())
}

async fn get_cam() -> Result<MediaStreamTrack, String> {
    let c = MediaStreamConstraints::new();
    let v = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&v, &"width".into(), &1280.into());
    let _ = js_sys::Reflect::set(&v, &"height".into(), &720.into());
    c.set_video(&v);
    let p = media_devices()?
        .get_user_media_with_constraints(&c)
        .map_err(|_| "Camera unavailable")?;
    let s: MediaStream = JsFuture::from(p)
        .await
        .map_err(|_| "Camera permission denied".to_string())?
        .unchecked_into();
    s.get_video_tracks()
        .get(0)
        .dyn_into::<MediaStreamTrack>()
        .map_err(|_| "No camera found".to_string())
}

fn stream_of(track: &MediaStreamTrack) -> Option<MediaStream> {
    let arr = js_sys::Array::of1(track);
    MediaStream::new_with_tracks(&arr).ok()
}

/// Join the call in `cid`, optionally with the camera on.
pub fn join(
    cid: ChannelId,
    video: bool,
    me: DeviceId,
    http: WebHttp,
    engine: EngineHandle,
    ui: RwSignal<CallUi>,
    on_err: impl Fn(String) + Clone + 'static,
) {
    if MGR.with(|m| m.borrow().is_some()) {
        leave(ui);
    }
    ui.update(|u| {
        u.joining = true;
        u.active = Some(cid);
        u.muted = false;
        u.me = Media::default();
    });
    spawn_local(async move {
        let mic = match get_mic().await {
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
        // A missing or refused camera never blocks joining.
        let cam = if video {
            match get_cam().await {
                Ok(t) => Some(t),
                Err(e) => {
                    on_err(e);
                    None
                }
            }
        } else {
            None
        };
        let ice = ice_servers(&http).await;
        if let Some(t) = &cam {
            if let Some(s) = stream_of(t) {
                STREAMS.with(|st| st.borrow_mut().insert((0, Slot::Cam), s));
            }
        }
        let alive = std::rc::Rc::new(std::cell::Cell::new(true));
        let has_cam = cam.is_some();
        MGR.with(|m| {
            *m.borrow_mut() = Some(Mgr {
                cid,
                me,
                mic,
                cam,
                screen: None,
                peers: HashMap::new(),
                ice,
                engine: engine.clone(),
                alive: alive.clone(),
            })
        });
        ui.update(|u| {
            u.joining = false;
            u.me.cam = has_cam;
        });
        bump(ui);
        signal(&engine, cid, "join", None, ui.get_untracked().me.encode());
        // Heartbeat + expiry.
        spawn_local(async move {
            while alive.get() {
                net::sleep(8_000).await;
                if !alive.get() {
                    break;
                }
                signal(&engine, cid, "here", None, ui.get_untracked().me.encode());
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
        for d in &gone {
            u.media.remove(d);
        }
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
        signal(&m.engine, m.cid, "leave", None, String::new());
        for (_, p) in m.peers {
            p.pc.close();
        }
        stop_stream(&m.mic);
        for t in [m.cam, m.screen].into_iter().flatten() {
            t.stop();
        }
    }
    STREAMS.with(|s| s.borrow_mut().clear());
    ui.update(|u| {
        u.active = None;
        u.joining = false;
        u.peers.clear();
        u.me = Media::default();
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
    STREAMS.with(|s| s.borrow_mut().retain(|(dev, _), _| *dev != d));
}

pub fn toggle_mute(ui: RwSignal<CallUi>) {
    let muted = !ui.get_untracked().muted;
    MGR.with(|m| {
        if let Some(m) = m.borrow().as_ref() {
            for t in m.mic.get_audio_tracks().iter() {
                if let Ok(t) = t.dyn_into::<MediaStreamTrack>() {
                    t.set_enabled(!muted);
                }
            }
        }
    });
    ui.update(|u| u.muted = muted);
}

/// The two video transceivers of a connection: [camera, screen].
fn video_transceivers(pc: &RtcPeerConnection) -> Vec<RtcRtpTransceiver> {
    pc.get_transceivers()
        .iter()
        .filter_map(|t| t.dyn_into::<RtcRtpTransceiver>().ok())
        .filter(|t| t.receiver().track().kind() == "video")
        .collect()
}

fn slot_index(slot: Slot) -> usize {
    if slot == Slot::Screen {
        1
    } else {
        0
    }
}

/// Put `track` (or nothing) on the camera or screen sender of every peer.
fn send_video(slot: Slot, track: Option<&MediaStreamTrack>) {
    MGR.with(|m| {
        if let Some(m) = m.borrow().as_ref() {
            for p in m.peers.values() {
                if let Some(t) = video_transceivers(&p.pc).get(slot_index(slot)) {
                    let _ = t.sender().replace_track(track);
                }
            }
        }
    });
}

/// Camera on/off. Works in voice calls too: it just starts sending video.
pub fn toggle_cam(ui: RwSignal<CallUi>, on_err: impl Fn(String) + 'static) {
    if ui.get_untracked().me.cam {
        if let Some(t) = MGR.with(|m| m.borrow_mut().as_mut().and_then(|m| m.cam.take())) {
            t.stop();
        }
        send_video(Slot::Cam, None);
        STREAMS.with(|s| s.borrow_mut().remove(&(0, Slot::Cam)));
        ui.update(|u| u.me.cam = false);
        bump(ui);
        announce(ui);
        return;
    }
    spawn_local(async move {
        let track = match get_cam().await {
            Ok(t) => t,
            Err(e) => {
                on_err(e);
                return;
            }
        };
        // The call may have ended while the permission prompt was open.
        let stored = MGR.with(|m| {
            m.borrow_mut()
                .as_mut()
                .map(|m| m.cam = Some(track.clone()))
                .is_some()
        });
        if !stored {
            track.stop();
            return;
        }
        send_video(Slot::Cam, Some(&track));
        if let Some(s) = stream_of(&track) {
            STREAMS.with(|st| st.borrow_mut().insert((0, Slot::Cam), s));
        }
        ui.update(|u| u.me.cam = true);
        bump(ui);
        announce(ui);
    });
}

fn stop_share(ui: RwSignal<CallUi>) {
    if let Some(t) = MGR.with(|m| m.borrow_mut().as_mut().and_then(|m| m.screen.take())) {
        t.stop();
    }
    send_video(Slot::Screen, None);
    STREAMS.with(|s| s.borrow_mut().remove(&(0, Slot::Screen)));
    ui.update(|u| u.me.screen = false);
    bump(ui);
    announce(ui);
}

pub fn can_share() -> bool {
    media_devices()
        .map(|md| js_sys::Reflect::has(&md, &"getDisplayMedia".into()).unwrap_or(false))
        .unwrap_or(false)
}

/// Screen share on/off, independent of the camera.
pub fn toggle_share(ui: RwSignal<CallUi>, on_err: impl Fn(String) + 'static) {
    if ui.get_untracked().me.screen {
        stop_share(ui);
        return;
    }
    spawn_local(async move {
        let Ok(md) = media_devices() else {
            on_err("Screen sharing isn't available here".into());
            return;
        };
        let c = web_sys::DisplayMediaStreamConstraints::new();
        let v = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&v, &"frameRate".into(), &30.into());
        c.set_video(&v);
        let Ok(p) = md.get_display_media_with_constraints(&c) else {
            on_err("Screen sharing isn't available here".into());
            return;
        };
        // Rejected = the user closed the picker; nothing to report.
        let Ok(stream) = JsFuture::from(p).await else {
            return;
        };
        let stream: MediaStream = stream.unchecked_into();
        let Ok(track) = stream.get_video_tracks().get(0).dyn_into::<MediaStreamTrack>() else {
            return;
        };
        // Text and UI stay sharp instead of being smoothed like a camera.
        let _ = js_sys::Reflect::set(&track, &"contentHint".into(), &"detail".into());
        let stored = MGR.with(|m| {
            m.borrow_mut()
                .as_mut()
                .map(|m| m.screen = Some(track.clone()))
                .is_some()
        });
        if !stored {
            track.stop();
            return;
        }
        send_video(Slot::Screen, Some(&track));
        // Stop sharing when the browser's own "Stop sharing" button is used.
        let cb = Closure::<dyn FnMut()>::new(move || {
            if ui.get_untracked().me.screen {
                stop_share(ui);
            }
        });
        track.set_onended(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
        STREAMS.with(|s| s.borrow_mut().insert((0, Slot::Screen), stream));
        ui.update(|u| u.me.screen = true);
        bump(ui);
        announce(ui);
    });
}

fn new_peer(d: DeviceId, user: UserId, ui: RwSignal<CallUi>, offerer: bool) -> Option<RtcPeerConnection> {
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
        for t in m.mic.get_audio_tracks().iter() {
            if let Ok(t) = t.dyn_into::<MediaStreamTrack>() {
                pc.add_track_0(&t, &m.mic);
            }
        }
        // The offerer creates the camera and screen lines; the answerer gets
        // them from the offer (see `take_offer`).
        if offerer {
            for track in [&m.cam, &m.screen] {
                let init = RtcRtpTransceiverInit::new();
                init.set_direction(RtcRtpTransceiverDirection::Sendrecv);
                let t = pc.add_transceiver_with_str_and_init("video", &init);
                let _ = t.sender().replace_track(track.as_ref());
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
                    signal(&engine, cid, "ice", Some(d), json);
                }
            },
        );
        pc.set_onicecandidate(Some(onice.as_ref().unchecked_ref()));
        let pc2 = pc.clone();
        let ontrack = Closure::<dyn FnMut(RtcTrackEvent)>::new(move |e: RtcTrackEvent| {
            let track = e.track();
            let slot = if track.kind() == "audio" {
                Slot::Audio
            } else {
                let tr = e.transceiver();
                let idx = video_transceivers(&pc2).iter().position(|t| t == &tr).unwrap_or(0);
                if idx == 1 {
                    Slot::Screen
                } else {
                    Slot::Cam
                }
            };
            if let Some(s) = stream_of(&track) {
                STREAMS.with(|st| st.borrow_mut().insert((d, slot), s));
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
    let Some(pc) = new_peer(d, user, ui, true) else {
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
    if let Some((engine, cid)) = MGR.with(|m| m.borrow().as_ref().map(|m| (m.engine.clone(), m.cid))) {
        signal(&engine, cid, "offer", Some(d), sdp);
    }
    sync_peers(ui);
}

async fn take_offer(d: DeviceId, user: UserId, sdp: String, ui: RwSignal<CallUi>) {
    let Some(pc) = new_peer(d, user, ui, false) else {
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
    // The offer created our camera and screen lines as receive-only; send on
    // them too, with whatever we currently have switched on.
    let (cam, screen) = MGR.with(|m| {
        m.borrow()
            .as_ref()
            .map(|m| (m.cam.clone(), m.screen.clone()))
            .unwrap_or((None, None))
    });
    for (t, track) in video_transceivers(&pc).iter().zip([cam, screen]) {
        t.set_direction(RtcRtpTransceiverDirection::Sendrecv);
        let _ = t.sender().replace_track(track.as_ref());
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
        signal(&engine, cid, "answer", Some(d), sdp);
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
        "join" | "here" | "media" => {
            ui.update(|u| {
                if op != "media" {
                    let v = u.presence.entry(cid).or_default();
                    v.retain(|(_, x, _)| *x != d);
                    v.push((user, d, now + PRESENCE_MS));
                }
                if let Some(m) = Media::decode(&data) {
                    u.media.insert(d, m);
                }
            });
            sync_peers(ui);
            if op == "media" {
                return;
            }
        }
        "leave" => {
            ui.update(|u| {
                if let Some(v) = u.presence.get_mut(&cid) {
                    v.retain(|(_, x, _)| *x != d);
                }
                u.media.remove(&d);
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
                    signal(&engine, cid, "here", None, ui.get_untracked().me.encode());
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

/// Attach the stream for `device` (0 = local) and `slot` to a media element.
pub fn attach(el: &web_sys::HtmlMediaElement, device: DeviceId, slot: Slot) {
    let s = STREAMS.with(|s| s.borrow().get(&(device, slot)).cloned());
    // Re-attaching the same stream would restart playback and cause a gap.
    let same = match (el.src_object(), &s) {
        (Some(cur), Some(new)) => JsValue::from(cur) == JsValue::from(new.clone()),
        (None, None) => true,
        _ => false,
    };
    if same {
        return;
    }
    el.set_src_object(s.as_ref());
    if let Ok(p) = el.play() {
        // play() rejects harmlessly when an element is replaced; swallow it.
        wasm_bindgen_futures::spawn_local(async move {
            let _ = JsFuture::from(p).await;
        });
    }
}
