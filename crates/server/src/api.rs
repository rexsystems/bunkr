//! HTTP + WebSocket API.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        FromRequestParts, Path, Query, State,
    },
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use bunkr_proto::{self as proto, *};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::db::{self, Db};
use crate::hub::Hub;

pub const MAX_DEVICES_PER_USER: i64 = 10;
pub const MAX_KEY_PACKAGES: i64 = 200;

#[derive(Clone)]
pub struct Config {
    pub name: String,
    pub retention_days: u32,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub hub: Hub,
    pub cfg: Config,
    pub secret: Arc<[u8; 32]>,
    pub setup_code: Arc<Mutex<Option<String>>>,
    pub limiter: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
}

// ---------------- errors ----------------

pub enum ApiErr {
    Status(StatusCode, String),
    Conflict(Conflict),
}

impl ApiErr {
    fn bad(m: impl Into<String>) -> Self {
        ApiErr::Status(StatusCode::BAD_REQUEST, m.into())
    }
    fn forbidden(m: impl Into<String>) -> Self {
        ApiErr::Status(StatusCode::FORBIDDEN, m.into())
    }
    fn unauthorized() -> Self {
        ApiErr::Status(StatusCode::UNAUTHORIZED, "unauthorized".into())
    }
    fn not_found() -> Self {
        ApiErr::Status(StatusCode::NOT_FOUND, "not found".into())
    }
}

impl From<rusqlite::Error> for ApiErr {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("db: {e}");
        ApiErr::Status(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        match self {
            ApiErr::Status(s, m) => (s, Json(ApiError { error: m })).into_response(),
            ApiErr::Conflict(c) => (StatusCode::CONFLICT, Json(c)).into_response(),
        }
    }
}

type R<T> = Result<Json<T>, ApiErr>;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn today() -> i64 {
    now_secs() / 86_400
}
fn this_hour() -> i64 {
    now_secs() / 3_600
}

fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

fn auth_hash(auth_key: &[u8]) -> Vec<u8> {
    sha(&[b"bunkr/auth-hash/v1\0".as_slice(), auth_key].concat())
}

fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

// ---------------- auth extractors ----------------

/// Any valid session (device may not be registered yet).
pub struct Session {
    pub token_hash: Vec<u8>,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub is_admin: bool,
}

/// A session bound to a registered device.
pub struct Dev {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub is_admin: bool,
}

pub struct Admin(pub Dev);

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiErr;
    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiErr> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(ApiErr::unauthorized)?
            .to_string();
        session_for_token(st, &token)
            .await?
            .ok_or_else(ApiErr::unauthorized)
    }
}

async fn session_for_token(st: &AppState, token: &str) -> Result<Option<Session>, ApiErr> {
    let th = sha(token.as_bytes());
    Ok(st
        .db
        .run(move |c| {
            c.query_row(
                "SELECT s.user_id, s.device_id, u.is_admin FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ? AND u.banned = 0",
                [&th],
                |r| {
                    Ok(Session {
                        token_hash: th.clone(),
                        user_id: r.get(0)?,
                        device_id: r.get(1)?,
                        is_admin: r.get::<_, i64>(2)? != 0,
                    })
                },
            )
            .optional()
        })
        .await?)
}

impl FromRequestParts<AppState> for Dev {
    type Rejection = ApiErr;
    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiErr> {
        let s = Session::from_request_parts(parts, st).await?;
        let device_id = s.device_id.ok_or_else(ApiErr::unauthorized)?;
        Ok(Dev {
            user_id: s.user_id,
            device_id,
            is_admin: s.is_admin,
        })
    }
}

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiErr;
    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiErr> {
        let d = Dev::from_request_parts(parts, st).await?;
        if !d.is_admin {
            return Err(ApiErr::forbidden("admins only"));
        }
        Ok(Admin(d))
    }
}

// ---------------- router ----------------

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/info", get(info))
        .route("/api/prelogin", post(prelogin))
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/device", post(register_device))
        .route("/api/logout", post(logout))
        .route("/api/password", post(change_password))
        .route("/api/keypackages", post(upload_key_packages))
        .route("/api/state", get(state))
        .route("/api/welcomes", get(welcomes))
        .route("/api/welcomes/ack", post(ack_welcome))
        .route("/api/channels/{id}/log", get(channel_log))
        .route("/api/channels/{id}/send", post(send))
        .route("/api/channels/{id}/commit", post(commit))
        .route("/api/channels/{id}/found", post(found))
        .route("/api/channels/{id}/pending", get(pending))
        .route("/api/channels/{id}/dismiss", post(dismiss))
        .route("/api/channels/{id}/rejoin", post(rejoin))
        .route("/api/ws", get(ws))
        .route("/api/admin/users", get(admin_users))
        .route("/api/admin/users/{id}/ban", post(admin_ban))
        .route("/api/admin/users/{id}/unban", post(admin_unban))
        .route("/api/admin/users/{id}/admin", post(admin_toggle_admin))
        .route("/api/admin/users/{id}", delete(admin_delete_user))
        .route("/api/admin/channels", post(admin_create_channel))
        .route("/api/admin/channels/{id}", put(admin_update_channel).delete(admin_delete_channel))
        .route("/api/admin/log/{seq}", delete(admin_delete_entry))
        .route("/api/admin/settings", post(admin_settings))
}

// ---------------- public ----------------

async fn info(State(st): State<AppState>) -> R<ServerInfo> {
    let (users, open) = st
        .db
        .run(|c| Ok::<_, rusqlite::Error>((db::user_count(c)?, db::registration_open(c)?)))
        .await?;
    Ok(Json(ServerInfo {
        name: st.cfg.name.clone(),
        version: env!("CARGO_PKG_VERSION").into(),
        protocol: PROTOCOL_VERSION,
        needs_setup: users == 0,
        registration_open: open || users == 0,
        retention_days: st.cfg.retention_days,
    }))
}

async fn prelogin(State(st): State<AppState>, Json(req): Json<PreloginReq>) -> R<PreloginResp> {
    let username = normalize_username(&req.username).unwrap_or_default();
    let u2 = username.clone();
    let salt: Option<Vec<u8>> = st
        .db
        .run(move |c| {
            c.query_row("SELECT salt FROM users WHERE username = ?", [&u2], |r| r.get(0))
                .optional()
        })
        .await?;
    // Unknown users get a stable fake salt: no account enumeration.
    let salt = salt.unwrap_or_else(|| {
        sha(&[st.secret.as_slice(), b"fake-salt", username.as_bytes()].concat())[..16].to_vec()
    });
    Ok(Json(PreloginResp { salt: B64(salt) }))
}

fn check_rate(st: &AppState, key: &str) -> Result<(), ApiErr> {
    let m = st.limiter.lock().unwrap();
    if let Some((fails, until)) = m.get(key) {
        if *fails >= 5 && Instant::now() < *until {
            return Err(ApiErr::Status(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts. Wait a bit.".into(),
            ));
        }
    }
    Ok(())
}

fn record_fail(st: &AppState, key: &str) {
    let mut m = st.limiter.lock().unwrap();
    let e = m.entry(key.to_string()).or_insert((0, Instant::now()));
    e.0 += 1;
    if e.0 >= 5 {
        let secs = 30u64 << (e.0 - 5).min(8);
        e.1 = Instant::now() + Duration::from_secs(secs);
    }
    if m.len() > 50_000 {
        m.clear();
    }
}

fn record_ok(st: &AppState, key: &str) {
    st.limiter.lock().unwrap().remove(key);
}

async fn register(State(st): State<AppState>, Json(req): Json<RegisterReq>) -> R<LoginResp> {
    let username = normalize_username(&req.username)
        .ok_or_else(|| ApiErr::bad("Username: 3-32 chars, a-z 0-9 _ . -"))?;
    if req.auth_key.0.len() != 32
        || req.account_pk.0.len() != 32
        || req.salt.0.len() < 16
        || req.salt.0.len() > 64
        || req.key_blob.0.len() > 256
    {
        return Err(ApiErr::bad("malformed keys"));
    }
    let setup = st.setup_code.clone();
    let token = new_token();
    let th = sha(token.as_bytes());
    let st2 = st.clone();
    let res = st
        .db
        .run(move |c| -> Result<LoginResp, ApiErr> {
            let tx = c.transaction()?;
            let first = db::user_count(&tx)? == 0;
            if first {
                let ok = {
                    let code = setup.lock().unwrap();
                    match (code.as_deref(), req.setup_code.as_deref()) {
                        (Some(a), Some(b)) => a.as_bytes().ct_eq(b.trim().as_bytes()).into(),
                        _ => false,
                    }
                };
                if !ok {
                    return Err(ApiErr::forbidden(
                        "Wrong setup code. It is printed in the server logs (docker logs bunkr).",
                    ));
                }
            } else if !db::registration_open(&tx)? {
                return Err(ApiErr::forbidden("Registration is closed on this server"));
            }
            let exists: Option<i64> = tx
                .query_row("SELECT id FROM users WHERE username = ?", [&username], |r| r.get(0))
                .optional()?;
            if exists.is_some() {
                return Err(ApiErr::Status(StatusCode::CONFLICT, "Username taken".into()));
            }
            tx.execute(
                "INSERT INTO users(username, auth_hash, salt, account_pk, key_blob, is_admin, created_day)
                 VALUES(?, ?, ?, ?, ?, ?, ?)",
                params![
                    username,
                    auth_hash(&req.auth_key.0),
                    req.salt.0,
                    req.account_pk.0,
                    req.key_blob.0,
                    first as i64,
                    today()
                ],
            )?;
            let uid = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO sessions(token_hash, user_id, created_day) VALUES(?, ?, ?)",
                params![th, uid, today()],
            )?;
            tx.commit()?;
            if first {
                *setup.lock().unwrap() = None;
            }
            Ok(LoginResp {
                token,
                user_id: uid,
                account_pk: req.account_pk,
                key_blob: req.key_blob,
                generation: 1,
                is_admin: first,
            })
        })
        .await?;
    st2.hub.broadcast(ServerWs::State);
    Ok(Json(res))
}

async fn login(State(st): State<AppState>, Json(req): Json<LoginReq>) -> R<LoginResp> {
    let username = normalize_username(&req.username).ok_or_else(ApiErr::unauthorized)?;
    check_rate(&st, &username)?;
    let token = new_token();
    let th = sha(token.as_bytes());
    let u2 = username.clone();
    let res = st
        .db
        .run(move |c| -> Result<Option<LoginResp>, ApiErr> {
            let row: Option<(i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, bool, bool)> = c
                .query_row(
                    "SELECT id, auth_hash, account_pk, key_blob, generation, is_admin, banned FROM users WHERE username = ?",
                    [&u2],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get::<_, i64>(5)? != 0, r.get::<_, i64>(6)? != 0)),
                )
                .optional()?;
            let Some((uid, hash, pk, blob, generation, is_admin, banned)) = row else {
                return Ok(None);
            };
            if !bool::from(auth_hash(&req.auth_key.0).ct_eq(&hash)) {
                return Ok(None);
            }
            if banned {
                return Err(ApiErr::forbidden("This account is banned"));
            }
            c.execute(
                "INSERT INTO sessions(token_hash, user_id, created_day) VALUES(?, ?, ?)",
                params![th, uid, today()],
            )?;
            Ok(Some(LoginResp {
                token,
                user_id: uid,
                account_pk: B64(pk),
                key_blob: B64(blob),
                generation,
                is_admin,
            }))
        })
        .await?;
    match res {
        Some(r) => {
            record_ok(&st, &username);
            Ok(Json(r))
        }
        None => {
            record_fail(&st, &username);
            Err(ApiErr::Status(
                StatusCode::UNAUTHORIZED,
                "Wrong username or password".into(),
            ))
        }
    }
}

async fn register_device(
    State(st): State<AppState>,
    s: Session,
    Json(req): Json<DeviceReq>,
) -> R<DeviceResp> {
    if s.device_id.is_some() {
        return Err(ApiErr::bad("session already has a device"));
    }
    let (did, chans) = st
        .db
        .run(move |c| -> Result<(i64, Vec<i64>), ApiErr> {
            let tx = c.transaction()?;
            let pk: Vec<u8> = tx.query_row(
                "SELECT account_pk FROM users WHERE id = ?",
                [s.user_id],
                |r| r.get(0),
            )?;
            // The account key must vouch for the device. Clients enforce this
            // too; checking here keeps junk out.
            if !verify_ed25519(&pk, &device_binding(s.user_id, &req.sig_pk.0), &req.account_sig.0) {
                return Err(ApiErr::bad("bad device signature"));
            }
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM devices WHERE user_id = ?",
                [s.user_id],
                |r| r.get(0),
            )?;
            if n >= MAX_DEVICES_PER_USER {
                return Err(ApiErr::bad("Too many devices. Log out somewhere else first."));
            }
            tx.execute(
                "INSERT INTO devices(user_id, sig_pk) VALUES(?, ?)",
                params![s.user_id, req.sig_pk.0],
            )?;
            let did = tx.last_insert_rowid();
            tx.execute(
                "UPDATE sessions SET device_id = ? WHERE token_hash = ?",
                params![did, s.token_hash],
            )?;
            // Ask every populated channel to let this device in.
            tx.execute(
                "INSERT OR IGNORE INTO joins(channel_id, device_id)
                 SELECT DISTINCT channel_id, ? FROM members",
                [did],
            )?;
            let chans: Vec<i64> = {
                let mut q = tx.prepare("SELECT channel_id FROM joins WHERE device_id = ?")?;
                let rows = q.query_map([did], |r| r.get(0))?;
                rows.collect::<rusqlite::Result<_>>()?
            };
            tx.commit()?;
            Ok((did, chans))
        })
        .await?;
    notify_pending(&st, chans).await;
    Ok(Json(DeviceResp { device_id: did }))
}

fn verify_ed25519(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(pk) = <[u8; 32]>::try_from(pk) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    let Ok(sig) = Signature::from_slice(sig) else { return false };
    vk.verify(msg, &sig).is_ok()
}

async fn notify_pending(st: &AppState, chans: Vec<i64>) {
    for ch in chans {
        let members = st
            .db
            .run(move |c| db::channel_members(c, ch))
            .await
            .unwrap_or_default();
        st.hub
            .send_many(&members, ServerWs::Pending { channel_id: ch });
    }
}

async fn logout(State(st): State<AppState>, s: Session) -> R<()> {
    let th = s.token_hash.clone();
    let device = s.device_id;
    let chans = st
        .db
        .run(move |c| -> rusqlite::Result<Vec<i64>> {
            let tx = c.transaction()?;
            let chans = match device {
                Some(d) => db::revoke_device(&tx, d)?,
                None => vec![],
            };
            tx.execute("DELETE FROM sessions WHERE token_hash = ?", [&th])?;
            tx.commit()?;
            Ok(chans)
        })
        .await?;
    if let Some(d) = device {
        st.hub.revoke(d);
    }
    notify_pending(&st, chans).await;
    Ok(Json(()))
}

/// Changing the password resets EVERYTHING: new account identity, every
/// device and session killed, removed from every encrypted group.
async fn change_password(
    State(st): State<AppState>,
    s: Session,
    Json(req): Json<PasswordChangeReq>,
) -> R<()> {
    if req.new_auth_key.0.len() != 32
        || req.new_account_pk.0.len() != 32
        || req.new_salt.0.len() < 16
        || req.new_key_blob.0.len() > 256
    {
        return Err(ApiErr::bad("malformed keys"));
    }
    let uid = s.user_id;
    let (devices, chans) = st
        .db
        .run(move |c| -> Result<(Vec<i64>, Vec<i64>), ApiErr> {
            let tx = c.transaction()?;
            let hash: Vec<u8> =
                tx.query_row("SELECT auth_hash FROM users WHERE id = ?", [uid], |r| r.get(0))?;
            if !bool::from(auth_hash(&req.old_auth_key.0).ct_eq(&hash)) {
                return Err(ApiErr::forbidden("Current password is wrong"));
            }
            let out = db::revoke_user(&tx, uid)?;
            tx.execute(
                "UPDATE users SET auth_hash = ?, salt = ?, account_pk = ?, key_blob = ?, generation = generation + 1 WHERE id = ?",
                params![
                    auth_hash(&req.new_auth_key.0),
                    req.new_salt.0,
                    req.new_account_pk.0,
                    req.new_key_blob.0,
                    uid
                ],
            )?;
            tx.commit()?;
            Ok(out)
        })
        .await?;
    for d in devices {
        st.hub.revoke(d);
    }
    notify_pending(&st, chans).await;
    st.hub.broadcast(ServerWs::State);
    Ok(Json(()))
}

async fn upload_key_packages(
    State(st): State<AppState>,
    d: Dev,
    Json(req): Json<KeyPackagesReq>,
) -> R<()> {
    if req.packages.len() > 100 || req.packages.iter().any(|p| p.0.len() > 8192) {
        return Err(ApiErr::bad("too many / too large key packages"));
    }
    let chans = st
        .db
        .run(move |c| -> rusqlite::Result<Vec<i64>> {
            let tx = c.transaction()?;
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM key_packages WHERE device_id = ?",
                [d.device_id],
                |r| r.get(0),
            )?;
            for p in req.packages.iter().take((MAX_KEY_PACKAGES - n).max(0) as usize) {
                tx.execute(
                    "INSERT INTO key_packages(device_id, data) VALUES(?, ?)",
                    params![d.device_id, p.0],
                )?;
            }
            let chans = {
                let mut q = tx.prepare("SELECT channel_id FROM joins WHERE device_id = ?")?;
                let rows = q.query_map([d.device_id], |r| r.get(0))?;
                rows.collect::<rusqlite::Result<_>>()?
            };
            tx.commit()?;
            Ok(chans)
        })
        .await?;
    notify_pending(&st, chans).await;
    Ok(Json(()))
}

async fn state(State(st): State<AppState>, d: Dev) -> R<StateResp> {
    let res = st
        .db
        .run(move |c| -> rusqlite::Result<StateResp> {
            let (username, generation): (String, i64) = c.query_row(
                "SELECT username, generation FROM users WHERE id = ?",
                [d.user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let kps: i64 = c.query_row(
                "SELECT COUNT(*) FROM key_packages WHERE device_id = ?",
                [d.device_id],
                |r| r.get(0),
            )?;
            let mut q = c.prepare(
                "SELECT ch.id, ch.name, ch.topic, ch.position, ch.epoch, ch.generation, ch.ttl_hours,
                   (SELECT COUNT(*) FROM members m WHERE m.channel_id = ch.id),
                   EXISTS(SELECT 1 FROM members m WHERE m.channel_id = ch.id AND m.device_id = ?1),
                   COALESCE((SELECT MAX(seq) FROM log l WHERE l.channel_id = ch.id), 0),
                   EXISTS(SELECT 1 FROM removals r WHERE r.channel_id = ch.id)
                     OR EXISTS(SELECT 1 FROM joins j WHERE j.channel_id = ch.id
                               AND EXISTS(SELECT 1 FROM key_packages k WHERE k.device_id = j.device_id)),
                   EXISTS(SELECT 1 FROM welcomes w WHERE w.channel_id = ch.id AND w.device_id = ?1)
                 FROM channels ch ORDER BY ch.position, ch.id",
            )?;
            let channels = q
                .query_map([d.device_id], |r| {
                    Ok(proto::Channel {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        topic: r.get(2)?,
                        position: r.get(3)?,
                        epoch: r.get(4)?,
                        generation: r.get(5)?,
                        ttl_hours: r.get(6)?,
                        member_count: r.get(7)?,
                        is_member: r.get(8)?,
                        head_seq: r.get(9)?,
                        has_pending: r.get(10)?,
                        has_welcome: r.get(11)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            let mut q = c.prepare(
                "SELECT id, username, account_pk, is_admin FROM users WHERE banned = 0 ORDER BY username",
            )?;
            let users = q
                .query_map([], |r| {
                    Ok(DirectoryUser {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        account_pk: B64(r.get(2)?),
                        is_admin: r.get::<_, i64>(3)? != 0,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(StateResp {
                user_id: d.user_id,
                device_id: d.device_id,
                username,
                is_admin: d.is_admin,
                generation,
                key_packages_left: kps,
                channels,
                users,
            })
        })
        .await?;
    Ok(Json(res))
}

async fn welcomes(State(st): State<AppState>, d: Dev) -> R<WelcomesResp> {
    let w = st
        .db
        .run(move |c| -> rusqlite::Result<Vec<proto::Welcome>> {
            let mut q = c.prepare(
                "SELECT channel_id, generation, commit_seq, data FROM welcomes WHERE device_id = ? ORDER BY commit_seq",
            )?;
            let rows = q.query_map([d.device_id], |r| {
                Ok(proto::Welcome {
                    channel_id: r.get(0)?,
                    generation: r.get(1)?,
                    commit_seq: r.get(2)?,
                    data: B64(r.get(3)?),
                })
            })?;
            rows.collect()
        })
        .await?;
    Ok(Json(WelcomesResp { welcomes: w }))
}

async fn ack_welcome(
    State(st): State<AppState>,
    d: Dev,
    Json(req): Json<AckWelcomeReq>,
) -> R<()> {
    let ch = req.channel_id;
    let requeued = st
        .db
        .run(move |c| -> rusqlite::Result<bool> {
            let tx = c.transaction()?;
            tx.execute(
                "DELETE FROM welcomes WHERE device_id = ? AND channel_id = ?",
                params![d.device_id, ch],
            )?;
            if req.failed {
                requeue(&tx, ch, d.device_id)?;
            }
            tx.commit()?;
            Ok(req.failed)
        })
        .await?;
    if requeued {
        notify_pending(&st, vec![ch]).await;
    }
    Ok(Json(()))
}

/// Take a device out of a group and queue it to be added again.
fn requeue(tx: &rusqlite::Connection, ch: i64, device: i64) -> rusqlite::Result<()> {
    let was_member = tx.execute(
        "DELETE FROM members WHERE channel_id = ? AND device_id = ?",
        params![ch, device],
    )? > 0;
    if was_member {
        tx.execute(
            "INSERT OR IGNORE INTO removals(channel_id, device_id) VALUES(?, ?)",
            params![ch, device],
        )?;
    }
    tx.execute(
        "DELETE FROM welcomes WHERE channel_id = ? AND device_id = ?",
        params![ch, device],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO joins(channel_id, device_id) VALUES(?, ?)",
        params![ch, device],
    )?;
    Ok(())
}

#[derive(Deserialize)]
struct After {
    after: Option<i64>,
}

async fn channel_log(
    State(st): State<AppState>,
    _d: Dev,
    Path(ch): Path<i64>,
    Query(q): Query<After>,
) -> R<LogResp> {
    let after = q.after.unwrap_or(0);
    let res = st
        .db
        .run(move |c| -> Result<LogResp, ApiErr> {
            let purged: Option<i64> = c
                .query_row("SELECT purged_upto FROM channels WHERE id = ?", [ch], |r| r.get(0))
                .optional()?;
            let purged = purged.ok_or_else(ApiErr::not_found)?;
            let mut q = c.prepare(
                "SELECT seq, kind, epoch, generation, data FROM log WHERE channel_id = ? AND seq > ? ORDER BY seq LIMIT 500",
            )?;
            let entries = q
                .query_map(params![ch, after], |r| {
                    Ok(LogEntry {
                        seq: r.get(0)?,
                        kind: match r.get::<_, i64>(1)? {
                            0 => LogKind::App,
                            1 => LogKind::Commit,
                            _ => LogKind::Founded,
                        },
                        epoch: r.get(2)?,
                        generation: r.get(3)?,
                        data: B64(r.get(4)?),
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(LogResp {
                entries,
                floor: purged + 1,
            })
        })
        .await?;
    Ok(Json(res))
}

/// Shared epoch/generation/membership gate for sends and commits.
fn gate(tx: &rusqlite::Connection, ch: i64, device: i64, epoch: i64, generation: i64) -> Result<(), ApiErr> {
    let row: Option<(i64, i64)> = tx
        .query_row(
            "SELECT epoch, generation FROM channels WHERE id = ?",
            [ch],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (cur_epoch, cur_gen) = row.ok_or_else(ApiErr::not_found)?;
    let member: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM members WHERE channel_id = ? AND device_id = ?)",
        params![ch, device],
        |r| r.get(0),
    )?;
    if !member {
        return Err(ApiErr::forbidden("not a member of this channel"));
    }
    if cur_epoch != epoch || cur_gen != generation {
        return Err(ApiErr::Conflict(Conflict {
            epoch: cur_epoch,
            generation: cur_gen,
        }));
    }
    Ok(())
}

async fn send(
    State(st): State<AppState>,
    d: Dev,
    Path(ch): Path<i64>,
    Json(req): Json<SendReq>,
) -> R<SendResp> {
    if req.data.0.len() > MAX_BLOB {
        return Err(ApiErr::bad("message too large"));
    }
    let (seq, members) = st
        .db
        .run(move |c| -> Result<(i64, Vec<i64>), ApiErr> {
            let tx = c.transaction()?;
            gate(&tx, ch, d.device_id, req.epoch, req.generation)?;
            // Note: the sender is deliberately NOT stored.
            tx.execute(
                "INSERT INTO log(channel_id, kind, epoch, generation, data, hour) VALUES(?, 0, ?, ?, ?, ?)",
                params![ch, req.epoch, req.generation, req.data.0, this_hour()],
            )?;
            let seq = tx.last_insert_rowid();
            let members = db::channel_members(&tx, ch)?;
            tx.commit()?;
            Ok((seq, members))
        })
        .await?;
    st.hub
        .send_many(&members, ServerWs::Log { channel_id: ch, seq });
    Ok(Json(SendResp { seq }))
}

async fn commit(
    State(st): State<AppState>,
    d: Dev,
    Path(ch): Path<i64>,
    Json(req): Json<CommitReq>,
) -> R<SendResp> {
    if req.commit.0.len() > MAX_BLOB * 4
        || req.welcome.as_ref().map(|w| w.0.len()).unwrap_or(0) > MAX_BLOB * 16
    {
        return Err(ApiErr::bad("commit too large"));
    }
    if !req.added.is_empty() && req.welcome.is_none() {
        return Err(ApiErr::bad("adds need a welcome"));
    }
    let (seq, members, welcomed) = st
        .db
        .run(move |c| -> Result<(i64, Vec<i64>, Vec<i64>), ApiErr> {
            let tx = c.transaction()?;
            gate(&tx, ch, d.device_id, req.epoch, req.generation)?;
            tx.execute(
                "INSERT INTO log(channel_id, kind, epoch, generation, data, hour) VALUES(?, 1, ?, ?, ?, ?)",
                params![ch, req.epoch, req.generation, req.commit.0, this_hour()],
            )?;
            let seq = tx.last_insert_rowid();
            tx.execute("UPDATE channels SET epoch = epoch + 1 WHERE id = ?", [ch])?;
            let mut welcomed = vec![];
            for a in &req.added {
                let alive: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices WHERE id = ?)",
                    [a.device_id],
                    |r| r.get(0),
                )?;
                tx.execute(
                    "DELETE FROM key_packages WHERE id = ? AND device_id = ?",
                    params![a.key_package_id, a.device_id],
                )?;
                tx.execute(
                    "DELETE FROM joins WHERE channel_id = ? AND device_id = ?",
                    params![ch, a.device_id],
                )?;
                if alive {
                    tx.execute(
                        "INSERT OR IGNORE INTO members(channel_id, device_id) VALUES(?, ?)",
                        params![ch, a.device_id],
                    )?;
                    tx.execute(
                        "INSERT OR REPLACE INTO welcomes(device_id, channel_id, generation, commit_seq, data) VALUES(?, ?, ?, ?, ?)",
                        params![a.device_id, ch, req.generation, seq, req.welcome.as_ref().unwrap().0],
                    )?;
                    welcomed.push(a.device_id);
                } else {
                    // Device vanished between pending and commit: evict it next.
                    tx.execute(
                        "INSERT OR IGNORE INTO removals(channel_id, device_id) VALUES(?, ?)",
                        params![ch, a.device_id],
                    )?;
                }
            }
            for r in &req.removed {
                tx.execute(
                    "DELETE FROM removals WHERE channel_id = ? AND device_id = ?",
                    params![ch, r],
                )?;
                tx.execute(
                    "DELETE FROM members WHERE channel_id = ? AND device_id = ?",
                    params![ch, r],
                )?;
            }
            let members = db::channel_members(&tx, ch)?;
            tx.commit()?;
            Ok((seq, members, welcomed))
        })
        .await?;
    st.hub
        .send_many(&members, ServerWs::Log { channel_id: ch, seq });
    st.hub
        .send_many(&welcomed, ServerWs::Welcome { channel_id: ch });
    Ok(Json(SendResp { seq }))
}

async fn found(
    State(st): State<AppState>,
    d: Dev,
    Path(ch): Path<i64>,
    Json(req): Json<FoundReq>,
) -> R<FoundResp> {
    let res = st
        .db
        .run(move |c| -> Result<FoundResp, ApiErr> {
            let tx = c.transaction()?;
            let row: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT epoch, generation FROM channels WHERE id = ?",
                    [ch],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (epoch, generation) = row.ok_or_else(ApiErr::not_found)?;
            if db::member_count(&tx, ch)? > 0 || generation != req.generation {
                return Err(ApiErr::Conflict(Conflict { epoch, generation }));
            }
            let generation = generation + 1;
            tx.execute(
                "UPDATE channels SET generation = ?, epoch = 0 WHERE id = ?",
                params![generation, ch],
            )?;
            tx.execute("DELETE FROM joins WHERE channel_id = ?", [ch])?;
            tx.execute("DELETE FROM removals WHERE channel_id = ?", [ch])?;
            tx.execute("DELETE FROM welcomes WHERE channel_id = ?", [ch])?;
            tx.execute(
                "INSERT INTO members(channel_id, device_id) VALUES(?, ?)",
                params![ch, d.device_id],
            )?;
            tx.execute(
                "INSERT INTO log(channel_id, kind, epoch, generation, data, hour) VALUES(?, 2, 0, ?, x'', ?)",
                params![ch, generation, this_hour()],
            )?;
            let seq = tx.last_insert_rowid();
            tx.execute(
                "INSERT OR IGNORE INTO joins(channel_id, device_id) SELECT ?, id FROM devices WHERE id != ?",
                params![ch, d.device_id],
            )?;
            tx.commit()?;
            Ok(FoundResp { generation, seq })
        })
        .await?;
    st.hub.broadcast(ServerWs::State);
    st.hub.send(d.device_id, ServerWs::Pending { channel_id: ch });
    Ok(Json(res))
}

async fn pending(State(st): State<AppState>, d: Dev, Path(ch): Path<i64>) -> R<PendingResp> {
    let res = st
        .db
        .run(move |c| -> Result<PendingResp, ApiErr> {
            let member: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM members WHERE channel_id = ? AND device_id = ?)",
                params![ch, d.device_id],
                |r| r.get(0),
            )?;
            if !member {
                return Err(ApiErr::forbidden("not a member"));
            }
            let mut q = c.prepare(
                "SELECT j.device_id, dv.user_id, k.id, k.data FROM joins j
                 JOIN devices dv ON dv.id = j.device_id
                 JOIN key_packages k ON k.id = (SELECT MIN(id) FROM key_packages WHERE device_id = j.device_id)
                 WHERE j.channel_id = ? LIMIT 50",
            )?;
            let joins = q
                .query_map([ch], |r| {
                    Ok(PendingJoin {
                        device_id: r.get(0)?,
                        user_id: r.get(1)?,
                        key_package_id: r.get(2)?,
                        key_package: B64(r.get(3)?),
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            let mut q = c.prepare("SELECT device_id FROM removals WHERE channel_id = ? LIMIT 100")?;
            let removals = q
                .query_map([ch], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(PendingResp { joins, removals })
        })
        .await?;
    Ok(Json(res))
}

async fn dismiss(
    State(st): State<AppState>,
    d: Dev,
    Path(ch): Path<i64>,
    Json(req): Json<DismissReq>,
) -> R<()> {
    st.db
        .run(move |c| -> Result<(), ApiErr> {
            let tx = c.transaction()?;
            let member: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM members WHERE channel_id = ? AND device_id = ?)",
                params![ch, d.device_id],
                |r| r.get(0),
            )?;
            if !member {
                return Err(ApiErr::forbidden("not a member"));
            }
            for j in &req.joins {
                tx.execute(
                    "DELETE FROM joins WHERE channel_id = ? AND device_id = ?",
                    params![ch, j],
                )?;
            }
            for r in &req.removals {
                tx.execute(
                    "DELETE FROM removals WHERE channel_id = ? AND device_id = ?",
                    params![ch, r],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(Json(()))
}

async fn rejoin(State(st): State<AppState>, d: Dev, Path(ch): Path<i64>) -> R<()> {
    st.db
        .run(move |c| -> rusqlite::Result<()> {
            let tx = c.transaction()?;
            requeue(&tx, ch, d.device_id)?;
            tx.commit()
        })
        .await?;
    notify_pending(&st, vec![ch]).await;
    st.hub.send(d.device_id, ServerWs::State);
    Ok(Json(()))
}

// ---------------- websocket ----------------

async fn ws(State(st): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    upgrade
        .max_message_size(4096)
        .on_upgrade(move |sock| ws_loop(st, sock))
}

async fn ws_loop(st: AppState, sock: WebSocket) {
    let (mut tx, mut rx) = sock.split();
    // First frame must authenticate (token never goes in the URL/logs).
    let first = tokio::time::timeout(Duration::from_secs(10), rx.next()).await;
    let token = match first {
        Ok(Some(Ok(Message::Text(t)))) => match serde_json::from_str::<ClientWs>(&t) {
            Ok(ClientWs::Auth { token }) => token,
            _ => return,
        },
        _ => return,
    };
    let Ok(Some(sess)) = session_for_token(&st, &token).await else {
        let _ = tx
            .send(Message::Text(serde_json::to_string(&ServerWs::Revoked).unwrap().into()))
            .await;
        return;
    };
    let Some(device) = sess.device_id else { return };
    let (etx, mut erx) = tokio::sync::mpsc::unbounded_channel();
    let id = st.hub.register(device, etx);
    let _ = tx
        .send(Message::Text(serde_json::to_string(&ServerWs::Ready).unwrap().into()))
        .await;
    loop {
        tokio::select! {
            ev = erx.recv() => {
                let Some(ev) = ev else { break };
                let revoked = matches!(ev, ServerWs::Revoked);
                if tx.send(Message::Text(serde_json::to_string(&ev).unwrap().into())).await.is_err() {
                    break;
                }
                if revoked { break; }
            }
            msg = rx.next() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        if let Ok(ClientWs::Ping) = serde_json::from_str::<ClientWs>(&t) {
                            if tx.send(Message::Text(serde_json::to_string(&ServerWs::Pong).unwrap().into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
    st.hub.unregister(device, id);
}

// ---------------- admin ----------------

async fn admin_users(State(st): State<AppState>, _a: Admin) -> R<AdminUsersResp> {
    let res = st
        .db
        .run(|c| -> rusqlite::Result<AdminUsersResp> {
            let mut q = c.prepare(
                "SELECT u.id, u.username, u.is_admin, u.banned, u.created_day,
                        (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id)
                 FROM users u ORDER BY u.id",
            )?;
            let users = q
                .query_map([], |r| {
                    Ok(AdminUser {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        is_admin: r.get::<_, i64>(2)? != 0,
                        banned: r.get::<_, i64>(3)? != 0,
                        created_day: r.get(4)?,
                        devices: r.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(AdminUsersResp {
                users,
                registration_open: db::registration_open(c)?,
            })
        })
        .await?;
    Ok(Json(res))
}

async fn kick_user(st: &AppState, uid: i64, ban: Option<bool>, delete: bool) -> Result<(), ApiErr> {
    let (devices, chans) = st
        .db
        .run(move |c| -> Result<(Vec<i64>, Vec<i64>), ApiErr> {
            let tx = c.transaction()?;
            let is_admin: Option<bool> = tx
                .query_row("SELECT is_admin FROM users WHERE id = ?", [uid], |r| {
                    Ok(r.get::<_, i64>(0)? != 0)
                })
                .optional()?;
            let is_admin = is_admin.ok_or_else(ApiErr::not_found)?;
            if is_admin && (ban == Some(true) || delete) {
                return Err(ApiErr::forbidden("Remove admin rights first"));
            }
            let out = if ban == Some(false) {
                (vec![], vec![])
            } else {
                db::revoke_user(&tx, uid)?
            };
            if let Some(b) = ban {
                tx.execute("UPDATE users SET banned = ? WHERE id = ?", params![b as i64, uid])?;
            }
            if delete {
                tx.execute("DELETE FROM users WHERE id = ?", [uid])?;
            }
            tx.commit()?;
            Ok(out)
        })
        .await?;
    for d in devices {
        st.hub.revoke(d);
    }
    notify_pending(st, chans).await;
    st.hub.broadcast(ServerWs::State);
    Ok(())
}

async fn admin_ban(State(st): State<AppState>, _a: Admin, Path(uid): Path<i64>) -> R<()> {
    kick_user(&st, uid, Some(true), false).await?;
    Ok(Json(()))
}

async fn admin_unban(State(st): State<AppState>, _a: Admin, Path(uid): Path<i64>) -> R<()> {
    kick_user(&st, uid, Some(false), false).await?;
    Ok(Json(()))
}

async fn admin_delete_user(State(st): State<AppState>, _a: Admin, Path(uid): Path<i64>) -> R<()> {
    kick_user(&st, uid, None, true).await?;
    Ok(Json(()))
}

async fn admin_toggle_admin(State(st): State<AppState>, a: Admin, Path(uid): Path<i64>) -> R<()> {
    if uid == a.0.user_id {
        return Err(ApiErr::bad("You can't change your own admin rights"));
    }
    st.db
        .run(move |c| -> Result<(), ApiErr> {
            let n = c.execute(
                "UPDATE users SET is_admin = 1 - is_admin WHERE id = ? AND banned = 0",
                [uid],
            )?;
            if n == 0 {
                return Err(ApiErr::not_found());
            }
            Ok(())
        })
        .await?;
    st.hub.broadcast(ServerWs::State);
    Ok(Json(()))
}

fn clean_channel(req: &ChannelUpsert) -> Result<(String, String, i64), ApiErr> {
    let name = normalize_channel_name(&req.name).ok_or_else(|| ApiErr::bad("Bad channel name"))?;
    let topic: String = req.topic.trim().chars().take(200).collect();
    if !(0..=24 * 365).contains(&req.ttl_hours) {
        return Err(ApiErr::bad("Bad TTL"));
    }
    Ok((name, topic, req.ttl_hours))
}

async fn admin_create_channel(
    State(st): State<AppState>,
    _a: Admin,
    Json(req): Json<ChannelUpsert>,
) -> R<()> {
    let (name, topic, ttl) = clean_channel(&req)?;
    st.db
        .run(move |c| -> Result<(), ApiErr> {
            let pos: i64 = c.query_row("SELECT COALESCE(MAX(position), 0) + 1 FROM channels", [], |r| r.get(0))?;
            c.execute(
                "INSERT INTO channels(name, topic, position, ttl_hours) VALUES(?, ?, ?, ?)",
                params![name, topic, pos, ttl],
            )
            .map_err(|_| ApiErr::bad("Channel name already exists"))?;
            Ok(())
        })
        .await?;
    st.hub.broadcast(ServerWs::State);
    Ok(Json(()))
}

async fn admin_update_channel(
    State(st): State<AppState>,
    _a: Admin,
    Path(id): Path<i64>,
    Json(req): Json<ChannelUpsert>,
) -> R<()> {
    let (name, topic, ttl) = clean_channel(&req)?;
    st.db
        .run(move |c| -> Result<(), ApiErr> {
            let n = c
                .execute(
                    "UPDATE channels SET name = ?, topic = ?, ttl_hours = ? WHERE id = ?",
                    params![name, topic, ttl, id],
                )
                .map_err(|_| ApiErr::bad("Channel name already exists"))?;
            if n == 0 {
                return Err(ApiErr::not_found());
            }
            Ok(())
        })
        .await?;
    st.hub.broadcast(ServerWs::State);
    Ok(Json(()))
}

async fn admin_delete_channel(State(st): State<AppState>, _a: Admin, Path(id): Path<i64>) -> R<()> {
    st.db
        .run(move |c| c.execute("DELETE FROM channels WHERE id = ?", [id]))
        .await?;
    st.hub.broadcast(ServerWs::State);
    Ok(Json(()))
}

/// Moderators can delete a message they can see (they can't read others').
async fn admin_delete_entry(State(st): State<AppState>, _a: Admin, Path(seq): Path<i64>) -> R<()> {
    let ch = st
        .db
        .run(move |c| -> rusqlite::Result<Option<i64>> {
            let ch: Option<i64> = c
                .query_row(
                    "SELECT channel_id FROM log WHERE seq = ? AND kind = 0",
                    [seq],
                    |r| r.get(0),
                )
                .optional()?;
            if ch.is_some() {
                c.execute("DELETE FROM log WHERE seq = ?", [seq])?;
            }
            Ok(ch)
        })
        .await?;
    let ch = ch.ok_or_else(ApiErr::not_found)?;
    st.hub
        .broadcast(ServerWs::Deleted { channel_id: ch, seq });
    Ok(Json(()))
}

async fn admin_settings(
    State(st): State<AppState>,
    _a: Admin,
    Json(req): Json<SettingsReq>,
) -> R<()> {
    st.db
        .run(move |c| {
            db::meta_set(
                c,
                "registration_open",
                if req.registration_open { b"1" } else { b"0" },
            )
        })
        .await?;
    Ok(Json(()))
}
