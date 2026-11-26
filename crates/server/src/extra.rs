//! DMs, ephemeral relay, encrypted attachments, TURN credentials, push.

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use bunkr_proto::*;
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::api::{gate, new_token, now_secs, sha, this_hour, ApiErr, AppState, Dev, R};
use crate::db;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/dms", post(open_dm))
        .route("/api/dms/{id}/ttl", put(dm_ttl))
        .route("/api/channels/{id}/ephemeral", post(ephemeral))
        .route(
            "/api/channels/{id}/blobs",
            post(upload_blob).layer(DefaultBodyLimit::disable()),
        )
        .route("/api/blobs/{id}", get(get_blob).delete(delete_blob))
        .route("/api/turn", get(turn))
        .route("/api/push/vapid", get(vapid))
        .route(
            "/api/push/subscribe",
            post(push_subscribe).delete(push_unsubscribe),
        )
}

// ---------------- DMs ----------------

async fn open_dm(State(st): State<AppState>, d: Dev, Json(req): Json<DmReq>) -> R<DmResp> {
    if req.user_id == d.user_id {
        return Err(ApiErr::bad("You can't DM yourself"));
    }
    let me = d.user_id;
    let (id, created) = st
        .db
        .run(move |c| -> Result<(i64, bool), ApiErr> {
            let tx = c.transaction()?;
            let ok: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id = ? AND banned = 0)",
                [req.user_id],
                |r| r.get(0),
            )?;
            if !ok {
                return Err(ApiErr::not_found());
            }
            let (a, b) = (me.min(req.user_id), me.max(req.user_id));
            let name = format!("dm-{a}-{b}");
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT id FROM channels WHERE name = ? AND kind = 'dm'",
                    [&name],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = existing {
                return Ok((id, false));
            }
            tx.execute(
                "INSERT INTO channels(name, topic, position, kind) VALUES(?, '', 1000000, 'dm')",
                [&name],
            )?;
            let id = tx.last_insert_rowid();
            for u in [a, b] {
                tx.execute(
                    "INSERT INTO channel_users(channel_id, user_id) VALUES(?, ?)",
                    params![id, u],
                )?;
            }
            tx.commit()?;
            Ok((id, true))
        })
        .await?;
    if created {
        st.hub.broadcast(ServerWs::State);
    }
    Ok(Json(DmResp { channel_id: id }))
}

/// Either participant can turn on disappearing messages in a DM.
async fn dm_ttl(
    State(st): State<AppState>,
    d: Dev,
    Path(id): Path<i64>,
    Json(req): Json<TtlReq>,
) -> R<()> {
    if !(0..=24 * 365).contains(&req.ttl_hours) {
        return Err(ApiErr::bad("Bad TTL"));
    }
    st.db
        .run(move |c| -> Result<(), ApiErr> {
            let n = c.execute(
                "UPDATE channels SET ttl_hours = ? WHERE id = ? AND kind = 'dm'
                 AND EXISTS(SELECT 1 FROM channel_users WHERE channel_id = ? AND user_id = ?)",
                params![req.ttl_hours, id, id, d.user_id],
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

// ---------------- ephemeral ----------------

/// Relay an MLS message to the other online members without storing it.
async fn ephemeral(
    State(st): State<AppState>,
    d: Dev,
    Path(ch): Path<i64>,
    Json(req): Json<SendReq>,
) -> R<()> {
    if req.data.0.len() > 64 * 1024 {
        return Err(ApiErr::bad("too large"));
    }
    if !st.allow(format!("eph:{}", d.device_id), 20.0, 60.0) {
        return Err(ApiErr::Status(
            StatusCode::TOO_MANY_REQUESTS,
            "slow down".into(),
        ));
    }
    let members = st
        .db
        .run(move |c| -> Result<Vec<i64>, ApiErr> {
            gate(c, ch, d.device_id, req.epoch, req.generation)?;
            Ok(db::channel_members(c, ch)?)
        })
        .await?;
    let others: Vec<i64> = members.into_iter().filter(|m| *m != d.device_id).collect();
    st.hub.send_many(
        &others,
        ServerWs::Ephemeral {
            channel_id: ch,
            data: req.data,
        },
    );
    Ok(Json(()))
}

// ---------------- attachments ----------------

fn blob_path(st: &AppState, id: &str) -> std::path::PathBuf {
    st.cfg.data_dir.join("blobs").join(&id[..2]).join(id)
}

fn valid_blob_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn remove_blob_files(st: &AppState, ids: &[String]) {
    for id in ids {
        if valid_blob_id(id) {
            let _ = std::fs::remove_file(blob_path(st, id));
        }
    }
}

/// Upload an already-encrypted attachment. The server never sees the key.
async fn upload_blob(
    State(st): State<AppState>,
    d: Dev,
    Path(ch): Path<i64>,
    body: Bytes,
) -> Result<Json<BlobResp>, ApiErr> {
    if body.is_empty() {
        return Err(ApiErr::bad("empty upload"));
    }
    if body.len() as u64 > st.cfg.max_upload {
        return Err(ApiErr::Status(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "File too large (max {} MB)",
                st.cfg.max_upload / 1024 / 1024
            ),
        ));
    }
    if !st.allow(format!("blob:{}", d.user_id), 1.0, 30.0) {
        return Err(ApiErr::Status(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many uploads, slow down".into(),
        ));
    }
    let (member, used) = st
        .db
        .run(move |c| -> rusqlite::Result<(bool, i64)> {
            let m = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM members WHERE channel_id = ? AND device_id = ?)",
                params![ch, d.device_id],
                |r| r.get::<_, bool>(0),
            )?;
            let used = c.query_row("SELECT COALESCE(SUM(size), 0) FROM blobs", [], |r| r.get(0))?;
            Ok((m, used))
        })
        .await?;
    if !member {
        return Err(ApiErr::forbidden("not a member"));
    }
    if used as u64 + body.len() as u64 > st.cfg.max_storage {
        return Err(ApiErr::Status(
            StatusCode::INSUFFICIENT_STORAGE,
            "This server's attachment storage is full".into(),
        ));
    }
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let id = hex::encode(raw);
    let token = new_token();
    let path = blob_path(&st, &id);
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|_| ApiErr::bad("storage error"))?;
    }
    tokio::fs::write(&path, &body)
        .await
        .map_err(|_| ApiErr::bad("storage error"))?;
    let (id2, size, hash) = (id.clone(), body.len() as i64, sha(token.as_bytes()));
    st.db
        .run(move |c| {
            c.execute(
                "INSERT INTO blobs(id, channel_id, size, hour, delete_hash) VALUES(?, ?, ?, ?, ?)",
                params![id2, ch, size, this_hour(), hash],
            )
        })
        .await?;
    Ok(Json(BlobResp {
        id,
        delete_token: token,
    }))
}

async fn get_blob(
    State(st): State<AppState>,
    d: Dev,
    Path(id): Path<String>,
) -> Result<Response, ApiErr> {
    if !valid_blob_id(&id) {
        return Err(ApiErr::not_found());
    }
    let id2 = id.clone();
    let ok = st
        .db
        .run(move |c| -> rusqlite::Result<bool> {
            let ch: Option<i64> = c
                .query_row("SELECT channel_id FROM blobs WHERE id = ?", [&id2], |r| {
                    r.get(0)
                })
                .optional()?;
            match ch {
                Some(ch) => db::allowed(c, ch, d.device_id),
                None => Ok(false),
            }
        })
        .await?;
    if !ok {
        return Err(ApiErr::not_found());
    }
    let bytes = tokio::fs::read(blob_path(&st, &id))
        .await
        .map_err(|_| ApiErr::not_found())?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "private, max-age=86400, immutable"),
        ],
        bytes,
    )
        .into_response())
}

#[derive(Deserialize)]
struct TokenQ {
    token: String,
}

async fn delete_blob(
    State(st): State<AppState>,
    _d: Dev,
    Path(id): Path<String>,
    Query(q): Query<TokenQ>,
) -> R<()> {
    if !valid_blob_id(&id) {
        return Err(ApiErr::not_found());
    }
    let id2 = id.clone();
    let hash = sha(q.token.as_bytes());
    st.db
        .run(move |c| -> Result<(), ApiErr> {
            let stored: Option<Vec<u8>> = c
                .query_row("SELECT delete_hash FROM blobs WHERE id = ?", [&id2], |r| {
                    r.get(0)
                })
                .optional()?;
            let stored = stored.ok_or_else(ApiErr::not_found)?;
            if !bool::from(stored.ct_eq(&hash)) {
                return Err(ApiErr::forbidden("not yours"));
            }
            c.execute("DELETE FROM blobs WHERE id = ?", [&id2])?;
            Ok(())
        })
        .await?;
    remove_blob_files(&st, &[id]);
    Ok(Json(()))
}

// ---------------- calls ----------------

/// Short-lived TURN credentials (coturn "use-auth-secret" scheme). The
/// username carries no user id: just an expiry and a random tag.
async fn turn(State(st): State<AppState>, _d: Dev) -> R<TurnResp> {
    use hmac::{Hmac, Mac};
    let mut ice_servers = vec![];
    if !st.cfg.stun_urls.is_empty() {
        ice_servers.push(IceServer {
            urls: st.cfg.stun_urls.clone(),
            username: None,
            credential: None,
        });
    }
    if let (false, Some(secret)) = (st.cfg.turn_urls.is_empty(), &st.cfg.turn_secret) {
        let mut tag = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut tag);
        let username = format!("{}:{}", now_secs() + 6 * 3600, hex::encode(tag));
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes()).expect("hmac");
        mac.update(username.as_bytes());
        use base64::Engine;
        let credential =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        ice_servers.push(IceServer {
            urls: st.cfg.turn_urls.clone(),
            username: Some(username),
            credential: Some(credential),
        });
    }
    Ok(Json(TurnResp { ice_servers }))
}

// ---------------- push ----------------

async fn vapid(State(st): State<AppState>) -> R<VapidResp> {
    let p = st.push.as_ref().ok_or_else(ApiErr::not_found)?;
    Ok(Json(VapidResp {
        public_key: p.public_key_b64(),
    }))
}

async fn push_subscribe(
    State(st): State<AppState>,
    d: Dev,
    Json(req): Json<PushSubscribeReq>,
) -> R<()> {
    if st.push.is_none() {
        return Err(ApiErr::not_found());
    }
    if !crate::push::allowed_endpoint(&req.endpoint) {
        return Err(ApiErr::bad("Unsupported push service"));
    }
    let scope = if req.scope == "dm" { "dm" } else { "all" };
    st.db
        .run(move |c| {
            c.execute(
                "INSERT INTO push_subs(device_id, endpoint, scope) VALUES(?, ?, ?)
                 ON CONFLICT(device_id) DO UPDATE SET endpoint = excluded.endpoint, scope = excluded.scope",
                params![d.device_id, req.endpoint, scope],
            )
        })
        .await?;
    Ok(Json(()))
}

async fn push_unsubscribe(State(st): State<AppState>, d: Dev) -> R<()> {
    st.db
        .run(move |c| c.execute("DELETE FROM push_subs WHERE device_id = ?", [d.device_id]))
        .await?;
    Ok(Json(()))
}
