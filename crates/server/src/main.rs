//! Bunkr server: a zero-knowledge delivery service for MLS-encrypted chat.

mod api;
mod db;
mod extra;
mod hub;
mod push;

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::http::{header, HeaderValue, Method};
use rand::RngCore;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
};

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; \
img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src 'self' ws: wss:; manifest-src 'self'; worker-src 'self'; \
frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bunkr_server=info".into()),
        )
        .with_target(false)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();

    let data = PathBuf::from(env("BUNKR_DATA", "./data"));
    std::fs::create_dir_all(&data).expect("create data dir");
    let db = db::Db::open(&data.join("bunkr.db")).expect("open database");

    let retention_days: u32 = env("BUNKR_RETENTION_DAYS", "30")
        .parse()
        .unwrap_or(30)
        .max(1);
    let name = env("BUNKR_NAME", "Bunkr");
    let web_dir = PathBuf::from(env("BUNKR_WEB_DIR", "./web/dist"));
    let bind: SocketAddr = env("BUNKR_BIND", "0.0.0.0:8080")
        .parse()
        .expect("BUNKR_BIND");

    let max_upload: u64 = env("BUNKR_MAX_UPLOAD_MB", "25")
        .parse()
        .unwrap_or(25)
        .clamp(1, 2048)
        * 1024
        * 1024;
    let list = |k: &str| -> Vec<String> {
        env(k, "")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let (secret, setup_code, vapid) = db
        .run(
            |c| -> rusqlite::Result<([u8; 32], Option<String>, [u8; 32])> {
                db::ensure_default_channel(c)?;
                let secret = match db::meta_get(c, "secret")? {
                    Some(s) if s.len() == 32 => s.try_into().unwrap(),
                    _ => {
                        let mut s = [0u8; 32];
                        rand::rngs::OsRng.fill_bytes(&mut s);
                        db::meta_set(c, "secret", &s)?;
                        s
                    }
                };
                let code = if db::user_count(c)? == 0 {
                    Some(std::env::var("BUNKR_SETUP_CODE").unwrap_or_else(|_| {
                        let mut b = [0u8; 6];
                        rand::rngs::OsRng.fill_bytes(&mut b);
                        hex::encode(b).to_uppercase()
                    }))
                } else {
                    None
                };
                let vapid = match db::meta_get(c, "vapid")? {
                    Some(s) if s.len() == 32 => s.try_into().unwrap(),
                    _ => loop {
                        let mut s = [0u8; 32];
                        rand::rngs::OsRng.fill_bytes(&mut s);
                        if p256::ecdsa::SigningKey::from_slice(&s).is_ok() {
                            db::meta_set(c, "vapid", &s)?;
                            break s;
                        }
                    },
                };
                Ok((secret, code, vapid))
            },
        )
        .await
        .expect("init database");

    if let Some(code) = &setup_code {
        tracing::info!("==============================================");
        tracing::info!("  No admin yet. Open Bunkr and create the");
        tracing::info!("  first account with this SETUP CODE:");
        tracing::info!("            {code}");
        tracing::info!("==============================================");
    }

    let state = api::AppState {
        db: db.clone(),
        hub: hub::Hub::default(),
        cfg: api::Config {
            name,
            retention_days,
            data_dir: data.clone(),
            max_upload,
            turn_urls: list("BUNKR_TURN_URLS"),
            stun_urls: list("BUNKR_STUN_URLS"),
            turn_secret: std::env::var("BUNKR_TURN_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
            refound_after_secs: env("BUNKR_REFOUND_SECS", "8").parse().unwrap_or(8),
        },
        secret: Arc::new(secret),
        setup_code: Arc::new(Mutex::new(setup_code)),
        limiter: Default::default(),
        push: if env("BUNKR_PUSH", "on") == "off" {
            None
        } else {
            push::Push::new(
                vapid,
                env(
                    "BUNKR_PUSH_CONTACT",
                    &format!("mailto:admin@{}", env("BUNKR_DOMAIN", "localhost")),
                ),
            )
            .map(Arc::new)
        },
    };

    // Retention: delete expired ciphertext every 10 minutes.
    {
        let db = db.clone();
        let blobs_dir = data.join("blobs");
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(600));
            loop {
                iv.tick().await;
                let now_h = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    / 3600) as i64;
                let r = db
                    .run(move |c| {
                        let out = db::purge(c, now_h, retention_days as i64)?;
                        Ok::<_, rusqlite::Error>((out, db::blob_ids(c)?))
                    })
                    .await;
                match r {
                    Err(e) => tracing::warn!("purge failed: {e}"),
                    Ok((_, live)) => {
                        // Remove expired and orphaned attachment files.
                        for dir in std::fs::read_dir(&blobs_dir)
                            .into_iter()
                            .flatten()
                            .flatten()
                        {
                            for f in std::fs::read_dir(dir.path())
                                .into_iter()
                                .flatten()
                                .flatten()
                            {
                                let name = f.file_name().to_string_lossy().to_string();
                                if !live.contains(&name) {
                                    let _ = std::fs::remove_file(f.path());
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    let index = web_dir.join("index.html");
    let static_files = ServeDir::new(&web_dir)
        .precompressed_br()
        .precompressed_gzip()
        .fallback(ServeFile::new(index));

    // CORS is open because auth is a bearer token (no cookies) and the
    // desktop app talks to arbitrary self-hosted servers.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    let app = api::router()
        .with_state(state)
        .fallback_service(static_files)
        .layer(RequestBodyLimitLayer::new(
            max_upload as usize + 1024 * 1024,
        ))
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(self), microphone=(self), display-capture=(self), geolocation=(), payment=(), usb=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ));

    tracing::info!("Bunkr listening on http://{bind} (no request logging, by design)");
    let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}
