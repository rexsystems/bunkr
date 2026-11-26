//! Bunkr client core: everything that touches keys lives here.
//!
//! Platform-neutral (native + wasm32). Networking is injected through the
//! [`Http`] trait so the exact same engine runs in the browser, in the desktop
//! app and in the native integration tests.

pub mod crypto;
pub mod device;
pub mod session;

pub use device::{ChanState, Device, Msg, MsgBody};

use bunkr_proto::Conflict;
use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("wrong password or corrupted data")]
    Decrypt,
    #[error("session revoked")]
    Revoked,
    #[error("network: {0}")]
    Network(String),
    #[error("{0}")]
    Server(String),
    #[error("mls: {0}")]
    Mls(String),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn mls(e: impl std::fmt::Debug) -> Self {
        Error::Mls(format!("{e:?}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Minimal HTTP abstraction. Implementations attach the bearer token.
#[allow(async_fn_in_trait)]
pub trait Http {
    /// Set (or clear) the bearer token used for subsequent requests.
    fn set_token(&self, token: Option<String>);
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> std::result::Result<(u16, Vec<u8>), String>;
}

pub enum Reply<T> {
    Ok(T),
    Conflict(Conflict),
}

pub async fn call<T: DeserializeOwned>(
    http: &impl Http,
    method: &str,
    path: &str,
    body: Option<&impl Serialize>,
) -> Result<Reply<T>> {
    let body = body.map(|b| serde_json::to_vec(b).expect("serializable"));
    let (status, bytes) = http
        .request(method, path, body)
        .await
        .map_err(Error::Network)?;
    match status {
        200..=299 => {
            let bytes = if bytes.is_empty() {
                b"null".to_vec()
            } else {
                bytes
            };
            serde_json::from_slice(&bytes)
                .map(Reply::Ok)
                .map_err(|e| Error::Other(format!("bad response from {path}: {e}")))
        }
        409 => serde_json::from_slice(&bytes)
            .map(Reply::Conflict)
            .map_err(|e| Error::Other(e.to_string())),
        401 => Err(Error::Revoked),
        _ => {
            let msg = serde_json::from_slice::<bunkr_proto::ApiError>(&bytes)
                .map(|e| e.error)
                .unwrap_or_else(|_| format!("HTTP {status}"));
            Err(Error::Server(msg))
        }
    }
}

pub async fn call_ok<T: DeserializeOwned>(
    http: &impl Http,
    method: &str,
    path: &str,
    body: Option<&impl Serialize>,
) -> Result<T> {
    match call(http, method, path, body).await? {
        Reply::Ok(v) => Ok(v),
        Reply::Conflict(_) => Err(Error::Other("conflict".into())),
    }
}

pub const NO_BODY: Option<&()> = None;
