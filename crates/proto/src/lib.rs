//! Wire types shared by the Bunkr server and clients.
//!
//! Everything the server stores about messages is opaque ciphertext. Binary
//! values travel as base64 strings (`B64`).

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const PROTOCOL_VERSION: u32 = 1;

/// Max username length (chars).
pub const MAX_USERNAME: usize = 32;
/// Max size of one encrypted message blob accepted by the server.
pub const MAX_BLOB: usize = 256 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct B64(pub Vec<u8>);

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map(B64)
            .map_err(serde::de::Error::custom)
    }
}
impl From<Vec<u8>> for B64 {
    fn from(v: Vec<u8>) -> Self {
        B64(v)
    }
}

pub type UserId = i64;
pub type DeviceId = i64;
pub type ChannelId = i64;
pub type Seq = i64;

// ---------- server info / auth ----------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub protocol: u32,
    /// True until the first (admin) account is created with the setup code.
    pub needs_setup: bool,
    pub registration_open: bool,
    pub retention_days: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PreloginReq {
    pub username: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PreloginResp {
    /// Argon2id salt. Unknown usernames get a deterministic fake salt so the
    /// endpoint does not reveal which accounts exist.
    pub salt: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterReq {
    pub username: String,
    pub salt: B64,
    /// 32 bytes derived from the password on the client. The password itself
    /// never leaves the device.
    pub auth_key: B64,
    /// Ed25519 account identity public key.
    pub account_pk: B64,
    /// Account secret key, encrypted on the client with the password-derived
    /// master key (XChaCha20-Poly1305).
    pub key_blob: B64,
    pub setup_code: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginReq {
    pub username: String,
    pub auth_key: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginResp {
    pub token: String,
    pub user_id: UserId,
    pub account_pk: B64,
    pub key_blob: B64,
    pub generation: i64,
    pub is_admin: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceReq {
    /// The device's MLS leaf signature public key.
    pub sig_pk: B64,
    /// Account key's signature over `device_binding(user_id, sig_pk)`.
    pub account_sig: B64,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceResp {
    pub device_id: DeviceId,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyPackagesReq {
    pub packages: Vec<B64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordChangeReq {
    pub old_auth_key: B64,
    pub new_salt: B64,
    pub new_auth_key: B64,
    pub new_account_pk: B64,
    pub new_key_blob: B64,
}

// ---------- state ----------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
    pub topic: String,
    pub position: i64,
    pub epoch: i64,
    /// Bumped every time the channel's MLS group is (re)founded.
    pub generation: i64,
    /// Number of devices currently in the MLS group.
    pub member_count: i64,
    /// Is the calling device in the group?
    pub is_member: bool,
    /// Messages older than this are deleted on the server (and on clients).
    pub ttl_hours: i64,
    pub head_seq: Seq,
    /// Joins/removals waiting for a member to commit them.
    pub has_pending: bool,
    /// Is a welcome waiting for the calling device?
    pub has_welcome: bool,
    /// The caller may (re)found the group: nobody is in it, or no member
    /// device has been online while the caller waited to be let in.
    pub can_found: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DirectoryUser {
    pub id: UserId,
    pub username: String,
    pub account_pk: B64,
    pub is_admin: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StateResp {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub username: String,
    pub is_admin: bool,
    pub generation: i64,
    pub key_packages_left: i64,
    pub channels: Vec<Channel>,
    pub users: Vec<DirectoryUser>,
}

// ---------- channel log ----------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogKind {
    /// MLS application message (encrypted chat payload).
    App,
    /// MLS commit (membership change).
    Commit,
    /// Group (re)founded; every older log entry is unreadable for newcomers.
    Founded,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogEntry {
    pub seq: Seq,
    pub kind: LogKind,
    pub epoch: i64,
    pub generation: i64,
    pub data: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogResp {
    pub entries: Vec<LogEntry>,
    /// Lowest seq still stored (older ones were purged by retention).
    pub floor: Seq,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SendReq {
    pub epoch: i64,
    pub generation: i64,
    pub data: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SendResp {
    pub seq: Seq,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CommitReq {
    pub epoch: i64,
    pub generation: i64,
    pub commit: B64,
    pub welcome: Option<B64>,
    pub added: Vec<AddedDevice>,
    pub removed: Vec<DeviceId>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AddedDevice {
    pub device_id: DeviceId,
    pub key_package_id: i64,
}

/// Rejection sent with HTTP 409 when the caller's epoch/generation is stale.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Conflict {
    pub epoch: i64,
    pub generation: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FoundReq {
    /// Generation the caller saw; server bumps it on success.
    pub generation: i64,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FoundResp {
    pub generation: i64,
    pub seq: Seq,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingJoin {
    pub device_id: DeviceId,
    pub user_id: UserId,
    pub key_package_id: i64,
    pub key_package: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingResp {
    pub joins: Vec<PendingJoin>,
    pub removals: Vec<DeviceId>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Welcome {
    pub channel_id: ChannelId,
    pub generation: i64,
    pub commit_seq: Seq,
    pub data: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WelcomesResp {
    pub welcomes: Vec<Welcome>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AckWelcomeReq {
    pub channel_id: ChannelId,
    /// The welcome could not be used; queue a fresh join.
    pub failed: bool,
}

/// Drop pending joins/removals that cannot or need not be committed.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DismissReq {
    pub joins: Vec<DeviceId>,
    pub removals: Vec<DeviceId>,
}

// ---------- realtime ----------

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ClientWs {
    Auth { token: String },
    Ping,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerWs {
    Ready,
    Pong,
    /// New entries in a channel log.
    Log {
        channel_id: ChannelId,
        seq: Seq,
    },
    /// Someone needs to be added to / removed from a channel group.
    Pending {
        channel_id: ChannelId,
    },
    /// A welcome is waiting for this device.
    Welcome {
        channel_id: ChannelId,
    },
    /// Channel list / directory changed.
    State,
    /// A log entry was deleted by a moderator.
    Deleted {
        channel_id: ChannelId,
        seq: Seq,
    },
    /// This session is dead (logout, ban, password change). Wipe everything.
    Revoked,
}

// ---------- admin ----------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AdminUser {
    pub id: UserId,
    pub username: String,
    pub is_admin: bool,
    pub banned: bool,
    pub devices: i64,
    pub created_day: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AdminUsersResp {
    pub users: Vec<AdminUser>,
    pub registration_open: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChannelUpsert {
    pub name: String,
    pub topic: String,
    pub ttl_hours: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SettingsReq {
    pub registration_open: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiError {
    pub error: String,
}

// ---------- shared crypto helpers (no deps) ----------

/// The byte string an account key signs to vouch for one of its devices.
pub fn device_binding(user_id: UserId, sig_pk: &[u8]) -> Vec<u8> {
    let mut v = b"bunkr/device-binding/v1\0".to_vec();
    v.extend_from_slice(&user_id.to_be_bytes());
    v.extend_from_slice(sig_pk);
    v
}

/// Normalise and validate a username: 3..=32 chars of [a-z0-9_.-].
pub fn normalize_username(raw: &str) -> Option<String> {
    let u = raw.trim().to_lowercase();
    let ok = (3..=MAX_USERNAME).contains(&u.chars().count())
        && u.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-".contains(c));
    ok.then_some(u)
}

pub fn normalize_channel_name(raw: &str) -> Option<String> {
    let n: String = raw
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_whitespace() { '-' } else { c })
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    (1..=32).contains(&n.chars().count()).then_some(n)
}
