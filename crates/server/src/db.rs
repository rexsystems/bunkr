//! SQLite storage. The server only ever holds opaque ciphertext for messages
//! and stores no IPs, emails, user agents or exact timestamps.

use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

pub type DbResult<T> = rusqlite::Result<T>;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;

CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB NOT NULL);

CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  auth_hash BLOB NOT NULL,
  salt BLOB NOT NULL,
  account_pk BLOB NOT NULL,
  key_blob BLOB NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  is_admin INTEGER NOT NULL DEFAULT 0,
  banned INTEGER NOT NULL DEFAULT 0,
  created_day INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sig_pk BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions(
  token_hash BLOB PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
  created_day INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS key_packages(
  id INTEGER PRIMARY KEY,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS channels(
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  topic TEXT NOT NULL DEFAULT '',
  position INTEGER NOT NULL DEFAULT 0,
  epoch INTEGER NOT NULL DEFAULT 0,
  generation INTEGER NOT NULL DEFAULT 0,
  ttl_hours INTEGER NOT NULL DEFAULT 0,
  purged_upto INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS members(
  channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  PRIMARY KEY(channel_id, device_id)
);

-- kind: 0 = app, 1 = commit, 2 = founded. `hour` = unix hour, for retention.
CREATE TABLE IF NOT EXISTS log(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  kind INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  data BLOB NOT NULL,
  hour INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS log_by_channel ON log(channel_id, seq);

CREATE TABLE IF NOT EXISTS joins(
  channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  since INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(channel_id, device_id)
);

-- No FK on device: the device row is usually already gone.
CREATE TABLE IF NOT EXISTS removals(
  channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  device_id INTEGER NOT NULL,
  PRIMARY KEY(channel_id, device_id)
);

CREATE TABLE IF NOT EXISTS welcomes(
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  commit_seq INTEGER NOT NULL,
  data BLOB NOT NULL,
  PRIMARY KEY(device_id, channel_id)
);
"#;

impl Db {
    pub fn open(path: &std::path::Path) -> DbResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Db(Arc::new(Mutex::new(conn))))
    }

    /// Run a closure on the connection off the async runtime.
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> T + Send + 'static,
    ) -> T {
        let db = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut c = db.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut c)
        })
        .await
        .expect("db task panicked")
    }
}

pub fn meta_get(c: &Connection, k: &str) -> DbResult<Option<Vec<u8>>> {
    c.query_row("SELECT v FROM meta WHERE k = ?", [k], |r| r.get(0))
        .optional()
}

pub fn meta_set(c: &Connection, k: &str, v: &[u8]) -> DbResult<()> {
    c.execute(
        "INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![k, v],
    )?;
    Ok(())
}

pub fn user_count(c: &Connection) -> DbResult<i64> {
    c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
}

pub fn registration_open(c: &Connection) -> DbResult<bool> {
    Ok(meta_get(c, "registration_open")?
        .map(|v| v == b"1")
        .unwrap_or(true))
}

/// Channels a device is currently a member of.
pub fn device_channels(c: &Connection, device: i64) -> DbResult<Vec<i64>> {
    let mut st = c.prepare("SELECT channel_id FROM members WHERE device_id = ?")?;
    let rows = st.query_map([device], |r| r.get(0))?;
    rows.collect()
}

pub fn channel_members(c: &Connection, channel: i64) -> DbResult<Vec<i64>> {
    let mut st = c.prepare("SELECT device_id FROM members WHERE channel_id = ?")?;
    let rows = st.query_map([channel], |r| r.get(0))?;
    rows.collect()
}

pub fn user_devices(c: &Connection, user: i64) -> DbResult<Vec<i64>> {
    let mut st = c.prepare("SELECT id FROM devices WHERE user_id = ?")?;
    let rows = st.query_map([user], |r| r.get(0))?;
    rows.collect()
}

/// Delete a device and queue its eviction from every group it was in.
/// Returns the affected channels.
pub fn revoke_device(c: &Connection, device: i64) -> DbResult<Vec<i64>> {
    let chans = device_channels(c, device)?;
    for ch in &chans {
        c.execute(
            "INSERT OR IGNORE INTO removals(channel_id, device_id) VALUES(?, ?)",
            params![ch, device],
        )?;
    }
    c.execute("DELETE FROM devices WHERE id = ?", [device])?;
    Ok(chans)
}

/// Revoke every device and session of a user. Returns (devices, channels).
pub fn revoke_user(c: &Connection, user: i64) -> DbResult<(Vec<i64>, Vec<i64>)> {
    let devices = user_devices(c, user)?;
    let mut chans = vec![];
    for d in &devices {
        chans.extend(revoke_device(c, *d)?);
    }
    c.execute("DELETE FROM sessions WHERE user_id = ?", [user])?;
    chans.sort_unstable();
    chans.dedup();
    Ok((devices, chans))
}

pub fn ensure_default_channel(c: &Connection) -> DbResult<()> {
    let n: i64 = c.query_row("SELECT COUNT(*) FROM channels", [], |r| r.get(0))?;
    if n == 0 && meta_get(c, "seeded")?.is_none() {
        c.execute(
            "INSERT INTO channels(name, topic, position) VALUES('general', 'Say hi. Everything here is end-to-end encrypted.', 0)",
            [],
        )?;
        c.execute(
            "INSERT INTO channels(name, topic, position) VALUES('random', 'Off-topic', 1)",
            [],
        )?;
        meta_set(c, "seeded", b"1")?;
    }
    Ok(())
}

/// Delete expired log entries. Returns how many rows were removed.
pub fn purge(c: &mut Connection, now_hour: i64, retention_days: i64) -> DbResult<usize> {
    let tx = c.transaction()?;
    let chans: Vec<(i64, i64)> = {
        let mut st = tx.prepare("SELECT id, ttl_hours FROM channels")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<DbResult<_>>()?
    };
    let mut total = 0;
    for (id, ttl) in chans {
        let ttl = if ttl > 0 { ttl } else { retention_days * 24 };
        let cutoff = now_hour - ttl;
        let max: Option<i64> = tx.query_row(
            "SELECT MAX(seq) FROM log WHERE channel_id = ? AND hour < ?",
            params![id, cutoff],
            |r| r.get(0),
        )?;
        if let Some(max) = max {
            total += tx.execute(
                "DELETE FROM log WHERE channel_id = ? AND seq <= ?",
                params![id, max],
            )?;
            tx.execute(
                "UPDATE channels SET purged_upto = MAX(purged_upto, ?) WHERE id = ?",
                params![max, id],
            )?;
        }
    }
    // Sessions that never registered a device are abandoned logins.
    tx.execute(
        "DELETE FROM sessions WHERE device_id IS NULL AND created_day < ?",
        [now_hour / 24 - 1],
    )?;
    tx.commit()?;
    Ok(total)
}
