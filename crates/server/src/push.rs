//! Web Push with VAPID. Pushes carry NO payload: they only wake the service
//! worker, which shows a generic "new messages" notification. Content never
//! leaves the encrypted channel.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

use crate::api::{now_secs, AppState};

pub struct Push {
    key: SigningKey,
    contact: String,
    client: reqwest::Client,
    last: Mutex<HashMap<i64, Instant>>,
}

/// Only real push services: the endpoint is user-supplied, so anything else
/// would let a client make the server send requests into arbitrary networks.
pub fn allowed_endpoint(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.contains(':') || host.contains('@') {
        return false;
    }
    const EXACT: [&str; 3] = [
        "fcm.googleapis.com",
        "updates.push.services.mozilla.com",
        "push.services.mozilla.com",
    ];
    const SUFFIX: [&str; 2] = [".push.apple.com", ".notify.windows.com"];
    EXACT.contains(&host)
        || SUFFIX
            .iter()
            .any(|s| host.ends_with(s) && host.len() > s.len())
}

impl Push {
    pub fn new(secret: [u8; 32], contact: String) -> Option<Self> {
        let key = SigningKey::from_slice(&secret).ok()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(Push {
            key,
            contact,
            client,
            last: Default::default(),
        })
    }

    pub fn public_key_b64(&self) -> String {
        let pk = self.key.verifying_key().to_encoded_point(false);
        B64URL.encode(pk.as_bytes())
    }

    fn jwt(&self, aud: &str) -> String {
        let header = B64URL.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = B64URL.encode(
            serde_json::json!({ "aud": aud, "exp": now_secs() + 12 * 3600, "sub": self.contact })
                .to_string(),
        );
        let input = format!("{header}.{claims}");
        let sig: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", B64URL.encode(sig.to_bytes()))
    }

    /// Returns false if the subscription is gone and should be deleted.
    async fn send(&self, endpoint: &str) -> bool {
        let aud = endpoint
            .splitn(4, '/')
            .take(3)
            .collect::<Vec<_>>()
            .join("/");
        let auth = format!("vapid t={}, k={}", self.jwt(&aud), self.public_key_b64());
        match self
            .client
            .post(endpoint)
            .header("TTL", "3600")
            .header("Urgency", "normal")
            .header("Authorization", auth)
            .header("Content-Length", "0")
            .send()
            .await
        {
            Ok(r) => !matches!(r.status().as_u16(), 404 | 410),
            Err(_) => true,
        }
    }

    fn throttled(&self, device: i64) -> bool {
        let mut m = self.last.lock().unwrap();
        let now = Instant::now();
        if let Some(t) = m.get(&device) {
            if now.duration_since(*t) < Duration::from_secs(60) {
                return true;
            }
        }
        m.insert(device, now);
        if m.len() > 100_000 {
            m.clear();
        }
        false
    }
}

/// Wake offline devices of everyone except the sender.
pub fn notify(st: &AppState, channel: i64, sender_user: i64) {
    let Some(push) = st.push.clone() else { return };
    let st = st.clone();
    tokio::spawn(async move {
        let subs = st
            .db
            .run(move |c| -> rusqlite::Result<Vec<(i64, String)>> {
                let mut q = c.prepare(
                    "SELECT p.device_id, p.endpoint FROM push_subs p
                     JOIN members m ON m.device_id = p.device_id AND m.channel_id = ?1
                     JOIN devices d ON d.id = p.device_id
                     JOIN channels ch ON ch.id = ?1
                     WHERE d.user_id != ?2 AND (p.scope = 'all' OR ch.kind = 'dm')",
                )?;
                let rows = q.query_map(rusqlite::params![channel, sender_user], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
                rows.collect()
            })
            .await
            .unwrap_or_default();
        for (device, endpoint) in subs {
            if st.hub.any_online(&[device]) || push.throttled(device) {
                continue;
            }
            if !push.send(&endpoint).await {
                let _ = st
                    .db
                    .run(move |c| c.execute("DELETE FROM push_subs WHERE device_id = ?", [device]))
                    .await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::allowed_endpoint;
    #[test]
    fn endpoints() {
        assert!(allowed_endpoint("https://fcm.googleapis.com/fcm/send/abc"));
        assert!(allowed_endpoint("https://web.push.apple.com/QW"));
        assert!(allowed_endpoint(
            "https://wns2-db5p.notify.windows.com/w/?token=x"
        ));
        assert!(!allowed_endpoint("http://fcm.googleapis.com/x"));
        assert!(!allowed_endpoint("https://evil.com/fcm.googleapis.com"));
        assert!(!allowed_endpoint("https://fcm.googleapis.com:8443/x"));
        assert!(!allowed_endpoint("https://user@fcm.googleapis.com/x"));
        assert!(!allowed_endpoint("https://push.apple.com.evil.com/x"));
        assert!(!allowed_endpoint("https://169.254.169.254/latest"));
    }
}
