//! Full protocol test against a real server process.
//!
//! Run with: `cargo build -p bunkr-server && cargo test -p bunkr-e2e -- --nocapture`

use std::cell::RefCell;
use std::process::{Child, Command};
use std::time::Duration;

use bunkr_core::{session, Device, Error, Http, MsgBody};

struct ReqHttp {
    base: String,
    client: reqwest::Client,
    token: RefCell<Option<String>>,
}

impl ReqHttp {
    fn new(base: &str) -> Self {
        ReqHttp {
            base: base.into(),
            client: reqwest::Client::new(),
            token: RefCell::new(None),
        }
    }
}

impl Http for ReqHttp {
    fn set_token(&self, token: Option<String>) {
        *self.token.borrow_mut() = token;
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), String> {
        let mut rb = self
            .client
            .request(method.parse().unwrap(), format!("{}{}", self.base, path));
        if let Some(t) = self.token.borrow().clone() {
            rb = rb.bearer_auth(t);
        }
        if let Some(b) = body {
            rb = rb.header("content-type", "application/json").body(b);
        }
        let r = rb.send().await.map_err(|e| e.to_string())?;
        let status = r.status().as_u16();
        Ok((status, r.bytes().await.map_err(|e| e.to_string())?.to_vec()))
    }
}

struct Server {
    child: Child,
    _dir: tempfile::TempDir,
    url: String,
    db: std::path::PathBuf,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

async fn start_server(refound_secs: u32) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let port = 20000 + (std::process::id() % 20000) as u16 + refound_secs as u16 % 7;
    let bin = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/debug/bunkr-server"
    );
    let child = Command::new(bin)
        .env("BUNKR_DATA", dir.path())
        .env("BUNKR_BIND", format!("127.0.0.1:{port}"))
        .env("BUNKR_SETUP_CODE", "SETUP123")
        .env("BUNKR_REFOUND_SECS", refound_secs.to_string())
        .env("BUNKR_WEB_DIR", dir.path())
        .spawn()
        .expect("build the server first: cargo build -p bunkr-server");
    let url = format!("http://127.0.0.1:{port}");
    for _ in 0..100 {
        if reqwest::get(format!("{url}/api/info")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let db = dir.path().join("bunkr.db");
    Server {
        child,
        _dir: dir,
        url,
        db,
    }
}

const NOW: i64 = 1_800_000_000_000;

struct Client {
    http: ReqHttp,
    dev: Device,
    keys: bunkr_core::crypto::PasswordKeys,
    salt: Vec<u8>,
}

impl Client {
    async fn register(url: &str, user: &str, pw: &str, code: Option<&str>) -> Client {
        let http = ReqHttp::new(url);
        let (keys, salt, dev) = session::register(&http, user, pw, code.map(String::from))
            .await
            .unwrap();
        Client {
            http,
            dev,
            keys,
            salt,
        }
    }
    async fn login(url: &str, user: &str, pw: &str) -> Result<Client, Error> {
        let http = ReqHttp::new(url);
        let (keys, salt, dev) = session::login(&http, user, pw).await?;
        Ok(Client {
            http,
            dev,
            keys,
            salt,
        })
    }
    async fn tick(&mut self) -> Result<(), Error> {
        self.dev.tick(&self.http, NOW).await.map(|_| ())
    }
    fn chan(&self, name: &str) -> i64 {
        self.dev
            .channels
            .iter()
            .find(|c| c.name == name)
            .unwrap()
            .id
    }
    fn texts(&self, name: &str) -> Vec<(String, String, bool)> {
        let cid = self.chan(name);
        self.dev
            .chans
            .get(&cid)
            .map(|c| {
                c.messages
                    .iter()
                    .filter_map(|m| match &m.body {
                        MsgBody::Text(t) => {
                            Some((self.dev.username_of(m.user_id), t.clone(), m.unverified))
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    async fn send(&mut self, name: &str, text: &str) {
        let cid = self.chan(name);
        self.dev
            .send_text(&self.http, cid, text, NOW)
            .await
            .unwrap();
    }
}

async fn settle(clients: &mut [&mut Client]) {
    for _ in 0..4 {
        for c in clients.iter_mut() {
            c.tick().await.unwrap();
        }
    }
}

#[tokio::test]
async fn full_flow() {
    let srv = start_server(3600).await;
    let url = srv.url.clone();

    // Setup code is mandatory for the first (admin) account.
    let http = ReqHttp::new(&url);
    assert!(
        session::register(&http, "mallory", "Sup3r-secret-pw", Some("WRONG".into()))
            .await
            .is_err()
    );
    // Weak passwords are refused client-side.
    assert!(
        session::register(&http, "alice", "short", Some("SETUP123".into()))
            .await
            .is_err()
    );

    let mut alice = Client::register(&url, "alice", "Alice-pass-1234", Some("SETUP123")).await;
    alice.tick().await.unwrap();
    assert!(alice.dev.is_admin);
    let general = alice.chan("general");
    assert!(alice.dev.is_joined(general), "alice founds #general");

    let mut bob = Client::register(&url, "bob", "Bob-pass-12345", None).await;
    settle(&mut [&mut bob, &mut alice]).await;
    assert!(bob.dev.is_joined(general), "alice let bob in");
    assert!(bob.dev.is_joined(bob.chan("random")));

    alice.send("general", "hi bob, this is secret").await;
    bob.tick().await.unwrap();
    assert_eq!(
        bob.texts("general"),
        vec![("alice".into(), "hi bob, this is secret".into(), false)]
    );
    bob.send("general", "hey alice").await;
    alice.tick().await.unwrap();
    assert!(alice
        .texts("general")
        .contains(&("bob".into(), "hey alice".into(), false)));

    // The server must never see plaintext.
    let raw = std::fs::read(&srv.db).unwrap();
    let wal = std::fs::read(srv.db.with_extension("db-wal")).unwrap_or_default();
    for hay in [&raw, &wal] {
        assert!(
            !hay.windows(14).any(|w| w == b"this is secret"),
            "plaintext leaked"
        );
        assert!(
            !hay.windows(9).any(|w| w == b"hey alice"),
            "plaintext leaked"
        );
    }

    // A third user; both existing members race to add her.
    let mut carol = Client::register(&url, "carol", "Carol-pass-1234", None).await;
    settle(&mut [&mut carol, &mut alice, &mut bob]).await;
    assert!(carol.dev.is_joined(general));
    carol.send("general", "carol here").await;
    settle(&mut [&mut alice, &mut bob]).await;
    assert!(alice.texts("general").iter().any(|t| t.1 == "carol here"));
    assert!(bob.texts("general").iter().any(|t| t.1 == "carol here"));
    // Carol cannot read what was said before she joined.
    assert!(!carol
        .texts("general")
        .iter()
        .any(|t| t.1.contains("secret")));

    // Device state survives a reload (export/import through the vault).
    let vault = session::Vault::seal(&url, &alice.keys, &alice.salt, &alice.dev);
    assert!(vault.open("not-the-password").is_err());
    let (_k, reloaded) = vault.open("Alice-pass-1234").unwrap();
    alice.dev = reloaded;
    alice.tick().await.unwrap();
    alice.send("general", "after reload").await;
    settle(&mut [&mut bob, &mut carol]).await;
    assert!(bob.texts("general").iter().any(|t| t.1 == "after reload"));
    assert!(carol.texts("general").iter().any(|t| t.1 == "after reload"));

    // Bob changes his password: EVERYTHING resets.
    session::change_password(&bob.http, &bob.keys, "Bob-new-pass-999")
        .await
        .unwrap();
    assert!(matches!(bob.tick().await, Err(Error::Revoked)));
    assert!(Client::login(&url, "bob", "Bob-pass-12345").await.is_err());
    settle(&mut [&mut alice, &mut carol]).await;
    let devs: Vec<_> = alice.dev.member_devices(general);
    assert!(
        !devs.iter().any(|(_, d, _)| *d == bob.dev.device_id),
        "old bob device evicted"
    );

    let mut bob2 = Client::login(&url, "bob", "Bob-new-pass-999")
        .await
        .unwrap();
    settle(&mut [&mut bob2, &mut alice, &mut carol]).await;
    assert!(bob2.dev.is_joined(general));
    assert!(
        bob2.texts("general").is_empty(),
        "fresh identity has no history"
    );
    assert!(
        alice.dev.changed.contains_key(&bob2.dev.user_id),
        "alice notices bob's key change"
    );
    bob2.send("general", "new bob").await;
    settle(&mut [&mut alice, &mut carol]).await;
    assert!(alice
        .texts("general")
        .contains(&("bob".into(), "new bob".into(), false)));

    // Admin bans carol.
    let carol_id = carol.dev.user_id;
    let r = alice
        .http
        .request("POST", &format!("/api/admin/users/{carol_id}/ban"), None)
        .await
        .unwrap();
    assert_eq!(r.0, 200);
    assert!(matches!(carol.tick().await, Err(Error::Revoked)));
    assert!(Client::login(&url, "carol", "Carol-pass-1234")
        .await
        .is_err());
    settle(&mut [&mut alice, &mut bob2]).await;
    assert!(!alice
        .dev
        .member_devices(general)
        .iter()
        .any(|(u, _, _)| *u == carol_id));
    // Non-admins can't ban.
    let r = bob2
        .http
        .request(
            "POST",
            &format!("/api/admin/users/{}/ban", alice.dev.user_id),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r.0, 403);

    // Everyone remaining still agrees on the group.
    alice.send("general", "final").await;
    bob2.tick().await.unwrap();
    assert!(bob2.texts("general").iter().any(|t| t.1 == "final"));
    assert_eq!(alice.dev.epoch_code(general), bob2.dev.epoch_code(general));

    // Last member leaves -> next device re-founds the channel.
    session::logout(&bob2.http).await.unwrap();
    session::logout(&alice.http).await.unwrap();
    let mut alice2 = Client::login(&url, "alice", "Alice-pass-1234")
        .await
        .unwrap();
    alice2.tick().await.unwrap();
    assert!(alice2.dev.is_joined(general));
    alice2.send("general", "back").await;
}

#[tokio::test]
async fn refound_when_members_offline() {
    let srv = start_server(1).await;
    let url = srv.url.clone();
    let mut alice = Client::register(&url, "alice", "Alice-pass-1234", Some("SETUP123")).await;
    alice.tick().await.unwrap();
    let general = alice.chan("general");
    alice.send("general", "old secret").await;
    // Alice goes away (closes the browser, never logs out). Bob arrives.
    let mut bob = Client::register(&url, "bob", "Bob-pass-12345", None).await;
    tokio::time::sleep(Duration::from_millis(1600)).await;
    bob.tick().await.unwrap();
    assert!(
        bob.dev.is_joined(general),
        "bob re-founds since nobody is online"
    );
    bob.send("general", "anyone?").await;
    assert!(!bob.texts("general").iter().any(|t| t.1 == "old secret"));
    // Alice returns: she drops the stale group and bob lets her back in.
    alice.tick().await.unwrap();
    bob.tick().await.unwrap();
    alice.tick().await.unwrap();
    assert!(alice.dev.is_joined(general));
    bob.send("general", "welcome back").await;
    alice.tick().await.unwrap();
    assert!(alice.texts("general").iter().any(|t| t.1 == "welcome back"));
    assert!(
        alice.texts("general").iter().any(|t| t.1 == "old secret"),
        "local history kept"
    );
}
