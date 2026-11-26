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
    fn texts_in(&self, cid: i64) -> Vec<String> {
        self.dev
            .chans
            .get(&cid)
            .map(|c| {
                c.messages
                    .iter()
                    .filter_map(|m| match &m.body {
                        MsgBody::Text(t) => Some(t.clone()),
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

async fn ws_events(
    url: &str,
    token: &str,
) -> tokio::sync::mpsc::UnboundedReceiver<bunkr_proto::ServerWs> {
    use futures_util::{SinkExt, StreamExt};
    let ws_url = url.replace("http://", "ws://") + "/api/ws";
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let auth = serde_json::to_string(&bunkr_proto::ClientWs::Auth {
        token: token.into(),
    })
    .unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::Text(auth.into()))
        .await
        .unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(Ok(m)) = ws.next().await {
            if let tokio_tungstenite::tungstenite::Message::Text(t) = m {
                if let Ok(ev) = serde_json::from_str(&t) {
                    let _ = tx.send(ev);
                }
            }
        }
    });
    rx
}

#[tokio::test]
async fn rich_messages_dms_files_ephemeral() {
    use bunkr_core::device::Eph;
    let srv = start_server(3599).await;
    let url = srv.url.clone();
    let mut alice = Client::register(&url, "alice", "Alice-pass-1234", Some("SETUP123")).await;
    alice.tick().await.unwrap();
    let mut bob = Client::register(&url, "bob", "Bob-pass-12345", None).await;
    let mut eve = Client::register(&url, "eve", "Eve-pass-123456", None).await;
    settle(&mut [&mut bob, &mut eve, &mut alice]).await;
    let g = alice.chan("general");

    // reply, edit, react, delete
    let id = alice
        .dev
        .send_message(&alice.http, g, "original", None, vec![], vec![], NOW)
        .await
        .unwrap();
    bob.dev
        .send_message(
            &bob.http,
            g,
            "a reply",
            Some(id.clone()),
            vec![],
            vec![],
            NOW,
        )
        .await
        .unwrap();
    alice
        .dev
        .edit_message(&alice.http, g, &id, "edited!", NOW)
        .await
        .unwrap();
    bob.dev.react(&bob.http, g, &id, "🔥", NOW).await.unwrap();
    eve.dev.react(&eve.http, g, &id, "🔥", NOW).await.unwrap();
    assert!(bob
        .dev
        .edit_message(&bob.http, g, &id, "hijack", NOW)
        .await
        .is_err());
    settle(&mut [&mut alice, &mut bob, &mut eve]).await;
    let find = |c: &Client, id: &str| {
        c.dev.chans[&g]
            .messages
            .iter()
            .find(|m| m.id == id)
            .cloned()
            .unwrap()
    };
    for c in [&alice, &bob, &eve] {
        let m = find(c, &id);
        assert_eq!(m.body, MsgBody::Text("edited!".into()));
        assert!(m.edited.is_some());
        assert_eq!(m.reactions["🔥"].len(), 2);
    }
    assert!(bob.dev.chans[&g]
        .messages
        .iter()
        .any(|m| m.reply_to.as_deref() == Some(id.as_str())));
    bob.dev.react(&bob.http, g, &id, "🔥", NOW).await.unwrap(); // toggle off
    alice
        .dev
        .delete_message(&alice.http, g, &id, NOW)
        .await
        .unwrap();
    settle(&mut [&mut alice, &mut bob, &mut eve]).await;
    assert_eq!(find(&eve, &id).body, MsgBody::Deleted);
    assert_eq!(find(&bob, &id).body, MsgBody::Deleted);

    // DMs: only the two participants are ever in the group
    let dm = alice
        .dev
        .open_dm(&alice.http, bob.dev.user_id, NOW)
        .await
        .unwrap();
    settle(&mut [&mut alice, &mut bob, &mut eve]).await;
    assert!(bob.dev.is_joined(dm));
    assert!(
        !eve.dev.channels.iter().any(|c| c.id == dm),
        "eve can't see the DM"
    );
    let r = eve
        .http
        .request("GET", &format!("/api/channels/{dm}/log?after=0"), None)
        .await
        .unwrap();
    assert_eq!(r.0, 404, "eve can't read DM ciphertext");
    let r = eve
        .http
        .request("POST", &format!("/api/channels/{dm}/rejoin"), None)
        .await
        .unwrap();
    assert_eq!(r.0, 404, "eve can't ask to join a DM");
    bob.dev
        .send_text(&bob.http, dm, "just us", NOW)
        .await
        .unwrap();
    alice.tick().await.unwrap();
    assert!(alice.texts_in(dm).contains(&"just us".to_string()));
    let devs = alice.dev.member_devices(dm);
    assert!(devs
        .iter()
        .all(|(u, _, ok)| (*u == alice.dev.user_id || *u == bob.dev.user_id) && *ok));
    assert_eq!(
        alice
            .dev
            .open_dm(&alice.http, bob.dev.user_id, NOW)
            .await
            .unwrap(),
        dm,
        "same DM reused"
    );

    // Files: encrypted, only members can fetch, uploader can delete
    let secret_file = b"%PDF top secret contents".repeat(1000);
    let (fref, token) = alice
        .dev
        .upload_file(
            &alice.http,
            dm,
            &secret_file,
            "plan.pdf",
            "application/pdf",
            None,
        )
        .await
        .unwrap();
    let blob_path = std::fs::read_dir(srv.db.parent().unwrap().join("blobs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join(&fref.blob);
    let on_disk = std::fs::read(&blob_path).unwrap();
    assert!(
        !on_disk.windows(10).any(|w| w == b"top secret"),
        "blob is encrypted at rest"
    );
    alice
        .dev
        .send_message(
            &alice.http,
            dm,
            "",
            None,
            vec![fref.clone()],
            vec![token],
            NOW,
        )
        .await
        .unwrap();
    bob.tick().await.unwrap();
    let got = bob.dev.chans[&dm]
        .messages
        .iter()
        .find_map(|m| m.files.first().cloned())
        .unwrap();
    assert_eq!(
        Device::download_file(&bob.http, &got).await.unwrap(),
        secret_file
    );
    let r = eve
        .http
        .request("GET", &format!("/api/blobs/{}", fref.blob), None)
        .await
        .unwrap();
    assert_eq!(r.0, 404, "eve can't download DM files");
    let r = bob
        .http
        .request(
            "DELETE",
            &format!("/api/blobs/{}?token=wrong", fref.blob),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r.0, 403);
    let fid = alice.dev.chans[&dm]
        .messages
        .iter()
        .find(|m| !m.files.is_empty())
        .unwrap()
        .id
        .clone();
    alice
        .dev
        .delete_message(&alice.http, dm, &fid, NOW)
        .await
        .unwrap();
    assert!(
        Device::download_file(&bob.http, &got).await.is_err(),
        "file gone after delete"
    );
    assert!(!blob_path.exists());

    // Ephemeral: relayed encrypted over websocket, never stored
    alice.tick().await.unwrap();
    let mut rx = ws_events(&url, &bob.dev.token).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    alice
        .dev
        .send_ephemeral(&alice.http, g, &Eph::Typing, NOW)
        .await
        .unwrap();
    let ev = loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            bunkr_proto::ServerWs::Ephemeral { channel_id, data } => break (channel_id, data),
            _ => continue,
        }
    };
    assert_eq!(ev.0, g);
    let (u, _, trusted, e) = bob.dev.open_ephemeral(g, &ev.1 .0).unwrap();
    assert_eq!((u, trusted, e), (alice.dev.user_id, true, Eph::Typing));
    assert!(eve.dev.open_ephemeral(dm, &ev.1 .0).is_none());
    let head: Vec<i64> = alice.dev.channels.iter().map(|c| c.head_seq).collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    alice.tick().await.unwrap();
    let head2: Vec<i64> = alice.dev.channels.iter().map(|c| c.head_seq).collect();
    assert_eq!(head, head2, "ephemeral not stored in the log");
}
