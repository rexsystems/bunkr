//! One logged-in device: its MLS state, channel caches and the sync engine.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bunkr_proto::{self as proto, ChannelId, DeviceId, Seq, UserId, B64};
use openmls::prelude::{tls_codec::Deserialize as _, tls_codec::Serialize as _, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use serde::{Deserialize, Serialize};

use crate::{call, call_ok, crypto, Error, Http, Reply, Result, NO_BODY};

/// Hybrid post-quantum suite: ML-KEM-768 + X25519 KEM, AES-256-GCM, SHA-384,
/// Ed25519 signatures.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519;
pub const KEY_PACKAGE_POOL: usize = 40;
pub const KEY_PACKAGE_LOW: i64 = 10;
pub const MAX_CACHED_PER_CHANNEL: usize = 600;
pub const MAX_TEXT: usize = 4000;
/// Every MLS ciphertext is padded to a multiple of this to hide lengths.
pub const PADDING: usize = 256;

pub struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;
    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

/// Contents of a member's MLS BasicCredential.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct CredentialBody {
    u: UserId,
    d: DeviceId,
    /// Account signature over `device_binding(u, leaf signature key)`.
    s: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "k", content = "v", rename_all = "snake_case")]
pub enum MsgBody {
    Text(String),
    System(String),
    Undecryptable,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Msg {
    pub seq: Seq,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub ts: i64,
    pub body: MsgBody,
    /// Sender device was not vouched for by a valid account signature.
    pub unverified: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ChanState {
    pub generation: i64,
    pub joined: bool,
    pub last_seq: Seq,
    /// Log entries this device authored (own messages are not decryptable by
    /// their sender in MLS, and own commits get merged instead).
    pub own: BTreeSet<Seq>,
    pub messages: Vec<Msg>,
}

/// Payload inside an MLS application message.
#[derive(Serialize, Deserialize)]
struct Payload {
    v: u8,
    ts: i64,
    text: String,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    v: u32,
    user_id: UserId,
    device_id: DeviceId,
    username: String,
    generation: i64,
    token: String,
    signer: B64,
    credential: B64,
    storage: Vec<(B64, B64)>,
    chans: BTreeMap<ChannelId, ChanState>,
    pins: BTreeMap<UserId, B64>,
    trust: BTreeMap<String, bool>,
    users: Vec<proto::DirectoryUser>,
    changed: BTreeMap<UserId, i64>,
}

pub struct Device {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub username: String,
    /// Account generation; bumps on password reset.
    pub generation: i64,
    pub token: String,
    provider: Provider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    groups: HashMap<ChannelId, MlsGroup>,
    pub chans: BTreeMap<ChannelId, ChanState>,
    /// Trust-on-first-use pins of account keys.
    pub pins: BTreeMap<UserId, Vec<u8>>,
    /// "user:device" -> credential verified against the account key.
    pub trust: BTreeMap<String, bool>,
    pub users: BTreeMap<UserId, proto::DirectoryUser>,
    /// Users whose account key changed (password reset) -> when we noticed.
    pub changed: BTreeMap<UserId, i64>,
    pub channels: Vec<proto::Channel>,
    pub is_admin: bool,
}

fn group_id(cid: ChannelId, generation: i64) -> GroupId {
    GroupId::from_slice(format!("bunkr/{cid}/{generation}").as_bytes())
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .padding_size(PADDING)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(32, 2000))
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .padding_size(PADDING)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(32, 2000))
        .build()
}

fn parse_credential(c: &Credential) -> Option<CredentialBody> {
    let basic = BasicCredential::try_from(c.clone()).ok()?;
    serde_json::from_slice(basic.identity()).ok()
}

fn tkey(u: UserId, d: DeviceId) -> String {
    format!("{u}:{d}")
}

/// Generate the leaf signature key for a new device (before it has an id).
pub fn new_signer() -> Result<SignatureKeyPair> {
    SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(Error::mls)
}

pub fn signer_public(s: &SignatureKeyPair) -> Vec<u8> {
    s.to_public_vec()
}

impl Device {
    pub fn create(
        user_id: UserId,
        device_id: DeviceId,
        username: String,
        generation: i64,
        token: String,
        account: &crypto::Account,
        signer: SignatureKeyPair,
    ) -> Result<Self> {
        let body = CredentialBody {
            u: user_id,
            d: device_id,
            s: B64(account.sign(&proto::device_binding(user_id, &signer.to_public_vec()))),
        };
        let cred: Credential =
            BasicCredential::new(serde_json::to_vec(&body).expect("json")).into();
        let credential = CredentialWithKey {
            credential: cred,
            signature_key: signer.to_public_vec().into(),
        };
        let provider = Provider {
            crypto: RustCrypto::default(),
            storage: MemoryStorage::default(),
        };
        signer.store(provider.storage()).map_err(Error::mls)?;
        let mut pins = BTreeMap::new();
        pins.insert(user_id, account.public());
        Ok(Device {
            user_id,
            device_id,
            username,
            generation,
            token,
            provider,
            signer,
            credential,
            groups: HashMap::new(),
            chans: BTreeMap::new(),
            pins,
            trust: BTreeMap::new(),
            users: BTreeMap::new(),
            changed: BTreeMap::new(),
            channels: vec![],
            is_admin: false,
        })
    }

    // ---------------- persistence ----------------

    pub fn export(&self) -> Vec<u8> {
        let storage = self
            .provider
            .storage
            .values
            .read()
            .expect("lock")
            .iter()
            .map(|(k, v)| (B64(k.clone()), B64(v.clone())))
            .collect();
        let p = Persisted {
            v: 1,
            user_id: self.user_id,
            device_id: self.device_id,
            username: self.username.clone(),
            generation: self.generation,
            token: self.token.clone(),
            signer: B64(serde_json::to_vec(&self.signer).expect("json")),
            credential: B64(self
                .credential
                .credential
                .tls_serialize_detached()
                .expect("tls")),
            storage,
            chans: self.chans.clone(),
            pins: self
                .pins
                .iter()
                .map(|(k, v)| (*k, B64(v.clone())))
                .collect(),
            trust: self.trust.clone(),
            users: self.users.values().cloned().collect(),
            changed: self.changed.clone(),
        };
        serde_json::to_vec(&p).expect("json")
    }

    pub fn import(bytes: &[u8]) -> Result<Self> {
        let p: Persisted =
            serde_json::from_slice(bytes).map_err(|e| Error::Other(e.to_string()))?;
        let storage = MemoryStorage::default();
        {
            let mut map = storage.values.write().expect("lock");
            for (k, v) in p.storage {
                map.insert(k.0, v.0);
            }
        }
        let provider = Provider {
            crypto: RustCrypto::default(),
            storage,
        };
        let signer: SignatureKeyPair =
            serde_json::from_slice(&p.signer.0).map_err(|e| Error::Other(e.to_string()))?;
        let credential = CredentialWithKey {
            credential: Credential::tls_deserialize_exact(&p.credential.0).map_err(Error::mls)?,
            signature_key: signer.to_public_vec().into(),
        };
        let mut groups = HashMap::new();
        for (cid, ch) in &p.chans {
            if ch.joined {
                if let Some(g) = MlsGroup::load(provider.storage(), &group_id(*cid, ch.generation))
                    .map_err(Error::mls)?
                {
                    groups.insert(*cid, g);
                }
            }
        }
        let mut chans = p.chans;
        for (cid, ch) in chans.iter_mut() {
            if ch.joined && !groups.contains_key(cid) {
                ch.joined = false;
            }
        }
        Ok(Device {
            user_id: p.user_id,
            device_id: p.device_id,
            username: p.username,
            generation: p.generation,
            token: p.token,
            provider,
            signer,
            credential,
            groups,
            chans,
            pins: p.pins.into_iter().map(|(k, v)| (k, v.0)).collect(),
            trust: p.trust,
            users: p.users.into_iter().map(|u| (u.id, u)).collect(),
            changed: p.changed,
            channels: vec![],
            is_admin: false,
        })
    }

    // ---------------- identity / trust ----------------

    pub fn own_fingerprint(&self) -> String {
        self.pins
            .get(&self.user_id)
            .map(|pk| crypto::fingerprint(pk))
            .unwrap_or_default()
    }

    pub fn fingerprint_of(&self, user: UserId) -> Option<String> {
        self.pins.get(&user).map(|pk| crypto::fingerprint(pk))
    }

    pub fn username_of(&self, user: UserId) -> String {
        self.users
            .get(&user)
            .map(|u| u.username.clone())
            .unwrap_or_else(|| format!("user#{user}"))
    }

    /// Verify a member's credential: the account key pinned for the claimed
    /// user must have signed this exact leaf signature key.
    fn verify_member(&mut self, cred: &Credential, sig_key: &[u8]) -> Option<CredentialBody> {
        let body = parse_credential(cred)?;
        let ok = self
            .pins
            .get(&body.u)
            .map(|pk| crypto::verify_sig(pk, &proto::device_binding(body.u, sig_key), &body.s.0))
            .unwrap_or(false);
        self.trust.insert(tkey(body.u, body.d), ok);
        ok.then_some(body)
    }

    fn is_trusted(&self, u: UserId, d: DeviceId) -> bool {
        self.trust.get(&tkey(u, d)).copied().unwrap_or(false)
    }

    // ---------------- key packages ----------------

    pub fn generate_key_packages(&self, n: usize) -> Result<Vec<B64>> {
        (0..n)
            .map(|_| {
                let kp = KeyPackage::builder()
                    .build(
                        CIPHERSUITE,
                        &self.provider,
                        &self.signer,
                        self.credential.clone(),
                    )
                    .map_err(Error::mls)?;
                Ok(B64(kp
                    .key_package()
                    .tls_serialize_detached()
                    .map_err(Error::mls)?))
            })
            .collect()
    }

    // ---------------- state ----------------

    /// Apply the server's view of channels and the user directory.
    pub fn apply_state(&mut self, st: &proto::StateResp, now_ms: i64) {
        self.is_admin = st.is_admin;
        self.username = st.username.clone();
        for u in &st.users {
            match self.pins.get(&u.id) {
                None => {
                    self.pins.insert(u.id, u.account_pk.0.clone());
                }
                Some(pk) if *pk != u.account_pk.0 => {
                    // Account key replaced: that user reset their password.
                    // Old devices are gone; re-pin and flag it in the UI.
                    self.pins.insert(u.id, u.account_pk.0.clone());
                    self.changed.insert(u.id, now_ms);
                    self.trust
                        .retain(|k, _| !k.starts_with(&format!("{}:", u.id)));
                }
                _ => {}
            }
            self.users.insert(u.id, u.clone());
        }
        let live: BTreeSet<ChannelId> = st.channels.iter().map(|c| c.id).collect();
        let dead: Vec<ChannelId> = self
            .chans
            .keys()
            .filter(|c| !live.contains(c))
            .copied()
            .collect();
        for cid in dead {
            self.drop_group(cid);
            self.chans.remove(&cid);
        }
        self.channels = st.channels.clone();
        self.channels.sort_by_key(|c| (c.position, c.id));
    }

    fn drop_group(&mut self, cid: ChannelId) {
        if let Some(mut g) = self.groups.remove(&cid) {
            let _ = g.delete(self.provider.storage());
        }
        if let Some(ch) = self.chans.get_mut(&cid) {
            ch.joined = false;
            ch.own.clear();
        }
    }

    fn system(&mut self, cid: ChannelId, seq: Seq, now_ms: i64, text: impl Into<String>) {
        let ch = self.chans.entry(cid).or_default();
        ch.messages.push(Msg {
            seq,
            user_id: 0,
            device_id: 0,
            ts: now_ms,
            body: MsgBody::System(text.into()),
            unverified: false,
        });
    }

    pub fn purge(&mut self, now_ms: i64, retention_days: u32) {
        for (cid, ch) in self.chans.iter_mut() {
            let ttl_h = self
                .channels
                .iter()
                .find(|c| c.id == *cid)
                .map(|c| c.ttl_hours)
                .filter(|h| *h > 0)
                .unwrap_or(retention_days as i64 * 24);
            let cutoff = now_ms - ttl_h * 3_600_000;
            ch.messages.retain(|m| m.ts >= cutoff);
            let extra = ch.messages.len().saturating_sub(MAX_CACHED_PER_CHANNEL);
            ch.messages.drain(..extra);
            if let Some(min_seq) = ch.messages.first().map(|m| m.seq) {
                ch.own.retain(|s| *s >= min_seq.min(ch.last_seq));
            }
        }
    }

    // ---------------- engine ----------------

    /// Full reconcile with the server. Safe to call any time.
    pub async fn tick(&mut self, http: &impl Http, now_ms: i64) -> Result<proto::StateResp> {
        let st: proto::StateResp = call_ok(http, "GET", "/api/state", NO_BODY).await?;
        if st.generation != self.generation {
            return Err(Error::Revoked);
        }
        self.apply_state(&st, now_ms);
        if st.key_packages_left < KEY_PACKAGE_LOW {
            let packages = self.generate_key_packages(KEY_PACKAGE_POOL)?;
            call_ok::<()>(
                http,
                "POST",
                "/api/keypackages",
                Some(&proto::KeyPackagesReq { packages }),
            )
            .await?;
        }
        if st.channels.iter().any(|c| c.has_welcome) {
            self.process_welcomes(http, now_ms).await?;
        }
        let channels = self.channels.clone();
        for c in &channels {
            let joined = self.groups.contains_key(&c.id);
            let ch = self.chans.entry(c.id).or_default();
            if joined && (!c.is_member || ch.generation != c.generation) {
                // We were removed, or the group was re-founded without us.
                self.drop_group(c.id);
            }
            let joined = self.groups.contains_key(&c.id);
            if !joined {
                if c.can_found {
                    self.found(http, c.id, c.generation, now_ms).await?;
                } else if c.is_member && !c.has_welcome {
                    // Server thinks we are in but we lost the group: ask again.
                    call_ok::<()>(
                        http,
                        "POST",
                        &format!("/api/channels/{}/rejoin", c.id),
                        NO_BODY,
                    )
                    .await?;
                }
            }
            if self.groups.contains_key(&c.id) {
                self.sync_channel(http, c.id, now_ms).await?;
                if c.has_pending {
                    self.handle_pending(http, c.id, now_ms).await?;
                }
            }
        }
        Ok(st)
    }

    async fn found(
        &mut self,
        http: &impl Http,
        cid: ChannelId,
        generation: i64,
        now_ms: i64,
    ) -> Result<()> {
        let r: Reply<proto::FoundResp> = call(
            http,
            "POST",
            &format!("/api/channels/{cid}/found"),
            Some(&proto::FoundReq { generation }),
        )
        .await?;
        let Reply::Ok(f) = r else { return Ok(()) };
        self.drop_group(cid);
        let g = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &create_config(),
            group_id(cid, f.generation),
            self.credential.clone(),
        )
        .map_err(Error::mls)?;
        self.groups.insert(cid, g);
        let ch = self.chans.entry(cid).or_default();
        ch.generation = f.generation;
        ch.joined = true;
        ch.last_seq = f.seq;
        ch.own.clear();
        self.trust.insert(tkey(self.user_id, self.device_id), true);
        self.system(
            cid,
            f.seq,
            now_ms,
            "New end-to-end encrypted session started",
        );
        Ok(())
    }

    pub async fn process_welcomes(&mut self, http: &impl Http, now_ms: i64) -> Result<()> {
        let w: proto::WelcomesResp = call_ok(http, "GET", "/api/welcomes", NO_BODY).await?;
        for wel in w.welcomes {
            let res = self.join_from_welcome(&wel);
            let failed = match res {
                Ok(()) => {
                    self.system(wel.channel_id, wel.commit_seq, now_ms, "You joined. Messages from before this point are not readable on this device.");
                    false
                }
                Err(_) => true,
            };
            call_ok::<()>(
                http,
                "POST",
                "/api/welcomes/ack",
                Some(&proto::AckWelcomeReq {
                    channel_id: wel.channel_id,
                    failed,
                }),
            )
            .await?;
            if !failed {
                self.sync_channel(http, wel.channel_id, now_ms).await?;
            }
        }
        Ok(())
    }

    fn join_from_welcome(&mut self, wel: &proto::Welcome) -> Result<()> {
        let msg = MlsMessageIn::tls_deserialize_exact(&wel.data.0).map_err(Error::mls)?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(Error::Mls("not a welcome".into()));
        };
        self.drop_group(wel.channel_id);
        let staged = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
            .map_err(Error::mls)?;
        let group = staged.into_group(&self.provider).map_err(Error::mls)?;
        if group.group_id() != &group_id(wel.channel_id, wel.generation) {
            return Err(Error::Mls("welcome for wrong group".into()));
        }
        let members: Vec<Member> = group.members().collect();
        for m in members {
            self.verify_member(&m.credential, &m.signature_key);
        }
        self.groups.insert(wel.channel_id, group);
        let ch = self.chans.entry(wel.channel_id).or_default();
        ch.generation = wel.generation;
        ch.joined = true;
        ch.last_seq = wel.commit_seq;
        ch.own.clear();
        Ok(())
    }

    /// Pull and process every new log entry of a channel.
    pub async fn sync_channel(
        &mut self,
        http: &impl Http,
        cid: ChannelId,
        now_ms: i64,
    ) -> Result<()> {
        loop {
            let after = self.chans.entry(cid).or_default().last_seq;
            let log: proto::LogResp = call_ok(
                http,
                "GET",
                &format!("/api/channels/{cid}/log?after={after}"),
                NO_BODY,
            )
            .await?;
            if self.groups.contains_key(&cid) && log.floor > after + 1 {
                // Retention deleted entries we never saw: our group state can
                // no longer be advanced. Start over with a fresh join.
                self.drop_group(cid);
                self.chans.entry(cid).or_default().last_seq = log.floor - 1;
                self.system(
                    cid,
                    log.floor - 1,
                    now_ms,
                    "Was offline too long; re-joining",
                );
                call_ok::<()>(
                    http,
                    "POST",
                    &format!("/api/channels/{cid}/rejoin"),
                    NO_BODY,
                )
                .await?;
                return Ok(());
            }
            if log.entries.is_empty() {
                return Ok(());
            }
            for e in log.entries {
                self.process_entry(cid, &e, now_ms);
                self.chans.entry(cid).or_default().last_seq = e.seq;
            }
        }
    }

    fn process_entry(&mut self, cid: ChannelId, e: &proto::LogEntry, now_ms: i64) {
        let ch = self.chans.entry(cid).or_default();
        if e.kind == proto::LogKind::Founded {
            if e.generation != ch.generation {
                self.drop_group(cid);
                self.system(cid, e.seq, now_ms, "Encryption session was re-created");
            }
            return;
        }
        if e.generation != ch.generation || !self.groups.contains_key(&cid) {
            return;
        }
        let own = ch.own.remove(&e.seq);
        if own {
            if e.kind == proto::LogKind::Commit {
                let g = self.groups.get_mut(&cid).expect("group");
                let _ = g.merge_pending_commit(&self.provider);
            }
            return;
        }
        let processed = (|| -> Result<ProcessedMessage> {
            let msg = MlsMessageIn::tls_deserialize_exact(&e.data.0).map_err(Error::mls)?;
            let pm = msg.try_into_protocol_message().map_err(Error::mls)?;
            let g = self.groups.get_mut(&cid).expect("group");
            g.process_message(&self.provider, pm).map_err(Error::mls)
        })();
        let processed = match processed {
            Ok(p) => p,
            Err(_) => {
                if e.kind == proto::LogKind::Commit {
                    // Possibly our own commit whose response got lost.
                    let g = self.groups.get_mut(&cid).expect("group");
                    if g.pending_commit().is_some() {
                        let _ = g.merge_pending_commit(&self.provider);
                    }
                } else {
                    self.chans.entry(cid).or_default().messages.push(Msg {
                        seq: e.seq,
                        user_id: 0,
                        device_id: 0,
                        ts: now_ms,
                        body: MsgBody::Undecryptable,
                        unverified: true,
                    });
                }
                return;
            }
        };
        let sender = parse_credential(processed.credential());
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                let (u, d) = sender.map(|s| (s.u, s.d)).unwrap_or((0, 0));
                let unverified = !self.is_trusted(u, d);
                let body = serde_json::from_slice::<Payload>(&app.into_bytes())
                    .ok()
                    .filter(|p| p.v == 1);
                let ch = self.chans.entry(cid).or_default();
                match body {
                    Some(p) => ch.messages.push(Msg {
                        seq: e.seq,
                        user_id: u,
                        device_id: d,
                        ts: p.ts,
                        body: MsgBody::Text(p.text.chars().take(MAX_TEXT).collect()),
                        unverified,
                    }),
                    None => ch.messages.push(Msg {
                        seq: e.seq,
                        user_id: u,
                        device_id: d,
                        ts: now_ms,
                        body: MsgBody::Undecryptable,
                        unverified,
                    }),
                }
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let adds: Vec<(Credential, Vec<u8>)> = staged
                    .add_proposals()
                    .map(|p| {
                        let ln = p.add_proposal().key_package().leaf_node();
                        (
                            ln.credential().clone(),
                            ln.signature_key().as_slice().to_vec(),
                        )
                    })
                    .collect();
                let self_removed = staged.self_removed();
                let g = self.groups.get_mut(&cid).expect("group");
                let merged = g.merge_staged_commit(&self.provider, *staged);
                for (c, k) in adds {
                    self.verify_member(&c, &k);
                }
                if self_removed || merged.is_err() {
                    self.drop_group(cid);
                }
            }
            _ => {}
        }
    }

    /// Add devices that are waiting to join, and evict removed ones.
    pub async fn handle_pending(
        &mut self,
        http: &impl Http,
        cid: ChannelId,
        now_ms: i64,
    ) -> Result<()> {
        for _attempt in 0..3 {
            if !self.groups.contains_key(&cid) {
                return Ok(());
            }
            self.sync_channel(http, cid, now_ms).await?;
            if !self.groups.contains_key(&cid) {
                return Ok(());
            }
            let p: proto::PendingResp = call_ok(
                http,
                "GET",
                &format!("/api/channels/{cid}/pending"),
                NO_BODY,
            )
            .await?;
            if p.joins.is_empty() && p.removals.is_empty() {
                return Ok(());
            }
            let mut dismiss = proto::DismissReq::default();
            let mut kps = vec![];
            let mut added = vec![];
            let present: Vec<(DeviceId, LeafNodeIndex)> = self.groups[&cid]
                .members()
                .filter_map(|m| parse_credential(&m.credential).map(|b| (b.d, m.index)))
                .collect();
            for j in &p.joins {
                if present.iter().any(|(d, _)| *d == j.device_id) {
                    dismiss.joins.push(j.device_id);
                    continue;
                }
                let kp = KeyPackageIn::tls_deserialize_exact(&j.key_package.0)
                    .map_err(Error::mls)
                    .and_then(|k| {
                        k.validate(self.provider.crypto(), ProtocolVersion::Mls10)
                            .map_err(Error::mls)
                    });
                let Ok(kp) = kp else {
                    dismiss.joins.push(j.device_id);
                    continue;
                };
                if kp.ciphersuite() != CIPHERSUITE {
                    dismiss.joins.push(j.device_id);
                    continue;
                }
                let ln = kp.leaf_node();
                let sig_key = ln.signature_key().as_slice().to_vec();
                // Refuse anything the claimed account key did not sign: a
                // malicious server cannot slip its own device into a channel.
                match self.verify_member(&ln.credential().clone(), &sig_key) {
                    Some(b) if b.u == j.user_id && b.d == j.device_id => {
                        kps.push(kp);
                        added.push(proto::AddedDevice {
                            device_id: j.device_id,
                            key_package_id: j.key_package_id,
                        });
                    }
                    _ => dismiss.joins.push(j.device_id),
                }
            }
            let mut removed = vec![];
            let mut leaves = vec![];
            for d in &p.removals {
                if *d == self.device_id {
                    continue;
                }
                match present.iter().find(|(pd, _)| pd == d) {
                    Some((_, idx)) => {
                        removed.push(*d);
                        leaves.push(*idx);
                    }
                    None => dismiss.removals.push(*d),
                }
            }
            if !dismiss.joins.is_empty() || !dismiss.removals.is_empty() {
                call_ok::<()>(
                    http,
                    "POST",
                    &format!("/api/channels/{cid}/dismiss"),
                    Some(&dismiss),
                )
                .await?;
            }
            if kps.is_empty() && leaves.is_empty() {
                return Ok(());
            }
            let g = self.groups.get_mut(&cid).expect("group");
            let bundle = g
                .commit_builder()
                .propose_adds(kps)
                .propose_removals(leaves)
                .load_psks(self.provider.storage())
                .map_err(Error::mls)?
                .build(
                    self.provider.rand(),
                    self.provider.crypto(),
                    &self.signer,
                    |_| true,
                )
                .map_err(Error::mls)?
                .stage_commit(&self.provider)
                .map_err(Error::mls)?;
            let epoch = g.epoch().as_u64() as i64;
            let (commit, welcome, _) = bundle.into_messages();
            let req = proto::CommitReq {
                epoch,
                generation: self.chans[&cid].generation,
                commit: B64(commit.tls_serialize_detached().map_err(Error::mls)?),
                welcome: welcome
                    .map(|w| w.tls_serialize_detached().map(B64))
                    .transpose()
                    .map_err(Error::mls)?,
                added,
                removed,
            };
            let r: Reply<proto::SendResp> = call(
                http,
                "POST",
                &format!("/api/channels/{cid}/commit"),
                Some(&req),
            )
            .await?;
            match r {
                Reply::Ok(s) => {
                    self.chans.entry(cid).or_default().own.insert(s.seq);
                    self.sync_channel(http, cid, now_ms).await?;
                    return Ok(());
                }
                Reply::Conflict(_) => {
                    let g = self.groups.get_mut(&cid).expect("group");
                    let _ = g.clear_pending_commit(self.provider.storage());
                }
            }
        }
        Ok(())
    }

    pub async fn send_text(
        &mut self,
        http: &impl Http,
        cid: ChannelId,
        text: &str,
        now_ms: i64,
    ) -> Result<()> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(());
        }
        if text.chars().count() > MAX_TEXT {
            return Err(Error::Other(format!("Message too long (max {MAX_TEXT})")));
        }
        let payload = serde_json::to_vec(&Payload {
            v: 1,
            ts: now_ms,
            text: text.to_string(),
        })
        .expect("json");
        for _ in 0..4 {
            self.sync_channel(http, cid, now_ms).await?;
            let generation = self.chans.entry(cid).or_default().generation;
            let Some(g) = self.groups.get_mut(&cid) else {
                return Err(Error::Other(
                    "Still joining this channel — waiting for a member to let this device in"
                        .into(),
                ));
            };
            let out = g
                .create_message(&self.provider, &self.signer, &payload)
                .map_err(Error::mls)?;
            let req = proto::SendReq {
                epoch: g.epoch().as_u64() as i64,
                generation,
                data: B64(out.tls_serialize_detached().map_err(Error::mls)?),
            };
            let r: Reply<proto::SendResp> = call(
                http,
                "POST",
                &format!("/api/channels/{cid}/send"),
                Some(&req),
            )
            .await?;
            if let Reply::Ok(s) = r {
                let ch = self.chans.entry(cid).or_default();
                ch.own.insert(s.seq);
                ch.messages.push(Msg {
                    seq: s.seq,
                    user_id: self.user_id,
                    device_id: self.device_id,
                    ts: now_ms,
                    body: MsgBody::Text(text.to_string()),
                    unverified: false,
                });
                return Ok(());
            }
        }
        Err(Error::Other("Channel is busy, try again".into()))
    }

    /// A moderator deleted a log entry.
    pub fn delete_local(&mut self, cid: ChannelId, seq: Seq) {
        if let Some(ch) = self.chans.get_mut(&cid) {
            ch.messages.retain(|m| m.seq != seq);
        }
    }

    pub fn is_joined(&self, cid: ChannelId) -> bool {
        self.groups.contains_key(&cid)
    }

    pub fn member_devices(&self, cid: ChannelId) -> Vec<(UserId, DeviceId, bool)> {
        self.groups
            .get(&cid)
            .map(|g| {
                g.members()
                    .filter_map(|m| parse_credential(&m.credential))
                    .map(|b| (b.u, b.d, self.is_trusted(b.u, b.d)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Short code that is identical for everyone in the same channel epoch;
    /// compare it out-of-band to rule out a man in the middle.
    pub fn epoch_code(&self, cid: ChannelId) -> Option<String> {
        let g = self.groups.get(&cid)?;
        let a = g.epoch_authenticator().as_slice();
        Some(
            crypto::fingerprint(a)
                .split(' ')
                .take(4)
                .collect::<Vec<_>>()
                .join(" "),
        )
    }
}
