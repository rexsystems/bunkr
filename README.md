<div align="center">

<img src="crates/web/static/icon.svg" width="88" alt="Bunkr">

# bunkr

**A self-hosted, Discord-style group chat where the server knows nothing.**

Post-quantum MLS end-to-end encryption · 100% Rust · Web, phone, macOS, Linux, Windows, Android (x64 + ARM)

</div>

<p align="center">
  <img src="docs/desktop.png" width="74%" alt="Bunkr desktop">
  &nbsp;
  <img src="docs/mobile.png" width="20%" alt="Bunkr on a phone">
</p>

## Features

- **Public channels** that everyone is in, and **private DMs**. Each one is its own end-to-end encrypted MLS group.
- **Replies, edits, deletes, reactions, @mentions**, and a typing indicator that is encrypted too.
- **Encrypted files and images.** They are encrypted on your device before upload, with drag & drop and paste.
- **Voice and video calls with screen sharing.** Peer-to-peer WebRTC, with call setup signed and encrypted through MLS.
- **Search** that runs on your device only, because the server can't search what it can't read.
- **Notifications.** In-app or native while Bunkr is open, and empty web push while it's closed (no text, sender or channel).
- **Disappearing messages** per channel (set by the admin) or per DM (set by either person).
- **Admin tools:** ban, delete accounts, promote admins, manage channels, close registration, remove messages.
- **Password change = total reset** of keys, devices and history.

---

## Self-host in one command

You need a Linux VPS with Docker installed.

```bash
git clone https://github.com/rexsystems/bunkr && cd bunkr && docker compose up -d --build
```

Bunkr is now on `http://YOUR_SERVER:8080`.

**With a domain and automatic HTTPS (recommended):** point a DNS `A` record at the VPS, then run:

```bash
BUNKR_DOMAIN=chat.example.com docker compose --profile tls up -d --build
```

Caddy fetches and renews the Let's Encrypt certificate for you.

Or run the guided installer. It asks for the domain, can also set up a TURN relay for calls, and prints the setup code:

```bash
./install.sh
```

**Calls across any network:** calls are peer-to-peer. To make them work behind strict NATs and mobile networks, run the bundled TURN relay. `./install.sh` sets this up for you. To do it by hand, set `BUNKR_TURN_SECRET` (a long random string), `BUNKR_TURN_URLS=turn:chat.example.com:3478?transport=udp,turn:chat.example.com:3478?transport=tcp` and `BUNKR_STUN_URLS=stun:chat.example.com:3478`, add `--profile calls`, and open UDP/TCP `3478` and UDP `49160-49260`. The relay only ever forwards encrypted media, and it refuses to relay into private networks.

### First login = admin

On first start the server prints a one-time **setup code** in its logs:

```bash
docker compose logs bunkr | grep -A1 "SETUP CODE"
```

Open Bunkr, enter the code and create the first account. That account is the **admin**.

> [!IMPORTANT]
> Use HTTPS in production. The browser downloads the encryption code from your server. Over plain HTTP, anyone on the network path could swap that code.

### Configuration

| Variable | Default | What it does |
|---|---|---|
| `BUNKR_DOMAIN` | – | Domain for automatic HTTPS (with `--profile tls`) |
| `BUNKR_NAME` | `Bunkr` | Server name shown in the app |
| `BUNKR_RETENTION_DAYS` | `30` | Ciphertext older than this is deleted from the server |
| `BUNKR_PORT` | `8080` | Host port (plain HTTP mode) |
| `BUNKR_SETUP_CODE` | random | Fixed first-run setup code, if you prefer to set your own |
| `BUNKR_MAX_UPLOAD_MB` | `25` | Max size of one encrypted attachment |
| `BUNKR_MAX_STORAGE_GB` | `20` | Total attachment storage on the server |
| `BUNKR_TURN_URLS` / `BUNKR_STUN_URLS` / `BUNKR_TURN_SECRET` | – | TURN/STUN relay for calls (see above) |
| `BUNKR_PUSH` | `on` | `off` disables web push |
| `BUNKR_PUSH_CONTACT` | `mailto:admin@<domain>` | Contact sent to push services (VAPID) |

Put them in a `.env` file next to `docker-compose.yml`, or prefix the command with them.

**Update:** `git pull && docker compose up -d --build`
**Backup:** the `bunkr-data` Docker volume (a single SQLite file).

---

## Apps

| Platform | How |
|---|---|
| **Browser (desktop + phone)** | Open your server URL. The layout is responsive, with a drawer and bottom sheet on phones. Use "Add to Home Screen" to install it like an app. |
| **macOS** (Apple Silicon + Intel) | `.dmg` from [Releases](../../releases) |
| **Windows** (x64 + ARM64) | `.msi` / `-setup.exe` from Releases |
| **Linux** (x64 + ARM64) | `.AppImage` / `.deb` / `.rpm` from Releases |
| **Android** | `bunkr-android.apk` from Releases |
| **iPhone / iPad** | Open your server in Safari → Share → **Add to Home Screen**. Push works from the home-screen app (iOS 16.4+). |

The desktop and Android apps are a thin [Tauri](https://tauri.app) shell around the same Rust/WASM client. They add native notifications, microphone/camera access and a banner when a new release is out. On first launch, enter your server address.

**Release:** `git tag v0.2.0 && git push --tags`. GitHub Actions builds all platforms into a draft release.

#### Signing (optional, do it once)
Unsigned builds work, but macOS and Windows warn on first open. The Android APK is signed with a throwaway key until you add a real one, so updates need a reinstall. Add these repository secrets and the workflow uses them automatically:

| Platform | Secrets |
|---|---|
| Android | `ANDROID_KEYSTORE_B64` (`base64 -w0 release.jks`), `ANDROID_KEYSTORE_PASSWORD` (key alias `bunkr`) |
| macOS | `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` ([Tauri guide](https://v2.tauri.app/distribute/sign/macos/)) |
| Windows | a code-signing certificate ([Tauri guide](https://v2.tauri.app/distribute/sign/windows/)) |

Create the Android key with `keytool -genkeypair -keystore release.jks -alias bunkr -keyalg RSA -keysize 4096 -validity 10000`.

---

## Security model

Bunkr's server is a **zero-knowledge delivery service**. It routes and stores opaque ciphertext and nothing else.

### Encryption
- **Every channel is an [MLS](https://www.rfc-editor.org/rfc/rfc9420) group** ([OpenMLS](https://github.com/openmls/openmls)), with forward secrecy and post-compromise security.
- **Post-quantum hybrid ciphersuite:** `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519`. Key exchange combines ML-KEM-768 and X25519, so it stays secure if either one holds.
- **Messages are padded** to 256-byte blocks so their length leaks less.
- **New devices cannot read history** from before they joined. That is how MLS works, and it is intentional.

### Identity
- Your password never leaves the device. **Argon2id** (64 MiB, 3 passes) derives two keys from it:
  - an `auth_key`, which proves who you are (the server stores only a hash of it);
  - a `master_key`, which never leaves the device and encrypts your account key and the local vault.
- Every account has an **Ed25519 identity key**, and every device is **signed by it**. Members' apps refuse to add a device whose signature doesn't verify, so **a malicious server cannot inject a device into a channel**.
- Account keys are pinned on first use. If someone's key changes, everyone sees a **"new identity"** warning.
- Fingerprints and a per-channel **epoch security code** can be compared out-of-band to rule out a man-in-the-middle.

### 🔥 Password change = total reset
Changing your password:
1. creates a brand-new identity key;
2. logs out **every** device (including the current one);
3. removes you from every encrypted group, so other members' apps evict your old devices;
4. wipes local history everywhere.

Then you log in fresh with the new password, under a new identity. **There is no password recovery.** If you lose the password, the account is gone.

If a session is revoked (password changed elsewhere, logout, ban), the app **wipes its local vault immediately**.

### Calls
Call setup (SDP offers/answers and ICE candidates) is sent as **MLS-encrypted, never-stored** messages from verified devices only. That means the DTLS fingerprints in it are authenticated end-to-end, so the media (DTLS-SRTP) can't be intercepted by the server or the TURN relay. Calls are a peer-to-peer mesh of up to 8 people. Without a TURN relay, peers see each other's IP addresses.

### Files
Each attachment gets a fresh random key (XChaCha20-Poly1305). The key travels only inside the MLS message, so the server stores opaque blobs. Only members of the conversation can download them, only the sender can delete them, and retention applies to them too.

### Minimal data
The server stores **only**: username, password-hash-of-a-derived-key, salt, public identity key, encrypted account key, device public keys, and channel ciphertext.

It also stores, for web push only, the push endpoint of the devices that opted in. Pushes contain **no payload at all**.

It does **not** store: who sent a message, IP addresses, emails, phone numbers, user agents, or exact timestamps (only the hour, for retention). It writes no request logs. Ciphertext is deleted after `BUNKR_RETENTION_DAYS`, or sooner in channels with **disappearing messages**.

### On the device
Everything local (MLS state, keys, message cache, session token) lives in an encrypted **vault** (XChaCha20-Poly1305 with the master key). You need your password to unlock it every time the app opens. The **Panic** button wipes it instantly.

### Hardening
Strict CSP (no inline scripts, no third-party anything), `frame-ancestors 'none'`, `no-referrer`, rate limits on logins, signups, uploads and realtime signals, constant-time comparisons, salts that don't reveal whether an account exists, and a non-root, read-only distroless container. Push endpoints are restricted to the real push services, so the server can't be used for SSRF. The TURN relay refuses private and loopback peers. Downloaded files are never rendered on Bunkr's origin: only allow-listed image types are shown inline, and everything else is an opaque download.

> [!WARNING]
> Bunkr has **not** been independently audited. It is built on well-reviewed libraries (OpenMLS, RustCrypto), and the protocol is covered by end-to-end tests. Until an audit happens, treat it as "very strong, unaudited".

---

## Admin

The admin's settings include **Users** and **Channels** tabs:
- **Ban / unban** a user. A ban kills all their devices instantly and evicts them from every encrypted group.
- **Delete** accounts, **promote/demote** admins.
- **Create / rename / delete channels.** Everyone is automatically in every channel, like a single Discord server.
- Set **disappearing messages** per channel (1 hour up to 90 days).
- **Open or close registration.**
- **Delete any message** for everyone. Admins can only delete messages, not read more than other members can.

---

## Architecture

```
crates/
  proto/    wire types shared by server & clients
  core/     ALL client crypto: Argon2id, vault, account keys, OpenMLS groups, sync engine
  server/   axum + SQLite + WebSocket delivery service (no crypto keys, ever)
  web/      Leptos (Rust → WebAssembly) UI, Hugeicons, Geist font
  e2e/      real-server protocol tests (join races, reset, ban, re-founding, no plaintext on disk)
desktop/    Tauri 2 shell for macOS / Windows / Linux
```

How a channel stays encrypted:

1. The first device to arrive **founds** the channel's MLS group.
2. New devices upload signed MLS KeyPackages. The server queues a "join".
3. Any online member's app verifies the device signature, **commits the add**, and the server delivers the Welcome.
4. If no member is online for a few seconds, the waiting device **re-founds** the group (new keys). Returning members are added back automatically.
5. The server enforces one ordered log per channel (epoch check). That avoids forks without the server ever seeing keys.

### Develop

```bash
# server
cargo run -p bunkr-server            # http://localhost:8080, data in ./data
# web client (needs: rustup target add wasm32-unknown-unknown, wasm-bindgen-cli 0.2.130)
./scripts/build-web.sh               # -> crates/web/dist (served by the server)
# tests (spawns a real server)
cargo build -p bunkr-server && cargo test -p bunkr-core -p bunkr-e2e
# desktop
cd desktop && npm install && npx tauri dev
```

Icons: [Hugeicons](https://hugeicons.com) free set (MIT), regenerated with `node scripts/gen-icons.mjs`. Font: [Geist](https://vercel.com/font) (OFL).

---

## License

AGPL-3.0-or-later
