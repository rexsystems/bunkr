//! Account flows: register, login (new device), password change, and the
//! encrypted on-device vault.

use bunkr_proto::{self as proto, B64};
use serde::{Deserialize, Serialize};

use crate::{
    call_ok,
    crypto::{self, Account, PasswordKeys},
    device::{self, Device},
    Error, Http, Result, NO_BODY,
};

pub const MIN_PASSWORD: usize = 10;

pub fn check_password_strength(pw: &str) -> std::result::Result<(), String> {
    if pw.chars().count() < MIN_PASSWORD {
        return Err(format!("Use at least {MIN_PASSWORD} characters"));
    }
    let classes = [
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if classes < 2 && pw.chars().count() < 16 {
        return Err("Mix letters, numbers or symbols (or use 16+ characters)".into());
    }
    Ok(())
}

/// What is kept on disk. Everything except the salt + username is sealed
/// with the password-derived master key.
#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub v: u32,
    pub server: String,
    pub username: String,
    pub salt: B64,
    pub sealed: B64,
}

impl Vault {
    pub fn seal(server: &str, keys: &PasswordKeys, salt: &[u8], dev: &Device) -> Vault {
        Vault {
            v: 1,
            server: server.to_string(),
            username: dev.username.clone(),
            salt: B64(salt.to_vec()),
            sealed: B64(crypto::seal(
                &keys.master_key,
                b"bunkr/vault/v1",
                &dev.export(),
            )),
        }
    }

    pub fn open(&self, password: &str) -> Result<(PasswordKeys, Device)> {
        let keys = crypto::derive_password_keys(password, &self.salt.0)?;
        let raw = crypto::open(&keys.master_key, b"bunkr/vault/v1", &self.sealed.0)?;
        Ok((keys, Device::import(&raw)?))
    }

    /// Re-seal with already-derived keys (no Argon2 on every save).
    pub fn reseal(&mut self, keys: &PasswordKeys, dev: &Device) {
        self.sealed = B64(crypto::seal(
            &keys.master_key,
            b"bunkr/vault/v1",
            &dev.export(),
        ));
    }
}

pub async fn register(
    http: &impl Http,
    username: &str,
    password: &str,
    setup_code: Option<String>,
) -> Result<(PasswordKeys, Vec<u8>, Device)> {
    check_password_strength(password).map_err(Error::Other)?;
    let username = proto::normalize_username(username)
        .ok_or_else(|| Error::Other("Username: 3-32 chars, a-z 0-9 _ . -".into()))?;
    let salt = crypto::random_salt();
    let keys = crypto::derive_password_keys(password, &salt)?;
    let account = Account::generate();
    http.set_token(None);
    let resp: proto::LoginResp = call_ok(
        http,
        "POST",
        "/api/register",
        Some(&proto::RegisterReq {
            username: username.clone(),
            salt: B64(salt.clone()),
            auth_key: B64(keys.auth_key.to_vec()),
            account_pk: B64(account.public()),
            key_blob: B64(account.seal(&keys.master_key)),
            setup_code,
        }),
    )
    .await?;
    let dev = finish_login(http, &username, &keys, resp).await?;
    Ok((keys, salt, dev))
}

pub async fn login(
    http: &impl Http,
    username: &str,
    password: &str,
) -> Result<(PasswordKeys, Vec<u8>, Device)> {
    let username = proto::normalize_username(username)
        .ok_or_else(|| Error::Other("Wrong username or password".into()))?;
    http.set_token(None);
    let pre: proto::PreloginResp = call_ok(
        http,
        "POST",
        "/api/prelogin",
        Some(&proto::PreloginReq {
            username: username.clone(),
        }),
    )
    .await?;
    let keys = crypto::derive_password_keys(password, &pre.salt.0)?;
    let resp: proto::LoginResp = call_ok(
        http,
        "POST",
        "/api/login",
        Some(&proto::LoginReq {
            username: username.clone(),
            auth_key: B64(keys.auth_key.to_vec()),
        }),
    )
    .await
    .map_err(|e| match e {
        Error::Revoked => Error::Other("Wrong username or password".into()),
        e => e,
    })?;
    let dev = finish_login(http, &username, &keys, resp).await?;
    Ok((keys, pre.salt.0, dev))
}

async fn finish_login(
    http: &impl Http,
    username: &str,
    keys: &PasswordKeys,
    resp: proto::LoginResp,
) -> Result<Device> {
    let account = Account::open(&keys.master_key, &resp.key_blob.0)?;
    if account.public() != resp.account_pk.0 {
        return Err(Error::Other(
            "Server returned a mismatched identity key".into(),
        ));
    }
    http.set_token(Some(resp.token.clone()));
    let signer = device::new_signer()?;
    let sig_pk = device::signer_public(&signer);
    let d: proto::DeviceResp = call_ok(
        http,
        "POST",
        "/api/device",
        Some(&proto::DeviceReq {
            sig_pk: B64(sig_pk.clone()),
            account_sig: B64(account.sign(&proto::device_binding(resp.user_id, &sig_pk))),
        }),
    )
    .await?;
    let dev = Device::create(
        resp.user_id,
        d.device_id,
        username.to_string(),
        resp.generation,
        resp.token,
        &account,
        signer,
    )?;
    let packages = dev.generate_key_packages(device::KEY_PACKAGE_POOL)?;
    call_ok::<()>(
        http,
        "POST",
        "/api/keypackages",
        Some(&proto::KeyPackagesReq { packages }),
    )
    .await?;
    Ok(dev)
}

/// Change the password. This resets EVERYTHING: a brand-new account identity
/// is created, every device (including this one) is logged out and removed
/// from all channels, and local data must be wiped by the caller.
pub async fn change_password(
    http: &impl Http,
    old_keys: &PasswordKeys,
    new_password: &str,
) -> Result<()> {
    check_password_strength(new_password).map_err(Error::Other)?;
    let salt = crypto::random_salt();
    let keys = crypto::derive_password_keys(new_password, &salt)?;
    let account = Account::generate();
    call_ok::<()>(
        http,
        "POST",
        "/api/password",
        Some(&proto::PasswordChangeReq {
            old_auth_key: B64(old_keys.auth_key.to_vec()),
            new_salt: B64(salt),
            new_auth_key: B64(keys.auth_key.to_vec()),
            new_account_pk: B64(account.public()),
            new_key_blob: B64(account.seal(&keys.master_key)),
        }),
    )
    .await
}

pub async fn logout(http: &impl Http) -> Result<()> {
    call_ok::<()>(http, "POST", "/api/logout", NO_BODY).await
}
