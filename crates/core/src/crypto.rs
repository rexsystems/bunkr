//! Password hardening, symmetric sealing and account identity keys.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// Argon2id cost. 64 MiB / 3 passes: ~1s in a browser, painful for GPUs.
pub const ARGON_M_KIB: u32 = 64 * 1024;
pub const ARGON_T: u32 = 3;
pub const ARGON_P: u32 = 1;

/// Keys derived from the password. `auth_key` goes to the server (it proves
/// you know the password); `master_key` never leaves the device and encrypts
/// the account key and all local data.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct PasswordKeys {
    pub auth_key: [u8; 32],
    pub master_key: [u8; 32],
}

pub fn random_salt() -> Vec<u8> {
    let mut s = vec![0u8; 16];
    OsRng.fill_bytes(&mut s);
    s
}

pub fn derive_password_keys(password: &str, salt: &[u8]) -> Result<PasswordKeys, Error> {
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(64))
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 64];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let mut keys = PasswordKeys {
        auth_key: [0; 32],
        master_key: [0; 32],
    };
    // Domain-separate the halves so neither can be derived from the other.
    keys.auth_key = sub_key(&out, b"bunkr/auth");
    keys.master_key = sub_key(&out, b"bunkr/master");
    out.zeroize();
    Ok(keys)
}

fn sub_key(ikm: &[u8], label: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update([0u8]);
    h.update(ikm);
    h.finalize().into()
}

/// XChaCha20-Poly1305 seal: `nonce(24) || ciphertext`.
pub fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad })
        .expect("encryption cannot fail");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() < 24 + 16 {
        return Err(Error::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&sealed[..24]),
            Payload {
                msg: &sealed[24..],
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

/// Long-term account identity. Signs every device the user logs in from.
#[derive(Clone)]
pub struct Account {
    pub sk: SigningKey,
}

impl Account {
    pub fn generate() -> Self {
        Account {
            sk: SigningKey::generate(&mut OsRng),
        }
    }
    pub fn public(&self) -> Vec<u8> {
        self.sk.verifying_key().to_bytes().to_vec()
    }
    pub fn seal(&self, master: &[u8; 32]) -> Vec<u8> {
        seal(master, b"bunkr/account-key/v1", &self.sk.to_bytes())
    }
    pub fn open(master: &[u8; 32], blob: &[u8]) -> Result<Self, Error> {
        let mut raw = open(master, b"bunkr/account-key/v1", blob)?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| Error::Decrypt)?;
        raw.zeroize();
        Ok(Account {
            sk: SigningKey::from_bytes(&arr),
        })
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sk.sign(msg).to_bytes().to_vec()
    }
}

pub fn verify_sig(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(pk) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

/// Human-comparable fingerprint of an account key: 8 groups of 5 digits.
pub fn fingerprint(account_pk: &[u8]) -> String {
    let h = Sha256::digest([b"bunkr/fingerprint/v1".as_slice(), account_pk].concat());
    h.chunks(4)
        .take(8)
        .map(|c| format!("{:05}", u32::from_be_bytes(c.try_into().unwrap()) % 100_000))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_tamper() {
        let k = [7u8; 32];
        let s = seal(&k, b"a", b"hello");
        assert_eq!(open(&k, b"a", &s).unwrap(), b"hello");
        assert!(open(&k, b"b", &s).is_err());
        let mut t = s.clone();
        *t.last_mut().unwrap() ^= 1;
        assert!(open(&k, b"a", &t).is_err());
    }

    #[test]
    fn password_keys_differ_and_are_deterministic() {
        let salt = [1u8; 16];
        let a = derive_password_keys("hunter2", &salt).unwrap();
        let b = derive_password_keys("hunter2", &salt).unwrap();
        let c = derive_password_keys("hunter3", &salt).unwrap();
        assert_eq!(a.auth_key, b.auth_key);
        assert_ne!(a.auth_key, a.master_key);
        assert_ne!(a.auth_key, c.auth_key);
    }

    #[test]
    fn account_seal() {
        let acc = Account::generate();
        let m = [3u8; 32];
        let blob = acc.seal(&m);
        let back = Account::open(&m, &blob).unwrap();
        assert_eq!(acc.public(), back.public());
        assert!(Account::open(&[4u8; 32], &blob).is_err());
        let sig = acc.sign(b"x");
        assert!(verify_sig(&acc.public(), b"x", &sig));
        assert!(!verify_sig(&acc.public(), b"y", &sig));
    }
}
