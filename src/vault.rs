//! The secret vault. Redaction replaces a secret with a marker carrying an
//! id; the original goes here, encrypted, so it can still be revealed on
//! this Mac. The vault lives outside the Dolt repo and is never synced:
//! other Macs only ever see markers.
//!
//! - Values: ChaCha20-Poly1305, random nonce per value.
//! - Key: 32 random bytes in the macOS Keychain (service "agentd-vault"),
//!   or AGENTD_VAULT_KEY (hex) for tests and non-macOS use.
//! - Ids: HMAC-SHA256(key, kind || value), first 12 hex chars. Keyed, so a
//!   synced marker can't be brute-forced back to a weak password the way a
//!   plain hash could; deterministic, so re-ingesting a file reproduces the
//!   same text (and hash).

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use std::path::Path;
use std::process::Command;

const KEYCHAIN_SERVICE: &str = "agentd-vault";

pub struct Vault {
    key: [u8; 32],
    conn: Connection,
    origin: String,
}

fn parse_key(hex_key: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_key.trim()).context("vault key is not hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("vault key must be 32 bytes"))
}

/// Reads the key from the Keychain, creating it on first use.
fn keychain_key(account: &str) -> Result<[u8; 32]> {
    let found = Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            account,
            "-w",
        ])
        .output()
        .context("running security (macOS Keychain)")?;
    if found.status.success() {
        return parse_key(&String::from_utf8_lossy(&found.stdout));
    }
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let hex_key = hex::encode(key);
    // -w as an argument is briefly visible in `ps` to this user only; the
    // alternative (an interactive prompt) can't run under launchd.
    let added = Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            account,
            "-w",
            &hex_key,
            "-U",
        ])
        .output()?;
    if !added.status.success() {
        bail!(
            "could not store the vault key in the Keychain: {}",
            String::from_utf8_lossy(&added.stderr).trim()
        );
    }
    parse_key(&hex_key)
}

impl Vault {
    pub fn open(path: &Path, machine: &str) -> Result<Vault> {
        let key = match std::env::var("AGENTD_VAULT_KEY") {
            Ok(k) => parse_key(&k)?,
            Err(_) => keychain_key(machine)?,
        };
        Self::open_with_key(path, key, machine)
    }

    pub fn open_with_key(path: &Path, key: [u8; 32], origin: &str) -> Result<Vault> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
               id TEXT PRIMARY KEY, kind TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
               origin TEXT NOT NULL, created_ms INTEGER NOT NULL
             );",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Vault {
            key,
            conn,
            origin: origin.to_string(),
        })
    }

    pub fn id(&self, kind: &str, value: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("any key length");
        mac.update(kind.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        hex::encode(&mac.finalize().into_bytes()[..6])
    }

    /// Stores the value (once) and returns its id.
    pub fn store(&self, kind: &str, value: &str) -> Result<String> {
        let id = self.id(kind, value);
        let exists: Option<i64> = self
            .conn
            .query_row("SELECT 1 FROM secrets WHERE id = ?1", params![id], |r| {
                r.get(0)
            })
            .optional()?;
        if exists.is_none() {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let ct = cipher
                .encrypt(&nonce, value.as_bytes())
                .map_err(|_| anyhow!("encrypting a secret failed"))?;
            self.conn.execute(
                "INSERT INTO secrets (id, kind, nonce, ciphertext, origin, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, kind, nonce.as_slice(), ct, self.origin, crate::dolt::now_ms()],
            )?;
        }
        Ok(id)
    }

    /// The original value, or None if this Mac never saw it (it was
    /// redacted on another Mac, whose vault holds it).
    pub fn reveal(&self, id: &str) -> Result<Option<(String, String)>> {
        let row: Option<(String, Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT kind, nonce, ciphertext FROM secrets WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((kind, nonce, ct)) = row else {
            return Ok(None);
        };
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
            .map_err(|_| anyhow!("decrypting secret {id} failed (wrong vault key?)"))?;
        Ok(Some((kind, String::from_utf8_lossy(&pt).into_owned())))
    }

    pub fn len(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))?)
    }
}

/// Secrets inside JSONL are stored JSON-escaped (`\n`, `\"`); show them as
/// they were typed.
pub fn display_value(raw: &str) -> String {
    serde_json::from_str::<String>(&format!("\"{raw}\"")).unwrap_or_else(|_| raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_encrypted_reveals_and_ids_are_keyed() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open_with_key(&dir.path().join("vault.sqlite"), [7u8; 32], "mac-a").unwrap();
        let id = v.store("env-secret", "hunter2-correct-horse").unwrap();
        assert_eq!(id.len(), 12);
        assert_eq!(v.store("env-secret", "hunter2-correct-horse").unwrap(), id); // deterministic, stored once
        assert_eq!(v.len().unwrap(), 1);
        assert_eq!(
            v.reveal(&id).unwrap(),
            Some(("env-secret".into(), "hunter2-correct-horse".into()))
        );
        assert_eq!(v.reveal("000000000000").unwrap(), None);
        // a different key gives a different id: the marker alone says nothing about the value
        let other =
            Vault::open_with_key(&dir.path().join("other.sqlite"), [8u8; 32], "mac-b").unwrap();
        assert_ne!(other.id("env-secret", "hunter2-correct-horse"), id);
        // and the file on disk never holds the plaintext
        let raw = std::fs::read(dir.path().join("vault.sqlite")).unwrap();
        assert!(!raw.windows(7).any(|w| w == b"hunter2"));
    }

    #[test]
    fn display_unescapes_json() {
        assert_eq!(display_value(r#"line1\nline2 \"q\""#), "line1\nline2 \"q\"");
        assert_eq!(display_value("plain"), "plain");
    }
}
