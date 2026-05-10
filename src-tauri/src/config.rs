//! Persists the DPAPI-encrypted WireGuard config blob to the Windows Registry.
//!
//! Storage: HKCU\Software\SWGC\Config  (value "EncryptedBlob", REG_BINARY)
//!
//! Security properties:
//! - Only the DPAPI ciphertext is written — plaintext never touches disk.
//! - The DPAPI entropy is derived from the user's passphrase via PBKDF2 and is
//!   never stored anywhere.  An attacker with the registry blob must also know
//!   the passphrase (and be the same Windows user) to decrypt it.
//! - WgConfig implements ZeroizeOnDrop: private_key and preshared_key are
//!   overwritten with zeros when the struct is dropped, minimising the window
//!   during which key material lives in process memory.
//! - DPAPI binds the ciphertext to the current Windows logon session; a
//!   different user (or the same user on a different machine) cannot decrypt it.

use crate::crypto;
use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Parsed, in-memory WireGuard configuration.
///
/// `ZeroizeOnDrop` ensures that when this struct is dropped (end of scope),
/// all String fields — including the private key — are overwritten with zeros
/// before the allocator reclaims the memory.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WgConfig {
    pub private_key: String,
    pub address: String,
    pub dns: Option<String>,
    pub peer_public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub allowed_ips: String,
    pub persistent_keepalive: Option<u16>,
}

const REG_KEY_PATH: &str = r"Software\SWGC\Config";
const REG_VALUE_NAME: &str = "EncryptedBlob";

/// Encrypt `config` with DPAPI (using `entropy`) and write the blob to the
/// Windows Registry.
///
/// `entropy` must be derived from the user's passphrase via
/// `crypto::derive_entropy`.  It is never stored — only the opaque DPAPI
/// ciphertext is written to the registry.
///
/// After this function returns, the caller's `WgConfig` should be dropped
/// (or will be zeroed automatically when it goes out of scope via `ZeroizeOnDrop`).
pub fn save_encrypted(config: &WgConfig, entropy: &[u8; 32]) -> Result<()> {
    // Serialise to JSON bytes — plaintext lives in `json` on the heap.
    let mut json = serde_json::to_vec(config)?;

    // Encrypt with DPAPI; `json` bytes are consumed as input.
    let blob = crypto::encrypt(&json, entropy)?;

    // Zeroize the plaintext JSON bytes immediately after encryption.
    json.zeroize();

    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, REG_BINARY};
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(REG_KEY_PATH)
            .map_err(|e| AppError::Config(format!("レジストリキー作成失敗: {e}")))?;

        key.set_raw_value(
            REG_VALUE_NAME,
            &winreg::RegValue {
                bytes: blob,
                vtype: REG_BINARY,
            },
        )
        .map_err(|e| AppError::Config(format!("レジストリ書き込み失敗: {e}")))?;
    }

    #[cfg(not(windows))]
    let _ = blob;

    Ok(())
}

/// Read the encrypted blob from the registry, decrypt it using `entropy`, and
/// return a `WgConfig`.
///
/// Returns `None` if no config has been imported yet.
/// Returns `Err` if decryption fails — most commonly because `entropy` was
/// derived from the wrong passphrase.
///
/// The returned `WgConfig` is `ZeroizeOnDrop` — the caller must not hold it
/// longer than necessary.
pub fn load_decrypted(entropy: &[u8; 32]) -> Result<Option<WgConfig>> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = match hkcu.open_subkey(REG_KEY_PATH) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        };

        let raw: winreg::RegValue = match key.get_raw_value(REG_VALUE_NAME) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        // Decrypt in Rust memory — plaintext never written to disk.
        let mut plaintext = crypto::decrypt(&raw.bytes, entropy)?;

        let config: WgConfig = serde_json::from_slice(&plaintext)
            .map_err(|e| AppError::Config(format!("設定の復号後パースに失敗: {e}")))?;

        // Zeroize the intermediate plaintext bytes immediately after parsing.
        plaintext.zeroize();

        return Ok(Some(config));
    }

    #[cfg(not(windows))]
    Ok(None)
}

/// Returns `true` if an encrypted config blob exists in the registry.
///
/// This check does NOT require the passphrase — it only verifies that the
/// registry key and value are present, not that the stored blob is decryptable.
pub fn has_config() -> bool {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(key) = hkcu.open_subkey(REG_KEY_PATH) {
            return key.get_raw_value(REG_VALUE_NAME).is_ok();
        }
        false
    }

    #[cfg(not(windows))]
    false
}

/// Delete the stored config from the registry.
///
/// Removes the encrypted blob — the WireGuard keys can no longer be recovered
/// by this application. Called when the user resets / reimports.
pub fn delete_config() -> Result<()> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = match hkcu.open_subkey_with_flags(
            REG_KEY_PATH,
            winreg::enums::KEY_SET_VALUE,
        ) {
            Ok(k) => k,
            Err(_) => return Ok(()), // nothing to delete
        };

        match key.delete_value(REG_VALUE_NAME) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(AppError::Config(format!("設定の削除失敗: {e}"))),
        }
    }

    Ok(())
}

/// Parse a WireGuard `.conf` file into a `WgConfig`.
///
/// Called once at import time. The caller is responsible for zeroizing the
/// source `content` string after this function returns.
pub fn parse_conf(content: &str) -> Result<WgConfig> {
    let mut private_key = String::new();
    let mut address = String::new();
    let mut dns = None;
    let mut peer_public_key = String::new();
    let mut preshared_key = None;
    let mut endpoint = String::new();
    let mut allowed_ips = String::new();
    let mut persistent_keepalive = None;
    let mut in_peer = false;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_peer = line.eq_ignore_ascii_case("[Peer]");
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        if in_peer {
            match key {
                "PublicKey" => peer_public_key = value.to_string(),
                "PresharedKey" if !value.is_empty() => preshared_key = Some(value.to_string()),
                "Endpoint" => endpoint = value.to_string(),
                "AllowedIPs" => allowed_ips = value.to_string(),
                "PersistentKeepalive" => persistent_keepalive = value.parse().ok(),
                _ => {}
            }
        } else {
            match key {
                "PrivateKey" => private_key = value.to_string(),
                "Address" => address = value.to_string(),
                "DNS" => dns = Some(value.to_string()),
                _ => {}
            }
        }
    }

    if private_key.is_empty() {
        return Err(AppError::Config("PrivateKey が見つかりません".into()));
    }
    if peer_public_key.is_empty() {
        return Err(AppError::Config("Peer PublicKey が見つかりません".into()));
    }
    if endpoint.is_empty() {
        return Err(AppError::Config("Endpoint が見つかりません".into()));
    }

    Ok(WgConfig {
        private_key,
        address,
        dns,
        peer_public_key,
        preshared_key,
        endpoint,
        allowed_ips,
        persistent_keepalive,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_conf() -> &'static str {
        "[Interface]\n\
         PrivateKey = qKIj8jMKLmn3OpQrStUvWxYzABCDEFGHIJKLMNOPQRS=\n\
         Address = 10.0.0.2/32\n\
         DNS = 1.1.1.1\n\
         \n\
         [Peer]\n\
         PublicKey = abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG=\n\
         PresharedKey = 0123456789abcdefghijklmnopqrstuvwxyzABCDEFG=\n\
         Endpoint = vpn.example.com:51820\n\
         AllowedIPs = 0.0.0.0/0\n\
         PersistentKeepalive = 25\n"
    }

    #[test]
    fn parse_conf_ok() {
        let cfg = parse_conf(sample_conf()).unwrap();
        assert_eq!(cfg.private_key, "qKIj8jMKLmn3OpQrStUvWxYzABCDEFGHIJKLMNOPQRS=");
        assert_eq!(cfg.address, "10.0.0.2/32");
        assert_eq!(cfg.dns, Some("1.1.1.1".into()));
        assert_eq!(cfg.endpoint, "vpn.example.com:51820");
        assert_eq!(cfg.persistent_keepalive, Some(25));
    }

    #[test]
    fn parse_conf_missing_private_key() {
        let bad = "[Interface]\nAddress = 10.0.0.1/32\n\n[Peer]\nPublicKey = abc=\nEndpoint = x:51820\n";
        let err = parse_conf(bad).unwrap_err().to_string();
        assert!(err.contains("PrivateKey"), "expected PrivateKey error, got: {err}");
    }

    #[test]
    fn parse_conf_missing_endpoint() {
        let bad = "[Interface]\nPrivateKey = abc=\n\n[Peer]\nPublicKey = def=\n";
        let err = parse_conf(bad).unwrap_err().to_string();
        assert!(err.contains("Endpoint"), "expected Endpoint error, got: {err}");
    }

    /// DPAPI round-trip: encrypt → registry → decrypt should return the original config.
    /// This test contacts the Windows registry and DPAPI — it runs only on Windows.
    #[test]
    #[cfg(windows)]
    fn registry_roundtrip() {
        let cfg = parse_conf(sample_conf()).unwrap();
        let original_key = cfg.private_key.clone();
        let original_endpoint = cfg.endpoint.clone();

        let entropy = crate::crypto::derive_entropy("registry-test-passphrase");

        // Save encrypted
        save_encrypted(&cfg, &entropy).expect("save_encrypted failed");

        // Load and decrypt
        let loaded = load_decrypted(&entropy)
            .expect("load_decrypted returned Err")
            .expect("load_decrypted returned None");

        assert_eq!(loaded.private_key, original_key);
        assert_eq!(loaded.endpoint, original_endpoint);
        assert_eq!(loaded.persistent_keepalive, Some(25));

        // Wrong passphrase must fail
        let bad_entropy = crate::crypto::derive_entropy("wrong-passphrase");
        assert!(
            load_decrypted(&bad_entropy).is_err(),
            "wrong passphrase must not decrypt"
        );

        // Clean up
        delete_config().expect("delete_config failed");
        assert!(!has_config(), "config should be gone after delete");
    }
}
