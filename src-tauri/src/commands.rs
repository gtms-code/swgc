//! Tauri IPC command handlers.
//!
//! # Security invariants enforced here
//!
//! - The user's passphrase is accepted only as a transient parameter.  It is
//!   immediately used to derive PBKDF2 entropy (`crypto::derive_entropy`), then
//!   zeroized in memory before any further work.  The derived entropy itself is
//!   `Zeroizing<[u8; 32]>` and is either used directly and dropped, or cached
//!   in `wireguard::CACHED_ENTROPY` for auto-reconnect.
//! - Sensitive data (`WgConfig`) is decrypted on-demand and dropped immediately
//!   after use. `WgConfig` is `ZeroizeOnDrop`, so the private key is overwritten
//!   with zeros when the struct goes out of scope.
//! - The plaintext content of the imported `.conf` file is zeroized immediately
//!   after parsing — before the function returns.
//! - No key material is ever returned to the TypeScript frontend.

use crate::config::{self, WgConfig};
use crate::error::AppError;
use crate::wireguard;
use serde::Serialize;
use std::fs;
use tauri::command;
use zeroize::Zeroize;

#[derive(Serialize)]
pub struct StatusResponse {
    pub has_config: bool,
    pub is_connected: bool,
    /// Only the endpoint string is exposed — no key material.
    pub peer_endpoint: Option<String>,
}

/// Returns current connection status. Safe to poll frequently; never exposes keys.
///
/// The peer endpoint is read directly from the in-memory `TunnelState` so no
/// passphrase is required.
#[command]
pub async fn get_status() -> Result<StatusResponse, AppError> {
    let has_config = config::has_config();
    let is_connected = wireguard::is_connected();

    let peer_endpoint = if is_connected {
        wireguard::get_peer_endpoint()
    } else {
        None
    };

    Ok(StatusResponse {
        has_config,
        is_connected,
        peer_endpoint,
    })
}

/// Import a WireGuard `.conf` file: read → parse → derive entropy → encrypt → persist.
///
/// The passphrase is used to derive PBKDF2 entropy and is zeroized immediately
/// after derivation.  The plaintext file content and the parsed `WgConfig`
/// (including the private key) are both zeroized before this function returns.
/// Nothing sensitive is returned to the frontend.
#[command]
pub async fn import_config(file_path: String, mut passphrase: String) -> Result<(), AppError> {
    // Reject suspiciously large files before reading them into memory.
    // A valid WireGuard .conf file is never larger than a few hundred bytes.
    const MAX_CONF_BYTES: u64 = 65_536; // 64 KiB
    let meta = fs::metadata(&file_path)
        .map_err(|e| AppError::Config(format!("ファイル情報取得エラー: {e}")))?;
    if meta.len() > MAX_CONF_BYTES {
        return Err(AppError::Config(format!(
            "ファイルが大きすぎます ({} bytes)。WireGuard設定ファイルは通常数百バイト以下です。",
            meta.len()
        )));
    }

    // Read the .conf file. `content` is a heap-allocated String containing
    // the plaintext private key.
    let mut content = fs::read_to_string(&file_path)
        .map_err(|e| AppError::Config(format!("ファイル読み込みエラー: {e}")))?;

    // Parse into WgConfig. On error, `content` is still zeroized below.
    let wg_config: WgConfig = match config::parse_conf(&content) {
        Ok(c) => c,
        Err(e) => {
            content.zeroize(); // zeroize even on parse failure
            passphrase.zeroize();
            return Err(e);
        }
    };

    // Zeroize the source file content immediately — the private key is now
    // only inside `wg_config` on the Rust heap.
    content.zeroize();

    // Derive PBKDF2 entropy from the passphrase, then zeroize the passphrase.
    let entropy = crate::crypto::derive_entropy(&passphrase);
    passphrase.zeroize();

    // Encrypt and persist. `wg_config` is ZeroizeOnDrop: its private_key
    // field is overwritten when this function returns.
    config::save_encrypted(&wg_config, &entropy)?;

    // `wg_config` and `entropy` are dropped and zeroed here.
    Ok(())
}

/// Decrypt the stored config (in memory only) and bring up the WireGuard tunnel.
///
/// The passphrase is used to derive PBKDF2 entropy, which is then used to
/// decrypt the stored config via DPAPI.  If decryption fails (wrong passphrase),
/// a user-friendly error is returned.  The passphrase is zeroized before any
/// I/O and the `WgConfig` is zeroized immediately after the driver call.
///
/// The derived entropy is cached in process memory for auto-reconnect.
#[command]
pub async fn connect(mut passphrase: String) -> Result<(), AppError> {
    let entropy = crate::crypto::derive_entropy(&passphrase);
    passphrase.zeroize();

    let wg_config: WgConfig = match config::load_decrypted(&entropy) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err(AppError::Config("設定がインポートされていません".into()))
        }
        Err(_) => {
            return Err(AppError::Config(
                "パスフレーズが正しくありません。\
                 正しいパスフレーズを入力するか、設定を再インポートしてください。"
                    .into(),
            ))
        }
    };

    // `entropy` is moved into connect() and cached for auto-reconnect.
    wireguard::connect(&wg_config, entropy)?;

    // `wg_config` (private_key zeroed) is dropped here.
    Ok(())
}

/// Tear down the WireGuard tunnel.
#[command]
pub async fn disconnect() -> Result<(), AppError> {
    wireguard::disconnect()
}

/// Read live WireGuard peer statistics from the kernel driver.
///
/// Returns TX/RX bytes and the time of the last successful handshake.
/// Call this periodically while connected to detect handshake failures.
#[command]
pub async fn tunnel_stats() -> Result<Option<wireguard::TunnelStats>, AppError> {
    wireguard::get_tunnel_stats()
}

/// Disconnect then immediately reconnect — useful when the WireGuard session
/// becomes stale (e.g. re-handshake failure after long idle).
///
/// Requires the passphrase to re-derive entropy and decrypt the stored config.
#[command]
pub async fn force_reconnect(mut passphrase: String) -> Result<(), AppError> {
    let entropy = crate::crypto::derive_entropy(&passphrase);
    passphrase.zeroize();

    let wg_config: WgConfig = match config::load_decrypted(&entropy) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err(AppError::Config("設定がインポートされていません".into()))
        }
        Err(_) => {
            return Err(AppError::Config(
                "パスフレーズが正しくありません。\
                 正しいパスフレーズを入力するか、設定を再インポートしてください。"
                    .into(),
            ))
        }
    };

    // Disconnect silently if connected (ignore "not connected" error).
    let _ = wireguard::disconnect();

    // Re-caches the entropy for subsequent auto-reconnects.
    wireguard::connect(&wg_config, entropy)?;
    Ok(())
}

/// Remove the encrypted config from the registry and clear the cached entropy.
///
/// After this call, `has_config()` returns `false` and the tunnel keys can no
/// longer be recovered by this application. The user must re-import.
#[command]
pub async fn delete_config() -> Result<(), AppError> {
    if wireguard::is_connected() {
        return Err(AppError::Config(
            "接続中は設定を削除できません。先に切断してください。".into(),
        ));
    }
    // Clear cached entropy so the monitor thread cannot attempt reconnection
    // after the config blob has been removed.
    wireguard::clear_cached_entropy();
    config::delete_config()
}
