//! Tauri IPC command handlers.
//!
//! # Security invariants enforced here
//!
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
#[command]
pub async fn get_status() -> Result<StatusResponse, AppError> {
    let has_config = config::has_config();
    let is_connected = wireguard::is_connected();

    let peer_endpoint = if is_connected && has_config {
        config::load_decrypted()
            .ok()
            .flatten()
            .map(|c| c.endpoint.clone())
        // WgConfig is dropped and zeroed here (ZeroizeOnDrop)
    } else {
        None
    };

    Ok(StatusResponse {
        has_config,
        is_connected,
        peer_endpoint,
    })
}

/// Import a WireGuard `.conf` file: read → parse → encrypt → persist → discard.
///
/// The plaintext file content and the parsed `WgConfig` (including the private key)
/// are both zeroized before this function returns. Nothing sensitive is returned
/// to the frontend.
#[command]
pub async fn import_config(file_path: String) -> Result<(), AppError> {
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
            return Err(e);
        }
    };

    // Zeroize the source file content immediately — the private key is now
    // only inside `wg_config` on the Rust heap.
    content.zeroize();

    // Encrypt and persist. `wg_config` is ZeroizeOnDrop: its private_key
    // field is overwritten when this function returns.
    config::save_encrypted(&wg_config)?;

    // `wg_config` is dropped and zeroed here.
    Ok(())
}

/// Decrypt the stored config (in memory only) and bring up the WireGuard tunnel.
///
/// The `WgConfig` is decrypted, used to configure the driver, then immediately
/// dropped and zeroed — it does not persist in memory after this call.
#[command]
pub async fn connect() -> Result<(), AppError> {
    let wg_config: WgConfig = config::load_decrypted()?
        .ok_or_else(|| AppError::Config("設定がインポートされていません".into()))?;

    wireguard::connect(&wg_config)?;

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
#[command]
pub async fn force_reconnect() -> Result<(), AppError> {
    let wg_config: WgConfig = config::load_decrypted()?
        .ok_or_else(|| AppError::Config("設定がインポートされていません".into()))?;

    // Disconnect silently if connected (ignore "not connected" error).
    let _ = wireguard::disconnect();

    wireguard::connect(&wg_config)?;
    Ok(())
}

/// Remove the encrypted config from the registry.
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
    config::delete_config()
}
