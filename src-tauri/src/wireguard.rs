//! WireGuard tunnel management via wireguard-nt.
//!
//! # Architecture
//!
//! wireguard-nt exposes a kernel-mode WireGuard adapter as a Windows network
//! interface. This module:
//!   1. Loads `wireguard.dll` at runtime with `libloading`.
//!   2. Calls `WireGuardCreateAdapter` to instantiate a virtual NIC.
//!   3. Builds a `WIREGUARD_INTERFACE` + `WIREGUARD_PEER` struct entirely in
//!      **process memory** — no config file is written to disk.
//!   4. Passes the struct to `WireGuardSetConfiguration` which hands it to the
//!      kernel driver.
//!   5. Brings the adapter UP and configures IP address / routing.
//!   6. On disconnect: tears down routing, sets adapter DOWN, closes handle.
//!
//! # Security
//!
//! The private key travels from the DPAPI blob → Rust heap → kernel driver and
//! is never written to disk in plaintext. The `WIREGUARD_INTERFACE` buffer is
//! stack/heap-allocated in Rust and zeroized after the driver call.

use crate::config::WgConfig;
use crate::error::{AppError, Result};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

// ── State ─────────────────────────────────────────────────────────────────

/// Wrapper around the raw wireguard-nt adapter handle (`*mut c_void`).
///
/// # Module-level safety invariant
///
/// **Every** read or write of the inner pointer must occur while `TUNNEL`
/// (the module-level `Mutex<Option<TunnelState>>`) is held.  All functions
/// in this module that access the adapter handle acquire the lock, use the
/// handle, and release the lock before returning.  The Rust compiler cannot
/// verify this invariant mechanically — it is upheld by code convention and
/// must be checked during code review.
///
/// # Why `unsafe impl Send`?
///
/// Raw pointers are `!Send` by default because the compiler cannot prove they
/// are safe to transfer across thread boundaries.  `AdapterHandle` is `Send`
/// because the invariant above guarantees that only one thread ever accesses
/// the handle at a time (the Mutex serialises all access), making concurrent
/// use impossible in practice even though the Windows kernel handle itself is
/// not intrinsically thread-safe.
struct AdapterHandle(*mut std::ffi::c_void);

// SAFETY: exclusive access is enforced by the TUNNEL Mutex; see AdapterHandle doc.
unsafe impl Send for AdapterHandle {}

impl AdapterHandle {
    /// Return the raw handle pointer for passing to WireGuard FFI functions.
    ///
    /// # Precondition
    ///
    /// The caller MUST hold the `TUNNEL` lock (i.e., call this only from within
    /// a `TUNNEL.lock()` guard scope).
    fn raw(&self) -> *mut std::ffi::c_void {
        self.0
    }
}

struct TunnelState {
    adapter: AdapterHandle,
    /// libloading Library — must be kept alive while adapter handle is live.
    _lib: libloading::Library,
    #[allow(dead_code)]
    interface_name: String,
    /// Peer endpoint string (e.g. "1.2.3.4:51820") stored for `get_peer_endpoint()`.
    /// Exposed via IPC so the frontend can display it without needing DPAPI access.
    peer_endpoint: String,
    /// Signal for the background monitor thread to stop (set true on disconnect).
    monitor_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
// No manual `unsafe impl Send for TunnelState` needed.
// All fields implement Send:
//   AdapterHandle  — unsafe impl Send (see above; invariant enforced by TUNNEL Mutex)
//   libloading::Library — Send + Sync (libloading guarantees this)
//   String         — Send + Sync
//   Arc<AtomicBool>— Send + Sync

static TUNNEL: Mutex<Option<TunnelState>> = Mutex::new(None);

// ── Entropy cache for auto-reconnect ──────────────────────────────────────

/// PBKDF2-derived entropy cached after a successful `connect()` call.
/// The monitor thread reads this to decrypt the stored config when
/// auto-reconnecting — without requiring the user to re-enter a passphrase.
/// Cleared only when the user deletes the stored config.
static CACHED_ENTROPY: Mutex<Option<Zeroizing<[u8; 32]>>> = Mutex::new(None);

/// Store `entropy` in the process-wide cache.  Called by `connect()`.
pub fn set_cached_entropy(entropy: Zeroizing<[u8; 32]>) {
    *CACHED_ENTROPY.lock().unwrap() = Some(entropy);
}

/// Clear the cached entropy.  Called by `delete_config` command so the
/// monitor thread cannot reconnect after the config has been erased.
pub fn clear_cached_entropy() {
    *CACHED_ENTROPY.lock().unwrap() = None;
}

/// Return a copy of the cached entropy, or `None` if not yet set.
fn get_cached_entropy() -> Option<Zeroizing<[u8; 32]>> {
    let guard = CACHED_ENTROPY.lock().unwrap();
    guard.as_ref().map(|e| Zeroizing::new(**e))
}

// ── Background keepalive monitor ──────────────────────────────────────────

/// Convert current system time to Windows FILETIME (100-ns intervals since 1601-01-01).
fn now_as_filetime() -> u64 {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let unix_100ns = dur.as_secs() * 10_000_000
        + dur.subsec_nanos() as u64 / 100;
    // Offset between 1601-01-01 and 1970-01-01 in 100-ns intervals.
    unix_100ns + 116_444_736_000_000_000
}

/// Spawned by `connect()`; monitors the tunnel every 30 s and auto-reconnects
/// when the session goes stale.  Exits only when `stop` is set (user disconnect).
///
/// Uses `diag_log` / `diag_log_fmt` directly because this function is defined
/// before the `diag!` macro.
fn monitor_thread(stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::Ordering;

    // ── State ────────────────────────────────────────────────────────────
    let mut prev_tx:   u64 = 0;
    let mut prev_hs:   u64 = 0;
    let mut count:     u32 = 0;
    // How many consecutive 30-second ticks have had no handshake at all.
    let mut no_hs_ticks: u32 = 0;
    // Exponential backoff between reconnect attempts: 30 → 60 → 120 (s).
    let mut backoff_secs: u64 = 30;
    let mut reconnect_attempts: u32 = 0;

    // ── Helper: sleep N seconds, returning early if stop is set ──────────
    let interruptible_sleep = |secs: u64, stop: &std::sync::Arc<std::sync::atomic::AtomicBool>| {
        for _ in 0..secs {
            if stop.load(Ordering::Relaxed) { return true; } // stopped
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        stop.load(Ordering::Relaxed) // check one final time
    };

    loop {
        // ── Wait one cycle ───────────────────────────────────────────────
        if interruptible_sleep(30, &stop) {
            diag_log("[monitor] ユーザー切断 — スレッド終了");
            return;
        }

        count += 1;

        // ── Poll stats ───────────────────────────────────────────────────
        let stats = match get_tunnel_stats() {
            Ok(Some(s)) => s,
            Ok(None) => {
                // TUNNEL is empty; disconnect() sets stop before clearing TUNNEL,
                // but check anyway so we don't spin.
                if stop.load(Ordering::Relaxed) {
                    diag_log("[monitor] ユーザー切断 — スレッド終了");
                    return;
                }
                diag_log(&format!("[monitor #{count}] TUNNEL が空です (予期しない状態)"));
                // Treat as stale and fall through to reconnect logic below.
                // Create a fake "no handshake" stats value.
                crate::wireguard::TunnelStats { tx_bytes: prev_tx, rx_bytes: 0, last_handshake: 0 }
            }
            Err(e) => {
                diag_log(&format!("[monitor #{count}] get_tunnel_stats エラー: {e}"));
                continue;
            }
        };

        // ── Log stats ────────────────────────────────────────────────────
        let tx_delta  = stats.tx_bytes.wrapping_sub(prev_tx);
        let hs_changed = stats.last_handshake != prev_hs && stats.last_handshake != 0;
        let hs_age_sec: i64 = if stats.last_handshake > 0 {
            ((now_as_filetime().saturating_sub(stats.last_handshake)) / 10_000_000) as i64
        } else {
            -1
        };
        diag_log(&format!(
            "[monitor #{count}] Tx+{tx_delta}B HS_age={hs_age_sec}s{}",
            if hs_changed { " ★再ハンドシェイク!" } else { "" }
        ));

        // ── Determine if reconnect is needed ─────────────────────────────
        let needs_reconnect = if stats.last_handshake == 0 {
            // No handshake yet — wait up to 90 seconds (3 ticks) before giving up.
            no_hs_ticks += 1;
            if no_hs_ticks >= 3 {
                diag_log(&format!(
                    "[monitor #{count}] 初期ハンドシェイクが90秒以内に確立されませんでした — 再接続します"
                ));
                true
            } else {
                false
            }
        } else {
            no_hs_ticks = 0;
            if hs_age_sec > 330 {
                // Session has been dead for >5.5 minutes (REKEY_AFTER_TIME + REJECT_AFTER_TIME).
                diag_log(&format!(
                    "[monitor #{count}] ⚠ セッション期限切れ ({hs_age_sec}秒) — 自動再接続します"
                ));
                true
            } else {
                // Session is healthy: reset backoff.
                if reconnect_attempts > 0 {
                    diag_log(&format!("[monitor #{count}] セッション回復 — バックオフをリセット"));
                }
                reconnect_attempts = 0;
                backoff_secs = 30;
                false
            }
        };

        prev_tx = stats.tx_bytes;
        prev_hs = stats.last_handshake;

        if !needs_reconnect {
            continue;
        }

        // ── Reconnect ────────────────────────────────────────────────────
        // Double-check stop flag before trying to reconnect.
        if stop.load(Ordering::Relaxed) {
            diag_log("[monitor] ユーザー切断 — 再接続をスキップ");
            return;
        }

        reconnect_attempts += 1;
        diag_log(&format!(
            "[monitor] 自動再接続を試みます (試行 #{reconnect_attempts}, バックオフ={backoff_secs}s)"
        ));

        // Retrieve the cached entropy (derived from the user's passphrase at
        // connect time) so we can decrypt the stored config without prompting.
        let entropy = match get_cached_entropy() {
            Some(e) => e,
            None => {
                diag_log(&format!(
                    "[monitor #{count}] キャッシュされたエントロピーがありません — 再接続できません"
                ));
                if interruptible_sleep(backoff_secs, &stop) { return; }
                continue;
            }
        };

        // Load the stored config via DPAPI using the cached entropy.
        let cfg = match crate::config::load_decrypted(&entropy) {
            Ok(Some(c)) => c,
            Ok(None) => {
                diag_log("[monitor] 設定が見つかりません — 再接続できません");
                if interruptible_sleep(backoff_secs, &stop) { return; }
                continue;
            }
            Err(e) => {
                diag_log(&format!("[monitor] 設定の読み込みに失敗しました: {e}"));
                if interruptible_sleep(backoff_secs, &stop) { return; }
                continue;
            }
        };

        match reconnect_for_monitor(&cfg, stop.clone()) {
            Ok(()) => {
                diag_log(&format!("[monitor] 自動再接続成功 (試行 #{reconnect_attempts})"));
                // Reset tracking state for the new session.
                prev_tx = 0;
                prev_hs = 0;
                no_hs_ticks = 0;
                // Keep reconnect_attempts / backoff so they reset only on healthy session.
            }
            Err(e) => {
                diag_log(&format!(
                    "[monitor] 自動再接続失敗 (試行 #{reconnect_attempts}): {e}"
                ));
                // Exponential backoff, capped at 120 seconds.
                backoff_secs = (backoff_secs * 2).min(120);
                if interruptible_sleep(backoff_secs, &stop) { return; }
            }
        }
    }
}

// ── DLL discovery ─────────────────────────────────────────────────────────

/// Candidate paths for `wireguard.dll`, tried in order.
///
/// The system DLL (`C:\Program Files\WireGuard\wireguard.dll`) is tried first
/// because it is version-matched with the installed `wireguard.sys` kernel
/// driver. Using our bundled wireguard-nt 1.0 DLL against a different driver
/// version causes `WireGuardSetConfiguration` to return ERROR_INVALID_PARAMETER.
fn dll_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    // 1. WireGuard for Windows system installation (version-matched with wireguard.sys)
    paths.push(r"C:\Program Files\WireGuard\wireguard.dll".into());

    // 2. Next to the executable (bundled distribution / fallback)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("wireguard.dll"));
        }
    }

    // 3. System32 / SysWOW64
    paths.push(r"C:\Windows\System32\wireguard.dll".into());

    paths
}

/// Verify that the DLL at `path` carries a valid Authenticode signature.
///
/// Uses `WinVerifyTrust` (wintrust.dll) to confirm:
/// 1. The file content matches the embedded signature (tamper detection).
/// 2. The code-signing certificate chains to a Windows-trusted root CA.
///
/// Revocation checks are skipped (`WTD_REVOKE_NONE`) so the app functions
/// offline.  This accepts potentially revoked certificates, which is an
/// acceptable trade-off for a bundled utility DLL on a device that has
/// already passed Windows Update and driver signing enforcement.
///
/// Why this matters: even though SWGC requires admin to run, the DLL next to
/// the executable can be in a user-writable location (e.g. the user runs the
/// app directly from their Downloads folder before installing it).  An
/// attacker with user-level access could plant a malicious unsigned DLL there.
/// Authenticode verification catches that case.
#[cfg(windows)]
fn verify_dll_signature(path: &std::path::Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::shared::guiddef::GUID;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::wintrust::{
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WinVerifyTrust,
    };

    // {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}  WINTRUST_ACTION_GENERIC_VERIFY_V2
    let mut action_guid = GUID {
        Data1: 0x00AAC56B,
        Data2: 0xCD44,
        Data3: 0x11D0,
        Data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    // Build a NUL-terminated UTF-16 path for the Win32 API.
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as DWORD,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    // SAFETY: zeroed() is valid for a C struct that will be immediately
    // populated before passing to a Win32 API.
    let mut trust_data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    trust_data.cbStruct          = std::mem::size_of::<WINTRUST_DATA>() as DWORD;
    trust_data.dwUIChoice        = WTD_UI_NONE;      // no dialogs
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE; // offline-safe
    trust_data.dwUnionChoice     = WTD_CHOICE_FILE;
    trust_data.dwStateAction     = WTD_STATEACTION_VERIFY;
    // SAFETY: union field — we set dwUnionChoice = WTD_CHOICE_FILE above.
    unsafe { *trust_data.u.pFile_mut() = &mut file_info as *mut _; }

    // With WTD_UI_NONE the HWND is ignored; null is documented as equivalent
    // to INVALID_HANDLE_VALUE when no UI is displayed.
    let hwnd = std::ptr::null_mut();

    let status = unsafe {
        WinVerifyTrust(hwnd, &mut action_guid, &mut trust_data as *mut _ as *mut _)
    };

    // Always release internal WinVerifyTrust state even if verification failed.
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(hwnd, &mut action_guid, &mut trust_data as *mut _ as *mut _);
    }

    if status == 0 {
        // ERROR_SUCCESS: signature is present, valid, and trusted.
        diag_log(&format!("  DLL署名検証OK: {}", path.display()));
        Ok(())
    } else {
        // Common non-zero HRESULT values:
        //   0x800B0100 TRUST_E_NOSIGNATURE       — 署名なし
        //   0x800B0101 TRUST_E_BADDIGEST          — ファイルが改ざんされている
        //   0x800B010A TRUST_E_SUBJECT_NOT_TRUSTED — 信頼されていない署名者
        //   0x800B0109 CERT_E_UNTRUSTEDROOT        — ルートCAが信頼されていない
        Err(AppError::WireGuard(format!(
            "wireguard.dll の署名検証に失敗しました (HRESULT=0x{:08X}): {:?}\n\
             未署名または改ざんされた DLL は読み込まれません。\
             公式の WireGuard または wireguard-nt のバイナリをご使用ください。",
            status as u32,
            path
        )))
    }
}

/// Load `wireguard.dll` from the first path that exists and passes
/// Authenticode signature verification.
/// Returns (Library, path_used).
unsafe fn load_dll() -> Result<(libloading::Library, std::path::PathBuf)> {
    for path in dll_paths() {
        if !path.exists() {
            continue;
        }

        // Verify Authenticode signature before mapping the DLL into process
        // memory.  This catches unsigned or tampered replacements even when
        // the DLL is placed in a nominally trusted directory.
        #[cfg(windows)]
        verify_dll_signature(&path)?;

        let lib = libloading::Library::new(&path)
            .map_err(|e| AppError::WireGuard(format!("DLLロード失敗 ({path:?}): {e}")))?;
        return Ok((lib, path));
    }
    Err(AppError::WireGuard(
        "wireguard.dll が見つかりません。アプリと同じフォルダに配置してください。".into(),
    ))
}

// ── Diagnostic logger ─────────────────────────────────────────────────────

/// Write a diagnostic line to stderr AND to %TEMP%\swgc_debug.log.
fn diag_log(msg: &str) {
    eprintln!("[SWGC] {msg}");
    let log_path = std::env::temp_dir().join("swgc_debug.log");
    let line = format!("{} {msg}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0));
    use std::io::Write;
    let _ = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(&log_path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
}

macro_rules! diag {
    ($($arg:tt)*) => { diag_log(&format!($($arg)*)) };
}

// ── Key decoding ──────────────────────────────────────────────────────────

/// Decode a WireGuard key from standard Base64 (RFC 4648) and return the
/// 32-byte raw key material.  Uses the `base64` crate rather than a hand-
/// rolled decoder to avoid subtle correctness issues.
fn decode_key(b64: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| AppError::WireGuard(format!("鍵のBase64デコード失敗: {e}")))?;
    if bytes.len() != 32 {
        return Err(AppError::WireGuard(format!(
            "鍵長が不正: {} bytes (期待: 32)",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

// ── Endpoint parsing ──────────────────────────────────────────────────────

use crate::wg_nt::*;

/// Parse "host:port" into a `SOCKADDR_INET`.
/// Performs DNS resolution if necessary.
fn parse_endpoint(endpoint: &str) -> Result<SOCKADDR_INET> {
    use std::net::{SocketAddr, ToSocketAddrs};

    // If the host part is a hostname (not a numeric IP), DNS resolution will be
    // used.  Warn about the security implications:
    //
    // - DNS spoofing / poisoned resolver / local hosts-file overrides can redirect
    //   the connection to a wrong server.
    // - WireGuard's public-key authentication prevents impersonation: a spoofed
    //   endpoint lacks the peer's private key, so the handshake will fail and no
    //   traffic will flow through the attacker's machine.
    // - However, the client's IP address IS disclosed to whichever server it
    //   connects to before the handshake fails.
    //
    // Recommendation: use a numeric IP address in the Endpoint field of .conf.
    if let Some(host) = endpoint.split(':').next() {
        if host.parse::<std::net::IpAddr>().is_err() {
            diag!(
                "  ⚠ エンドポイント {:?} はIPアドレスではなくホスト名です。DNS解決を行います。\
                セキュリティのため .conf の Endpoint には固定IPアドレスの使用を推奨します。\
                (DNS詐称が発生しても WireGuard の公開鍵認証により接続先の詐称は防がれますが、\
                接続失敗やクライアントIPの開示が起きる可能性があります)",
                host
            );
        }
    }

    let addrs: Vec<SocketAddr> = endpoint
        .to_socket_addrs()
        .map_err(|e| AppError::WireGuard(format!("エンドポイント解決失敗 ({endpoint}): {e}")))?
        .collect();

    let addr = addrs
        .into_iter()
        .find(|a| a.is_ipv4() || a.is_ipv6())
        .ok_or_else(|| AppError::WireGuard(format!("エンドポイントが解決できません: {endpoint}")))?;

    Ok(sockaddr_from_std(addr))
}

fn sockaddr_from_std(addr: std::net::SocketAddr) -> SOCKADDR_INET {
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let port = v4.port().to_be();
            let ip   = u32::from(*v4.ip()).to_be();
            unsafe {
                let mut s = std::mem::zeroed::<SOCKADDR_INET>();
                s.Ipv4.sin_family      = 2; // AF_INET
                s.Ipv4.sin_port        = port;
                s.Ipv4.sin_addr.S_addr = ip;
                s
            }
        }
        std::net::SocketAddr::V6(v6) => {
            let port = v6.port().to_be();
            unsafe {
                let mut s = std::mem::zeroed::<SOCKADDR_INET>();
                s.Ipv6.sin6_family    = 23; // AF_INET6
                s.Ipv6.sin6_port      = port;
                s.Ipv6.sin6_addr.Byte = v6.ip().octets();
                s
            }
        }
    }
}

// ── Allowed-IP parsing ────────────────────────────────────────────────────

/// Parse a comma-separated list of CIDR strings into `WIREGUARD_ALLOWED_IP` entries.
fn parse_allowed_ips(s: &str) -> Result<Vec<WIREGUARD_ALLOWED_IP>> {
    let mut result = Vec::new();
    for cidr in s.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        result.push(parse_one_cidr(cidr)?);
    }
    Ok(result)
}

fn parse_one_cidr(cidr: &str) -> Result<WIREGUARD_ALLOWED_IP> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| AppError::WireGuard(format!("不正な AllowedIPs エントリ: {cidr}")))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| AppError::WireGuard(format!("プレフィックス長が不正: {prefix_str}")))?;

    let mut aip: WIREGUARD_ALLOWED_IP = unsafe { std::mem::zeroed() };

    if let Ok(v4) = addr_str.parse::<std::net::Ipv4Addr>() {
        aip.AddressFamily = 2; // AF_INET
        aip.Cidr = prefix;
        // Write only the raw 4-byte IPv4 address into the union.
        // WG_IP_ADDR has no family/port field — AddressFamily is a separate field.
        aip.Address.V4.S_addr = u32::from(v4).to_be();
    } else if let Ok(v6) = addr_str.parse::<std::net::Ipv6Addr>() {
        aip.AddressFamily = 23; // AF_INET6
        aip.Cidr = prefix;
        aip.Address.V6.Byte = v6.octets();
    } else {
        return Err(AppError::WireGuard(format!("IPアドレスのパース失敗: {addr_str}")));
    }

    Ok(aip)
}

// ── Wide-string helper ────────────────────────────────────────────────────

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ── connect (internal) ───────────────────────────────────────────────────

/// Internal tunnel setup shared by user-initiated `connect()` and the monitor
/// thread's auto-reconnect.  Does **not** spawn a monitor thread.
///
/// * `monitor_stop` — the `AtomicBool` used to signal the monitor thread.
///   The *same* Arc is reused across reconnects so `disconnect()` can always
///   stop the (continuously running) monitor thread.
/// * `is_reconnect` — when `true`, the log file is appended to (not truncated)
///   and the header line says "自動再接続" instead of "connect()".
fn connect_with_stop(
    config: &WgConfig,
    monitor_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    is_reconnect: bool,
) -> Result<()> {
    // ── Start diagnostic log ─────────────────────────────────────────────
    let log_path = std::env::temp_dir().join("swgc_debug.log");
    if !is_reconnect {
        // Fresh connect: truncate the log so each session starts clean.
        let _ = std::fs::write(&log_path, "");
        diag!("=== SWGC connect() start ===");
    } else {
        diag!("=== SWGC 自動再接続 ===");
    }
    diag!("log file: {}", log_path.display());
    diag!("struct sizes: WIREGUARD_INTERFACE={} WIREGUARD_PEER={} WIREGUARD_ALLOWED_IP={}",
        std::mem::size_of::<WIREGUARD_INTERFACE>(),
        std::mem::size_of::<WIREGUARD_PEER>(),
        std::mem::size_of::<WIREGUARD_ALLOWED_IP>());

    let mut guard = TUNNEL.lock().unwrap();
    if guard.is_some() {
        return Err(AppError::WireGuard("既に接続中です".into()));
    }

    // ── Compile-time size assertions ─────────────────────────────────────
    // ALIGNED(8) on WIREGUARD_INTERFACE rounds 76 → 80 bytes.
    // ALIGNED(8) on WIREGUARD_PEER    rounds 132 → 136 bytes (u64 alignment).
    const _: () = assert!(std::mem::size_of::<WIREGUARD_INTERFACE>()  ==  80);
    const _: () = assert!(std::mem::size_of::<WIREGUARD_PEER>()       == 136);
    const _: () = assert!(std::mem::size_of::<WIREGUARD_ALLOWED_IP>() ==  24);

    // ── 1. Decode keys ───────────────────────────────────────────────────
    diag!("step 1: decoding keys");
    // Wrap decoded key material in Zeroizing<> so the heap/stack bytes are
    // automatically zeroed when the variable goes out of scope — including on
    // panic.  Explicit .zeroize() calls later are kept for "belt-and-suspenders"
    // early zeroing as soon as the material is no longer needed.
    let mut private_key = Zeroizing::new(
        decode_key(&config.private_key)
            .map_err(|e| { diag!("  PrivateKey decode error: {e}"); e })?
    );
    diag!("  PrivateKey decoded OK");

    let peer_pub = decode_key(&config.peer_public_key)
        .map_err(|e| { diag!("  PeerPublicKey decode error: {e}"); e })?;
    diag!("  PeerPublicKey decoded OK");

    let has_psk = config.preshared_key.is_some();
    let psk = Zeroizing::new(if let Some(ref k) = config.preshared_key {
        let r = decode_key(k).map_err(|e| { diag!("  PSK decode error: {e}"); e })?;
        diag!("  PSK decoded OK");
        r
    } else {
        diag!("  no PSK");
        [0u8; 32]
    });

    let endpoint = parse_endpoint(&config.endpoint)
        .map_err(|e| { diag!("  endpoint parse error: {e}"); e })?;
    diag!("  endpoint={} parsed OK", config.endpoint);

    let allowed_ips = parse_allowed_ips(&config.allowed_ips)
        .map_err(|e| { diag!("  allowed_ips parse error: {e}"); e })?;
    diag!("  allowed_ips count={}", allowed_ips.len());
    for (i, aip) in allowed_ips.iter().enumerate() {
        let af = aip.AddressFamily;
        diag!("    [{}] af={} cidr={}", i, af, aip.Cidr);
    }

    let keepalive: u16 = config.persistent_keepalive.unwrap_or(0);
    diag!("  keepalive={keepalive}");

    // ── 2. Load DLL ──────────────────────────────────────────────────────
    diag!("step 2: loading DLL");
    let (lib, dll_path) = unsafe { load_dll()? };
    diag!("  DLL loaded from: {}", dll_path.display());

    macro_rules! load_fn {
        ($name:literal, $ty:ty) => {
            unsafe {
                lib.get::<$ty>($name)
                   .map_err(|e| AppError::WireGuard(
                       format!("{} ロード失敗: {e}", stringify!($name))
                   ))?
            }
        };
    }

    let fn_get_ver    = load_fn!(b"WireGuardGetRunningDriverVersion\0",
                                 FnWireGuardGetRunningDriverVersion);
    let fn_del_driver = load_fn!(b"WireGuardDeleteDriver\0",
                                 FnWireGuardDeleteDriver);
    let fn_create     = load_fn!(b"WireGuardCreateAdapter\0",
                                 FnWireGuardCreateAdapter);
    let fn_set_cfg    = load_fn!(b"WireGuardSetConfiguration\0",
                                 FnWireGuardSetConfiguration);
    let fn_set_state  = load_fn!(b"WireGuardSetAdapterState\0",
                                 FnWireGuardSetAdapterState);
    let fn_close      = load_fn!(b"WireGuardCloseAdapter\0",
                                 FnWireGuardCloseAdapter);
    let fn_get_luid   = load_fn!(b"WireGuardGetAdapterLUID\0",
                                 FnWireGuardGetAdapterLUID);
    diag!("  all DLL symbols loaded OK");

    // Query driver version before adapter creation (informational only).
    // Version 0 simply means the driver is not yet loaded — that is normal.
    // WireGuardCreateAdapter loads (or installs) the driver automatically.
    // We intentionally do NOT call WireGuardDeleteDriver here: doing so
    // removes any installed wireguard.sys and forces a re-install, which can
    // disrupt a running official WireGuard client and cause our own handshake
    // to fail due to driver/service restart timing.
    let pre_ver = unsafe { fn_get_ver() };
    diag!("  pre-CreateAdapter driver version raw=0x{pre_ver:08x}");
    // fn_del_driver is loaded but intentionally unused — kept for potential
    // future use (e.g. a forced clean-up command).
    let _ = fn_del_driver;

    // ── 3. Build configuration buffer ────────────────────────────────────
    diag!("step 3: building config buffer");
    let iface_size = std::mem::size_of::<WIREGUARD_INTERFACE>();
    let peer_size  = std::mem::size_of::<WIREGUARD_PEER>();
    let aip_size   = std::mem::size_of::<WIREGUARD_ALLOWED_IP>();
    let total      = iface_size + peer_size + aip_size * allowed_ips.len();
    diag!("  buffer layout: iface={iface_size} + peer={peer_size} + aip={aip_size}×{} = {total}",
        allowed_ips.len());

    let mut iface: WIREGUARD_INTERFACE = unsafe { std::mem::zeroed() };
    iface.Flags      = WIREGUARD_INTERFACE_FLAG_HAS_PRIVATE_KEY
                     | WIREGUARD_INTERFACE_FLAG_REPLACE_PEERS;
    // Deref Zeroizing<[u8;32]> to copy the key bytes into the C struct.
    iface.PrivateKey = *private_key;
    iface.PeersCount = 1;
    diag!("  iface.Flags=0x{:08x} PeersCount={}", iface.Flags, iface.PeersCount);

    let mut peer: WIREGUARD_PEER = unsafe { std::mem::zeroed() };
    peer.Flags = WIREGUARD_PEER_FLAG_HAS_PUBLIC_KEY
               | WIREGUARD_PEER_FLAG_HAS_ENDPOINT
               | WIREGUARD_PEER_FLAG_REPLACE_ALLOWED_IPS;
    peer.PublicKey       = peer_pub;
    peer.Endpoint        = endpoint;
    peer.AllowedIPsCount = allowed_ips.len() as DWORD;

    if has_psk {
        peer.Flags |= WIREGUARD_PEER_FLAG_HAS_PRESHARED_KEY;
        peer.PresharedKey = *psk;
    }
    if keepalive > 0 {
        peer.Flags |= WIREGUARD_PEER_FLAG_HAS_PERSISTENT_KEEPALIVE;
        peer.PersistentKeepalive = keepalive;
    }
    diag!("  peer.Flags=0x{:08x} AllowedIPsCount={} Keepalive={}",
        peer.Flags, peer.AllowedIPsCount, peer.PersistentKeepalive);

    // Use Zeroizing<Vec<u8>> so the buffer — which contains the private key
    // and PSK in the first (iface_size + peer_size) bytes — is guaranteed to be
    // zeroed even if a panic unwinds the stack before the explicit zeroize calls.
    let mut buf = Zeroizing::new(vec![0u8; total]);
    unsafe {
        std::ptr::copy_nonoverlapping(
            &iface as *const WIREGUARD_INTERFACE as *const u8,
            buf.as_mut_ptr(), iface_size);
        std::ptr::copy_nonoverlapping(
            &peer as *const WIREGUARD_PEER as *const u8,
            buf.as_mut_ptr().add(iface_size), peer_size);
        for (i, aip) in allowed_ips.iter().enumerate() {
            std::ptr::copy_nonoverlapping(
                aip as *const WIREGUARD_ALLOWED_IP as *const u8,
                buf.as_mut_ptr().add(iface_size + peer_size + i * aip_size),
                aip_size);
        }
    }

    // Zero key material from the stack-allocated C structs immediately after
    // copying to buf.  This narrows the window during which key bytes live in
    // multiple locations simultaneously (iface, peer, and buf).
    iface.PrivateKey.zeroize();
    peer.PresharedKey.zeroize();

    // ── 4. Create adapter ────────────────────────────────────────────────
    diag!("step 4: WireGuardCreateAdapter(\"SWGC\")");
    let adapter_name = to_wide_null("SWGC");
    let tunnel_type  = to_wide_null("WireGuard");

    let adapter: HANDLE = unsafe {
        fn_create(adapter_name.as_ptr(), tunnel_type.as_ptr(), std::ptr::null())
    };
    let create_err = std::io::Error::last_os_error();

    if adapter.is_null() {
        diag!("  CreateAdapter FAILED: {create_err}");
        private_key.zeroize();
        buf.zeroize();
        return Err(AppError::WireGuard(format!("WireGuardCreateAdapter 失敗: {create_err}")));
    }
    diag!("  CreateAdapter OK, handle={adapter:?}");
    // Query driver version NOW (after adapter creation) for accurate version.
    let post_ver = unsafe { fn_get_ver() };
    diag!("  post-CreateAdapter driver version raw=0x{post_ver:08x} ({}.{}.{}.{})",
        post_ver >> 24, (post_ver >> 16) & 0xFF,
        (post_ver >>  8) & 0xFF, post_ver & 0xFF);
    if post_ver == 0 {
        diag!("  WARNING: driver still version 0 after CreateAdapter — IOCTL mismatch likely");
    }

    // ── Resolve actual interface index via LUID ───────────────────────────
    // Windows may rename the adapter (e.g. "SWGC 10") if "SWGC" was already
    // taken from a prior session.  Using the interface INDEX is always correct
    // regardless of the friendly name Windows assigned.
    let iface_index: u32 = unsafe {
        // Get the NET_LUID from the adapter handle.
        let mut luid: u64 = 0;
        fn_get_luid(adapter, &mut luid);
        diag!("  adapter LUID = 0x{luid:016x}");

        // iphlpapi!ConvertInterfaceLuidToIndex → interface index (1-based).
        type FnConvertLuidToIndex = unsafe extern "system" fn(
            luid:  *const u64,
            index: *mut u32,
        ) -> u32;
        match libloading::Library::new("iphlpapi.dll") {
            Err(e) => {
                diag!("  iphlpapi.dll ロード失敗: {e} → 名前フォールバック使用");
                0  // will fall back to name-based netsh
            }
            Ok(iphlp) => {
                match iphlp.get::<FnConvertLuidToIndex>(b"ConvertInterfaceLuidToIndex\0") {
                    Err(e) => {
                        diag!("  ConvertInterfaceLuidToIndex ロード失敗: {e} → 名前フォールバック使用");
                        0
                    }
                    Ok(convert) => {
                        let mut idx: u32 = 0;
                        let ret = convert(&luid, &mut idx);
                        diag!("  ConvertInterfaceLuidToIndex: ret={ret} index={idx}");
                        if ret == 0 { idx } else { 0 }
                    }
                }
            }
        }
    };
    // Build the netsh interface identifier: prefer numeric index, fall back to name.
    let iface_id = if iface_index > 0 {
        iface_index.to_string()
    } else {
        "SWGC".to_string()
    };
    diag!("  netsh will use interface identifier: \"{iface_id}\"");

    // ── 5. Set configuration ─────────────────────────────────────────────
    diag!("step 5: WireGuardSetConfiguration (total={total} bytes)");
    let set_cfg_ok: BOOL = unsafe {
        fn_set_cfg(adapter, buf.as_ptr() as *const _, buf.len() as DWORD)
    };
    // Capture IMMEDIATELY before any other Windows API.
    let set_cfg_err = std::io::Error::last_os_error();
    diag!("  SetConfiguration returned {set_cfg_ok}, last_os_error={set_cfg_err}");

    // Zeroize sensitive key material.
    private_key.zeroize();
    buf.zeroize();

    if set_cfg_ok == 0 {
        unsafe { fn_close(adapter); }
        let msg = format!(
            "WireGuardSetConfiguration 失敗 (buf={total}B, iface={iface_size}, peer={peer_size}, aip={aip_size}×{}): {set_cfg_err}",
            allowed_ips.len());
        diag!("  ERROR: {msg}");
        diag!("  ログファイル: {}", log_path.display());
        return Err(AppError::WireGuard(msg));
    }

    // ── 6. Bring adapter UP ──────────────────────────────────────────────
    diag!("step 6: WireGuardSetAdapterState(UP)");
    let set_state_ok: BOOL = unsafe { fn_set_state(adapter, WIREGUARD_ADAPTER_STATE_UP) };
    let state_err = std::io::Error::last_os_error();
    diag!("  SetAdapterState returned {set_state_ok}, last_os_error={state_err}");

    if set_state_ok == 0 {
        unsafe { fn_close(adapter); }
        return Err(AppError::WireGuard(format!("WireGuardSetAdapterState(UP) 失敗: {state_err}")));
    }

    // ── 7. Configure interface address ───────────────────────────────────
    diag!("step 7: netsh interface address / routing");
    if !config.address.is_empty() {
        let (ip, prefix) = config.address
            .split_once('/')
            .unwrap_or((&config.address, "32"));
        let result = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "set", "address",
                   &iface_id, "static", ip, &prefix_to_mask(prefix)])
            .output();
        match result {
            Ok(out) => {
                diag!("  netsh address: exit={} stdout={} stderr={}",
                    out.status,
                    String::from_utf8_lossy(&out.stdout).trim(),
                    String::from_utf8_lossy(&out.stderr).trim());
            }
            Err(e) => diag!("  netsh 実行失敗: {e}"),
        }
    }

    // ── 8. Add routes for all AllowedIPs ─────────────────────────────────
    diag!("step 8: adding routes for allowed IPs");
    for cidr in config.allowed_ips.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let r = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "add", "route",
                   cidr, &iface_id, "store=active"])
            .output();
        match &r {
            Ok(out) => diag!("  netsh add route {cidr}: exit={} out={} err={}",
                out.status,
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()),
            Err(e) => diag!("  netsh add route {cidr} 失敗: {e}"),
        }
    }

    // ── 9. Configure DNS servers from .conf DNS = line ───────────────────
    // Set the VPN-provided DNS server(s) on the WireGuard interface so that
    // DNS queries from this device are resolved via the VPN tunnel.
    //
    // Note: this does NOT affect endpoint hostname resolution during connect /
    // auto-reconnect — those happen before the tunnel is established and
    // therefore use the system (pre-VPN) DNS.  Setting DNS here ensures that
    // traffic *through* the tunnel uses the correct resolver.
    diag!("step 9: configuring DNS");
    if let Some(ref dns_str) = config.dns {
        let dns_servers: Vec<&str> = dns_str
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        for (idx, dns_ip) in dns_servers.iter().enumerate() {
            // Determine address family to pick the right netsh sub-command.
            let af = if dns_ip.parse::<std::net::Ipv6Addr>().is_ok() {
                "ipv6"
            } else {
                "ipv4"
            };

            let args: Vec<&str> = if idx == 0 {
                // Primary DNS: use "set dnsservers … static … primary validate=no"
                vec!["interface", af, "set", "dnsservers",
                     &iface_id, "static", dns_ip, "primary", "validate=no"]
            } else {
                // Secondary / tertiary: use "add dnsservers … validate=no"
                vec!["interface", af, "add", "dnsservers",
                     &iface_id, dns_ip, "validate=no"]
            };

            let result = std::process::Command::new("netsh").args(&args).output();
            match result {
                Ok(out) => diag!(
                    "  netsh DNS[{idx}] {dns_ip} ({af}): exit={} out={} err={}",
                    out.status,
                    String::from_utf8_lossy(&out.stdout).trim(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
                Err(e) => diag!("  netsh DNS[{idx}] {dns_ip} 失敗: {e}"),
            }
        }
    } else {
        diag!("  .conf に DNS 行なし — スキップ");
    }

    // ── 10. Readback: verify driver stored the configuration ──────────────
    diag!("step 9: WireGuardGetConfiguration readback");
    unsafe {
        if let Ok(fn_get_cfg) = lib.get::<FnWireGuardGetConfiguration>(
            b"WireGuardGetConfiguration\0") {
            let mut sz: DWORD = 0;
            fn_get_cfg(adapter, std::ptr::null_mut(), &mut sz);
            diag!("  GetConfiguration size query: sz={sz}");
            if sz > 0 {
                let mut rb = vec![0u8; sz as usize];
                let mut sz2 = sz;
                let ok = fn_get_cfg(adapter, rb.as_mut_ptr() as *mut _, &mut sz2);
                diag!("  GetConfiguration: ok={ok} sz2={sz2}");
                if ok != 0 && sz2 as usize >= 80 {
                    let iface_flags = u32::from_le_bytes([rb[0],rb[1],rb[2],rb[3]]);
                    let peers_count = u32::from_le_bytes([rb[72],rb[73],rb[74],rb[75]]);
                    // HAS_PUBLIC_KEY=0x01 means driver accepted the private key and derived public key.
                    // If this bit is 0, the driver has no private key → no handshakes possible.
                    let has_pubkey = (iface_flags & WIREGUARD_INTERFACE_FLAG_HAS_PUBLIC_KEY) != 0;
                    let has_port   = (iface_flags & WIREGUARD_INTERFACE_FLAG_HAS_LISTEN_PORT) != 0;
                    diag!("  readback iface: Flags=0x{iface_flags:08x} PeersCount={peers_count} \
                        HAS_PUBLIC_KEY={has_pubkey} HAS_LISTEN_PORT={has_port}");
                    if sz2 as usize >= 80 + 136 {
                        let p = &rb[80..];
                        let peer_flags = u32::from_le_bytes([p[0],p[1],p[2],p[3]]);
                        let pk0 = p[8];
                        let ka  = u16::from_le_bytes([p[72],p[73]]);
                        let ep_fam  = u16::from_le_bytes([p[76],p[77]]);
                        let ep_port = u16::from_be_bytes([p[78],p[79]]);
                        let ep_ip   = &p[80..84];
                        // TxBytes @ offset 104, RxBytes @ 112, LastHandshake @ 120, AIPCount @ 128
                        let tx = u64::from_le_bytes(p[104..112].try_into().unwrap_or([0;8]));
                        let rx = u64::from_le_bytes(p[112..120].try_into().unwrap_or([0;8]));
                        let hs = u64::from_le_bytes(p[120..128].try_into().unwrap_or([0;8]));
                        let aip_count = u32::from_le_bytes([p[128],p[129],p[130],p[131]]);
                        diag!("  readback peer: Flags=0x{peer_flags:08x} PK[0]={pk0:02x} KA={ka}");
                        diag!("  readback peer: EP family={ep_fam} port={ep_port} ip={}.{}.{}.{}",
                            ep_ip[0], ep_ip[1], ep_ip[2], ep_ip[3]);
                        diag!("  readback peer: Tx={tx} Rx={rx} LastHS={hs} AIPs={aip_count}");
                    }
                }
            }
        }
    }

    // ── 11. Save state ────────────────────────────────────────────────────
    // The monitor_stop Arc is provided by the caller (connect() or reconnect_for_monitor).
    // We intentionally do NOT spawn a new monitor thread here — the caller handles that.
    *guard = Some(TunnelState {
        adapter: AdapterHandle(adapter),
        _lib: lib,
        interface_name: "SWGC".into(),
        peer_endpoint: config.endpoint.clone(),
        monitor_stop,
    });

    diag!("=== connect_with_stop() SUCCESS, tunnel UP ===");
    Ok(())
}

// ── connect (public) ──────────────────────────────────────────────────────

/// Bring up a WireGuard tunnel.
///
/// `entropy` must be the PBKDF2-derived value from the user's passphrase
/// (via `crypto::derive_entropy`).  It is cached in process memory so the
/// background monitor thread can auto-reconnect without re-prompting.
///
/// Call order: cache entropy → call `connect_with_stop` → spawn monitor thread.
pub fn connect(config: &WgConfig, entropy: Zeroizing<[u8; 32]>) -> Result<()> {
    // Cache entropy BEFORE connect_with_stop so the monitor thread has it
    // available immediately even if the first connect succeeds and a
    // reconnect is triggered soon after.
    set_cached_entropy(entropy);

    let monitor_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    connect_with_stop(config, monitor_stop.clone(), false)?;

    let stop_clone = monitor_stop;
    std::thread::Builder::new()
        .name("swgc-monitor".into())
        .spawn(move || monitor_thread(stop_clone))
        .ok(); // spawn failure is non-fatal

    Ok(())
}

/// Returns the peer endpoint string stored when the tunnel was last brought up,
/// or `None` if no tunnel is currently active.
///
/// Used by `get_status` so the frontend can display the endpoint without
/// requiring DPAPI access (no passphrase needed).
pub fn get_peer_endpoint() -> Option<String> {
    TUNNEL.lock().unwrap()
        .as_ref()
        .map(|s| s.peer_endpoint.clone())
}

// ── reconnect (called from monitor thread) ────────────────────────────────

/// Close the current (stale) adapter and reconnect using the *same* stop Arc.
/// Called from `monitor_thread` — must NOT set `monitor_stop = true`.
///
/// Uses `diag_log` directly because this function is defined before `diag!`.
fn reconnect_for_monitor(
    config: &crate::config::WgConfig,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    diag_log("=== [monitor] 旧アダプターを閉じて再接続します ===");

    // ── 1. Close old adapter WITHOUT signalling stop ──────────────────────
    {
        let mut guard = TUNNEL.lock().unwrap();
        if let Some(old) = guard.take() {
            // NOTE: do NOT call old.monitor_stop.store(true) — that IS `stop`.
            unsafe {
                if let Ok(f) = old._lib.get::<FnWireGuardSetAdapterState>(
                    b"WireGuardSetAdapterState\0")
                {
                    f(old.adapter.raw(), WIREGUARD_ADAPTER_STATE_DOWN);
                }
                if let Ok(f) = old._lib.get::<FnWireGuardCloseAdapter>(
                    b"WireGuardCloseAdapter\0")
                {
                    f(old.adapter.raw());
                }
            }
            // old._lib dropped here (DLL ref-count decremented)
        }
    } // TUNNEL lock released

    // ── 2. Re-establish tunnel with the same stop Arc ─────────────────────
    connect_with_stop(config, stop, true) // is_reconnect = true
}

// ── disconnect ────────────────────────────────────────────────────────────

/// Tear down the WireGuard tunnel.
pub fn disconnect() -> Result<()> {
    let mut guard = TUNNEL.lock().unwrap();
    let state = guard.take().ok_or_else(|| AppError::WireGuard("接続していません".into()))?;

    // Stop the background monitor thread.
    state.monitor_stop.store(true, std::sync::atomic::Ordering::Relaxed);

    // Remove routing (best-effort; Windows removes interface routes automatically
    // when the adapter is closed, so errors here are non-fatal)
    let _ = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "delete", "route", "0.0.0.0/0", "SWGC"])
        .output();

    // Bring adapter DOWN then close
    unsafe {
        if let Ok(set_state) = state._lib.get::<FnWireGuardSetAdapterState>(
            b"WireGuardSetAdapterState\0",
        ) {
            set_state(state.adapter.raw(), WIREGUARD_ADAPTER_STATE_DOWN);
        }
        if let Ok(close) = state._lib.get::<FnWireGuardCloseAdapter>(
            b"WireGuardCloseAdapter\0",
        ) {
            close(state.adapter.raw());
        }
    }

    log::info!("WireGuard tunnel DOWN");
    Ok(())
}

/// Returns true if the tunnel is currently up.
pub fn is_connected() -> bool {
    TUNNEL.lock().unwrap().is_some()
}

// ── Tunnel statistics ─────────────────────────────────────────────────────

/// Per-peer statistics read back from the WireGuard kernel driver.
#[derive(serde::Serialize, Debug, Clone)]
pub struct TunnelStats {
    /// Bytes sent through the tunnel.
    pub tx_bytes: u64,
    /// Bytes received through the tunnel.
    pub rx_bytes: u64,
    /// Windows FILETIME of last successful handshake
    /// (100-ns intervals since 1601-01-01 UTC). `0` = no handshake yet.
    pub last_handshake: u64,
}

/// Read per-peer statistics from the running WireGuard driver via
/// `WireGuardGetConfiguration`. Returns `None` if no tunnel is active.
pub fn get_tunnel_stats() -> Result<Option<TunnelStats>> {
    let guard = TUNNEL.lock().unwrap();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => return Ok(None),
    };

    unsafe {
        let fn_get_cfg = state
            ._lib
            .get::<FnWireGuardGetConfiguration>(b"WireGuardGetConfiguration\0")
            .map_err(|e| {
                AppError::WireGuard(format!("WireGuardGetConfiguration ロード失敗: {e}"))
            })?;

        // ── First call: query required buffer size ────────────────────────
        // Pass Bytes = 0 → driver returns FALSE + ERROR_MORE_DATA and sets
        // *Bytes to the number of bytes needed.
        let mut bytes: DWORD = 0;
        fn_get_cfg(state.adapter.raw(), std::ptr::null_mut(), &mut bytes);
        // Ignore return value (always FALSE here); bytes now holds required size.

        if bytes == 0 {
            // Driver returned nothing — adapter may be in an unexpected state.
            return Ok(None);
        }

        // ── Second call: get the actual configuration ─────────────────────
        let mut buf: Vec<u8> = vec![0u8; bytes as usize];
        let mut bytes2 = bytes;
        let ok = fn_get_cfg(state.adapter.raw(), buf.as_mut_ptr() as *mut _, &mut bytes2);
        if ok == 0 {
            let e = std::io::Error::last_os_error();
            return Err(AppError::WireGuard(format!(
                "WireGuardGetConfiguration 失敗: {e}"
            )));
        }

        // ── Parse: WIREGUARD_INTERFACE (80 B) followed by WIREGUARD_PEER ──
        let iface_size = std::mem::size_of::<WIREGUARD_INTERFACE>();
        let peer_size = std::mem::size_of::<WIREGUARD_PEER>();
        if buf.len() < iface_size + peer_size {
            // No peer data in the response (PeersCount == 0).
            return Ok(None);
        }

        // Use read_unaligned because the buffer is a Vec<u8> (align 1) but
        // WIREGUARD_PEER requires align 8.
        let peer: WIREGUARD_PEER = std::ptr::read_unaligned(
            buf.as_ptr().add(iface_size) as *const WIREGUARD_PEER,
        );

        Ok(Some(TunnelStats {
            tx_bytes: peer.TxBytes,
            rx_bytes: peer.RxBytes,
            last_handshake: peer.LastHandshake,
        }))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Convert a CIDR prefix length to a dotted-decimal subnet mask string.
fn prefix_to_mask(prefix: &str) -> String {
    let n: u32 = prefix.parse().unwrap_or(32);
    if n == 0 {
        return "0.0.0.0".into();
    }
    let mask = !((1u32 << (32 - n)) - 1);
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >>  8) & 0xFF,
        mask & 0xFF
    )
}
