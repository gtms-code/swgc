//! wireguard-nt FFI bindings.
//!
//! This module provides safe Rust wrappers around the C API exposed by
//! `wireguard.dll` (wireguard-nt 1.0). The DLL must be present at:
//!   - `<exe_dir>/wireguard.dll`  (bundled distribution), or
//!   - `C:\Program Files\WireGuard\wireguard.dll`  (system installation)
//!
//! All structs mirror the layout defined in `wireguard.h` exactly.
//! Fields are little-endian on x86-64; the kernel driver enforces this.
//!
//! Reference: https://git.zx2c4.com/wireguard-nt/about/

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;

// ── Basic integer aliases ─────────────────────────────────────────────────

pub type BOOL   = i32;
pub type DWORD  = u32;
pub type WORD   = u16;
pub type BYTE   = u8;
pub type HANDLE = *mut c_void;

// ── Key / address sizes ───────────────────────────────────────────────────

pub const WIREGUARD_KEY_LENGTH: usize = 32;

/// Raw 32-byte WireGuard key (private, public, or pre-shared).
pub type WgKey = [u8; WIREGUARD_KEY_LENGTH];

// ── Adapter state ─────────────────────────────────────────────────────────

pub const WIREGUARD_ADAPTER_STATE_DOWN: DWORD = 0;
pub const WIREGUARD_ADAPTER_STATE_UP:   DWORD = 1;

// ── Allowed-IP flags ──────────────────────────────────────────────────────

pub const WIREGUARD_ALLOWED_IP_FLAG_NONE: DWORD = 0;

// ── Peer flags ────────────────────────────────────────────────────────────

pub const WIREGUARD_PEER_FLAG_HAS_PUBLIC_KEY:       DWORD = 1 << 0;
pub const WIREGUARD_PEER_FLAG_HAS_PRESHARED_KEY:    DWORD = 1 << 1;
pub const WIREGUARD_PEER_FLAG_HAS_PERSISTENT_KEEPALIVE: DWORD = 1 << 2;
pub const WIREGUARD_PEER_FLAG_HAS_ENDPOINT:         DWORD = 1 << 3;
pub const WIREGUARD_PEER_FLAG_REPLACE_ALLOWED_IPS:  DWORD = 1 << 5;

// ── Interface flags ───────────────────────────────────────────────────────
// Values from wireguard.h (wireguard-nt):
//   WIREGUARD_INTERFACE_FLAG_HAS_PUBLIC_KEY  = 0x00000001  (set in GET readback when private key is loaded)
//   WIREGUARD_INTERFACE_FLAG_HAS_PRIVATE_KEY = 0x00000002  (set in SET call to tell driver to accept private key)
//   WIREGUARD_INTERFACE_FLAG_HAS_LISTEN_PORT = 0x00000004
//   WIREGUARD_INTERFACE_FLAG_REPLACE_PEERS   = 0x00000008

pub const WIREGUARD_INTERFACE_FLAG_HAS_PUBLIC_KEY:  DWORD = 1 << 0; // 0x01
pub const WIREGUARD_INTERFACE_FLAG_HAS_PRIVATE_KEY: DWORD = 1 << 1; // 0x02
pub const WIREGUARD_INTERFACE_FLAG_HAS_LISTEN_PORT: DWORD = 1 << 2; // 0x04
pub const WIREGUARD_INTERFACE_FLAG_REPLACE_PEERS:   DWORD = 1 << 3; // 0x08

// ── sockaddr_in / sockaddr_in6 (Windows layout) ───────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN_ADDR {
    pub S_addr: u32,  // network byte order
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN6_ADDR {
    pub Byte: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR_IN {
    pub sin_family: WORD,      // AF_INET = 2
    pub sin_port:   WORD,      // network byte order
    pub sin_addr:   IN_ADDR,
    pub sin_zero:   [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR_IN6 {
    pub sin6_family:   WORD,   // AF_INET6 = 23
    pub sin6_port:     WORD,
    pub sin6_flowinfo: u32,
    pub sin6_addr:     IN6_ADDR,
    pub sin6_scope_id: u32,
}

/// Tagged union — same memory as sockaddr_in / sockaddr_in6.
#[repr(C)]
#[derive(Clone, Copy)]
pub union SOCKADDR_INET {
    pub Ipv4: SOCKADDR_IN,
    pub Ipv6: SOCKADDR_IN6,
    pub si_family: WORD,
}

// ── WIREGUARD_ALLOWED_IP ──────────────────────────────────────────────────

/// Raw IP address union for `WIREGUARD_ALLOWED_IP`.
///
/// This is NOT a sockaddr — there is no address-family or port wrapper here.
/// The C header defines this as `union { IN_ADDR V4; IN6_ADDR V6; }`.
/// Total size: 16 bytes (max of 4 and 16), alignment: 4 (from V4).
#[repr(C)]
#[derive(Clone, Copy)]
pub union WG_IP_ADDR {
    pub V4: IN_ADDR,   // AF_INET  — 4 bytes
    pub V6: IN6_ADDR,  // AF_INET6 — 16 bytes
}

/// Mirrors `_WIREGUARD_ALLOWED_IP` from wireguard.h exactly.
/// Size = 16 + 2 + 1 + 5 = 24 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WIREGUARD_ALLOWED_IP {
    pub Address:       WG_IP_ADDR,  // 16 bytes — raw IP, not a sockaddr
    pub AddressFamily: WORD,        // AF_INET=2 or AF_INET6=23
    pub Cidr:          BYTE,
    pub _padding:      [u8; 5],
}

// ── WIREGUARD_PEER ────────────────────────────────────────────────────────

/// Mirrors `struct ALIGNED(8) _WIREGUARD_PEER` from wireguard.h (wireguard-nt 1.0).
///
/// The C struct has NO `Reserved1` field and NO field-level `__declspec(align(8))`
/// on `Endpoint`.  The `ALIGNED(8)` annotation is on the *struct itself*.
///
/// Layout (MSVC / Rust #[repr(C, align(8))]):
///   Flags(4) Reserved(4) PublicKey(32) PresharedKey(32)
///   PersistentKeepalive(2) [pad 2] Endpoint(28)
///   TxBytes(8) RxBytes(8) LastHandshake(8) AllowedIPsCount(4)
///   [4 trailing pad] = **136 bytes** (alignment 8).
///
/// Field offsets:
///   Flags=0   Reserved=4   PublicKey=8   PresharedKey=40
///   PersistentKeepalive=72   [implicit pad 2 bytes]   Endpoint=76
///   TxBytes=104   RxBytes=112   LastHandshake=120   AllowedIPsCount=128
///   sizeof=136
///
/// Note: `_reserved1` below is the explicit representation of the 2 bytes of
/// implicit padding that C inserts between PersistentKeepalive (align 2) and
/// Endpoint (align 4, offset must be ≡ 0 mod 4; 74%4=2 → pad 2).
/// Having it as an explicit WORD field gives the same binary layout.
#[repr(C, align(8))]
pub struct WIREGUARD_PEER {
    pub Flags:               DWORD,          // 4   offset 0
    pub Reserved:            DWORD,          // 4   offset 4
    pub PublicKey:           WgKey,          // 32  offset 8
    pub PresharedKey:        WgKey,          // 32  offset 40
    pub PersistentKeepalive: WORD,           // 2   offset 72
    pub _reserved1:          WORD,           // 2   offset 74  (implicit pad in C)
    pub Endpoint:            SOCKADDR_INET,  // 28  offset 76
    pub TxBytes:             u64,            // 8   offset 104
    pub RxBytes:             u64,            // 8   offset 112
    pub LastHandshake:       u64,            // 8   offset 120
    pub AllowedIPsCount:     DWORD,          // 4   offset 128
    // 4 bytes trailing padding (ALIGNED(8)) → sizeof = 136
    // Followed in memory by AllowedIPsCount × WIREGUARD_ALLOWED_IP
}

// ── WIREGUARD_INTERFACE ───────────────────────────────────────────────────

/// Mirrors `struct ALIGNED(8) _WIREGUARD_INTERFACE` from wireguard.h.
///
/// `ALIGNED(8)` = `__declspec(align(8))` on the *struct itself* rounds sizeof
/// up to the next multiple of 8.  Natural size is 76 bytes; with ALIGNED(8)
/// sizeof = **80 bytes** (4 bytes of trailing padding appended).
///
/// Field layout:
///   Flags(4) ListenPort(2) PrivateKey(32) PublicKey(32) [pad 2] PeersCount(4) [pad 4]
///   offsets:  0             4              6              38       70             72      76
///   sizeof = 80, alignment = 8.
///
/// The trailing 4 bytes (offsets 76-79) are implicit padding added by
/// `ALIGNED(8)`; they do NOT correspond to any named field.  The DLL computes
/// the address of the first WIREGUARD_PEER as `Config + sizeof(WIREGUARD_INTERFACE)`
/// = `Config + 80`, so every byte of that padding must be present in the buffer.
#[repr(C, align(8))]
pub struct WIREGUARD_INTERFACE {
    pub Flags:      DWORD,   // 4   offset 0
    pub ListenPort: WORD,    // 2   offset 4
    // NO explicit padding — PrivateKey ([u8;32], align 1) sits at offset 6
    pub PrivateKey: WgKey,   // 32  offset 6
    pub PublicKey:  WgKey,   // 32  offset 38  (read-only; driver fills this)
    // 2 bytes implicit padding at offset 70 (DWORD alignment for PeersCount)
    pub PeersCount: DWORD,   // 4   offset 72
    // 4 bytes implicit trailing padding (ALIGNED(8)) at offsets 76-79
    // sizeof = 80, align = 8
    // Followed in memory by PeersCount × (WIREGUARD_PEER + allowed-IPs)
}

// ── DLL function pointer types ────────────────────────────────────────────

pub type FnWireGuardCreateAdapter = unsafe extern "system" fn(
    Name:       *const u16,  // MAX_ADAPTER_NAME = 128 wchars
    TunnelType: *const u16,
    RequestedGUID: *const winapi::shared::guiddef::GUID,
) -> HANDLE;

pub type FnWireGuardOpenAdapter = unsafe extern "system" fn(
    Name: *const u16,
) -> HANDLE;

pub type FnWireGuardCloseAdapter = unsafe extern "system" fn(
    Adapter: HANDLE,
);

pub type FnWireGuardSetConfiguration = unsafe extern "system" fn(
    Adapter: HANDLE,
    Config:  *const c_void,
    Bytes:   DWORD,
) -> BOOL;

pub type FnWireGuardSetAdapterState = unsafe extern "system" fn(
    Adapter: HANDLE,
    State:   DWORD,
) -> BOOL;

pub type FnWireGuardGetRunningDriverVersion = unsafe extern "system" fn() -> DWORD;

pub type FnWireGuardDeleteDriver = unsafe extern "system" fn() -> BOOL;

pub type FnWireGuardGetAdapter = unsafe extern "system" fn(
    Name: *const u16,
) -> HANDLE;

pub type FnWireGuardGetConfiguration = unsafe extern "system" fn(
    Adapter: HANDLE,
    Config:  *mut c_void,
    Bytes:   *mut DWORD,
) -> BOOL;

/// `void WireGuardGetAdapterLUID(WIREGUARD_ADAPTER_HANDLE Adapter, NET_LUID *Luid)`
///
/// Returns the NET_LUID of the adapter as a ULONG64 (the `Value` field of the
/// NET_LUID_LH union).  We use this to convert to an interface index via
/// `iphlpapi!ConvertInterfaceLuidToIndex`, so we can refer to the adapter by
/// index rather than by name in netsh commands (the OS may suffix the friendly
/// name with a number when duplicates exist, e.g. "SWGC 10").
pub type FnWireGuardGetAdapterLUID = unsafe extern "system" fn(
    Adapter: HANDLE,
    Luid:    *mut u64,  // NET_LUID is a ULONG64 union — just use u64
);
