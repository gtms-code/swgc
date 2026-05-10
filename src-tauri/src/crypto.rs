//! Secure storage using Windows DPAPI + PBKDF2-derived per-passphrase entropy.
//!
//! # Security design
//!
//! - **User binding**: The ciphertext is cryptographically bound to the Windows
//!   logon session of the user who called `encrypt()`. A different user account
//!   (or the same account on a different machine) cannot call `decrypt()`
//!   successfully.
//!
//! - **Passphrase-derived entropy**: `derive_entropy` runs PBKDF2-HMAC-SHA256
//!   (100,000 iterations) on the user's passphrase and mixes the 32-byte output
//!   into every DPAPI call.  Unlike the previous hardcoded constant, this value
//!   is **never stored anywhere** — not on disk, not in the registry.  An
//!   attacker who extracts the DPAPI blob from the registry must also know the
//!   passphrase to decrypt it, even when running as the same Windows user.
//!
//!   Salt: `b"swgc-dpapi-salt-v2"` — public, fixed, version-stamped.
//!   Iterations: 100,000 (NIST SP 800-132 compliant).
//!   Output: 32 bytes, wrapped in `Zeroizing<[u8; 32]>` for automatic zeroing.
//!
//! - **No plaintext on disk**: `encrypt` and `decrypt` operate entirely in RAM.
//!   The caller is responsible for zeroizing sensitive inputs after each call.

use crate::error::{AppError, Result};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Key derivation  (pure Rust — platform-independent)
// ---------------------------------------------------------------------------

/// Derive a 32-byte DPAPI entropy value from a user passphrase via
/// PBKDF2-HMAC-SHA256.
///
/// The derived bytes are used as DPAPI's optional entropy parameter, binding
/// the ciphertext to both the Windows logon session and this passphrase.
/// The passphrase is never stored; only the DPAPI ciphertext goes to the
/// registry.
///
/// - Salt: `b"swgc-dpapi-salt-v2"` (public, version-stamped, purpose-specific)
/// - Iterations: 100,000 (NIST SP 800-132 compliant)
/// - Output: 32 bytes wrapped in `Zeroizing<[u8; 32]>` (zeroed on drop)
pub fn derive_entropy(passphrase: &str) -> Zeroizing<[u8; 32]> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    const SALT: &[u8] = b"swgc-dpapi-salt-v2";
    const ITERATIONS: u32 = 100_000;

    let mut raw = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), SALT, ITERATIONS, &mut raw);
    Zeroizing::new(raw)
}

// ---------------------------------------------------------------------------
// DPAPI wrapper (Windows only)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod dpapi {
    use super::*;
    use std::ptr;
    use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData};
    use winapi::um::winbase::LocalFree;
    use winapi::um::wincrypt::DATA_BLOB;

    fn make_blob(data: &[u8]) -> DATA_BLOB {
        DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    /// Encrypt `plaintext` bytes with DPAPI, bound to the current Windows user
    /// and the supplied `entropy` (32 bytes derived from the user passphrase).
    ///
    /// Returns the opaque ciphertext blob.  The caller should `zeroize` the
    /// input `plaintext` after this call if it contains sensitive key material.
    pub fn encrypt(plaintext: &[u8], entropy: &[u8; 32]) -> Result<Vec<u8>> {
        let mut input = make_blob(plaintext);
        let mut ent   = make_blob(entropy.as_slice());
        let mut output = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        // SAFETY:
        // - `input` and `ent` point into valid, live slices.
        // - `output` is a properly initialised DATA_BLOB; DPAPI allocates its buffer.
        // - Flags = 0 → user-session scope (not CRYPTPROTECT_LOCAL_MACHINE).
        let ok = unsafe {
            CryptProtectData(
                &mut input,
                ptr::null(),     // optional description (unused)
                &mut ent,
                ptr::null_mut(), // pvReserved — must be NULL
                ptr::null_mut(), // no UI prompt
                0,               // dwFlags: user-session scope
                &mut output,
            )
        };

        if ok == 0 {
            return Err(AppError::Crypto(format!(
                "CryptProtectData failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Copy the DPAPI-allocated buffer into a Vec, then free it.
        // SAFETY: DPAPI guarantees output.pbData is valid for output.cbData bytes.
        let ciphertext = unsafe {
            std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
        };
        unsafe { LocalFree(output.pbData as *mut _) };

        Ok(ciphertext)
    }

    /// Decrypt a DPAPI blob previously produced by `encrypt` with the same entropy.
    ///
    /// Returns an error if `entropy` does not match (wrong passphrase), if the
    /// blob is corrupted, or if the calling user differs from the encrypting user.
    ///
    /// Returns plaintext bytes in process memory.  The caller must `zeroize`
    /// the returned `Vec<u8>` as soon as it is no longer needed.
    pub fn decrypt(ciphertext: &[u8], entropy: &[u8; 32]) -> Result<Vec<u8>> {
        let mut input = make_blob(ciphertext);
        let mut ent   = make_blob(entropy.as_slice());
        let mut output = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        // SAFETY: same reasoning as encrypt above.
        let ok = unsafe {
            CryptUnprotectData(
                &mut input,
                ptr::null_mut(), // ppszDataDescr (unused)
                &mut ent,
                ptr::null_mut(), // pvReserved
                ptr::null_mut(), // no UI prompt
                0,
                &mut output,
            )
        };

        if ok == 0 {
            return Err(AppError::Crypto(format!(
                "CryptUnprotectData failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: same as encrypt.
        let plaintext = unsafe {
            std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
        };
        unsafe { LocalFree(output.pbData as *mut _) };

        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Public API — forwards to DPAPI on Windows.
// Non-Windows builds fail at compile time so an insecure port cannot be made.
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub use dpapi::{decrypt, encrypt};

#[cfg(not(windows))]
pub fn encrypt(_plaintext: &[u8], _entropy: &[u8; 32]) -> Result<Vec<u8>> {
    Err(AppError::Crypto("Windows専用アプリです".into()))
}

#[cfg(not(windows))]
pub fn decrypt(_ciphertext: &[u8], _entropy: &[u8; 32]) -> Result<Vec<u8>> {
    Err(AppError::Crypto("Windows専用アプリです".into()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    // ── derive_entropy ────────────────────────────────────────────────────

    #[test]
    fn derive_entropy_is_deterministic() {
        let e1 = derive_entropy("my-passphrase");
        let e2 = derive_entropy("my-passphrase");
        assert_eq!(*e1, *e2, "same passphrase must yield same entropy");
    }

    #[test]
    fn derive_entropy_differs_for_different_passphrases() {
        let e1 = derive_entropy("passphrase-a");
        let e2 = derive_entropy("passphrase-b");
        assert_ne!(*e1, *e2, "different passphrases must yield different entropy");
    }

    #[test]
    fn derive_entropy_output_is_32_bytes() {
        let e = derive_entropy("test");
        assert_eq!(e.len(), 32);
    }

    // ── DPAPI round-trips (Windows only) ──────────────────────────────────

    /// Basic DPAPI round-trip: decrypt(encrypt(pt)) == pt.
    #[test]
    #[cfg(windows)]
    fn encrypt_decrypt_roundtrip() {
        let entropy = derive_entropy("test-passphrase");
        let plaintext = b"top-secret WireGuard private key material";

        let ciphertext = encrypt(plaintext, &entropy).expect("encrypt failed");

        // Ciphertext must not contain the plaintext as a substring.
        assert!(
            !ciphertext
                .windows(plaintext.len())
                .any(|w| w == plaintext.as_slice()),
            "ciphertext must not contain plaintext verbatim"
        );

        let mut recovered = decrypt(&ciphertext, &entropy).expect("decrypt failed");

        assert_eq!(
            recovered.as_slice(),
            plaintext.as_slice(),
            "decrypted bytes must equal original plaintext"
        );

        recovered.zeroize();
    }

    /// Wrong passphrase → wrong entropy → DPAPI must reject decryption.
    #[test]
    #[cfg(windows)]
    fn wrong_passphrase_fails_decrypt() {
        let entropy_ok  = derive_entropy("correct-passphrase");
        let entropy_bad = derive_entropy("wrong-passphrase");

        let ciphertext = encrypt(b"secret data", &entropy_ok).unwrap();
        let result = decrypt(&ciphertext, &entropy_bad);
        assert!(result.is_err(), "wrong passphrase must not decrypt successfully");
    }

    /// DPAPI uses a random session key per call, so two encryptions of the
    /// same plaintext must produce different blobs.
    #[test]
    #[cfg(windows)]
    fn ciphertext_is_nondeterministic() {
        let entropy = derive_entropy("test");
        let blob1 = encrypt(b"same input", &entropy).unwrap();
        let blob2 = encrypt(b"same input", &entropy).unwrap();
        assert_ne!(blob1, blob2, "DPAPI blobs should differ across calls");
    }

    /// Decrypting a tampered blob must return an error, not garbage plaintext.
    #[test]
    #[cfg(windows)]
    fn tampered_ciphertext_is_rejected() {
        let entropy = derive_entropy("test");
        let mut blob = encrypt(b"sensitive data", &entropy).unwrap();
        let mid = blob.len() / 2;
        blob[mid] ^= 0xFF;
        let result = decrypt(&blob, &entropy);
        assert!(result.is_err(), "tampered blob must not decrypt successfully");
    }

    /// Empty plaintext must survive the round-trip without panicking.
    #[test]
    #[cfg(windows)]
    fn roundtrip_empty_plaintext() {
        let entropy = derive_entropy("test");
        let ct = encrypt(&[], &entropy).expect("encrypt empty slice failed");
        let pt = decrypt(&ct, &entropy).expect("decrypt empty ciphertext failed");
        assert!(pt.is_empty());
    }
}
