//! Secure storage using Windows DPAPI (CryptProtectData / CryptUnprotectData).
//!
//! # Security design
//!
//! - **User binding**: The ciphertext is cryptographically bound to the Windows
//!   logon session of the user who called `encrypt()`. Even with the raw registry
//!   blob, a different user account (or the same account on a different machine)
//!   cannot call `decrypt()` successfully.
//!
//! - **Application entropy**: A 25-byte constant (`ENTROPY`) is passed as
//!   DPAPI's optional entropy parameter.  Its purpose is **application scoping**:
//!   other applications that call `CryptUnprotectData` on our registry blob
//!   without supplying this exact value will receive a decryption error.
//!
//!   **Important limitation**: this constant is NOT a secret.  It is visible in
//!   the source code, on GitHub, and extractable from the binary with `strings`.
//!   A process running as the same user that supplies this constant can decrypt
//!   the blob just as SWGC does.  The real security boundary is the DPAPI
//!   user-session binding described above — a different Windows user account or
//!   the same account on a different machine cannot decrypt even knowing this
//!   constant.  The entropy provides namespace isolation, not process isolation.
//!
//! - **No plaintext on disk**: `encrypt` and `decrypt` operate entirely in RAM.
//!   The caller is responsible for zeroizing sensitive inputs after the call.

use crate::error::{AppError, Result};

#[cfg(windows)]
mod dpapi {
    use super::*;
    use std::ptr;
    use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData};
    use winapi::um::winbase::LocalFree;
    use winapi::um::wincrypt::DATA_BLOB;

    /// Application-specific entropy mixed into every DPAPI call.
    ///
    /// Purpose: namespace isolation — other apps calling CryptUnprotectData on
    /// our registry blob without this exact value will fail.  This is NOT a
    /// secret; it is visible in the binary and source code.  See module doc.
    ///
    /// Changing this string would invalidate all stored blobs (users would need
    /// to re-import their WireGuard configuration).
    const ENTROPY: &[u8] = b"swgc-wireguard-config-v1\0";

    fn make_blob(data: &[u8]) -> DATA_BLOB {
        DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    /// Encrypt `plaintext` bytes with DPAPI, bound to the current Windows user.
    ///
    /// Returns the opaque ciphertext blob. The caller should `zeroize` the
    /// input `plaintext` after this call if it contains sensitive key material.
    pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut input = make_blob(plaintext);
        let mut entropy = make_blob(ENTROPY);
        let mut output = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        // SAFETY:
        // - `input` and `entropy` point into valid, live slices.
        // - `output` is a properly initialised DATA_BLOB; DPAPI allocates its buffer.
        // - Flags = 0 → user-session scope (not CRYPTPROTECT_LOCAL_MACHINE).
        let ok = unsafe {
            CryptProtectData(
                &mut input,
                ptr::null(),     // optional description (unused)
                &mut entropy,
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

    /// Decrypt a DPAPI blob previously produced by `encrypt`.
    ///
    /// Returns plaintext bytes in process memory. The caller must `zeroize`
    /// the returned `Vec<u8>` as soon as it is no longer needed.
    pub fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut input = make_blob(ciphertext);
        let mut entropy = make_blob(ENTROPY);
        let mut output = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        // SAFETY: same reasoning as encrypt above.
        let ok = unsafe {
            CryptUnprotectData(
                &mut input,
                ptr::null_mut(), // ppszDataDescr (unused)
                &mut entropy,
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
pub fn encrypt(_plaintext: &[u8]) -> Result<Vec<u8>> {
    Err(AppError::Crypto("Windows専用アプリです".into()))
}

#[cfg(not(windows))]
pub fn decrypt(_ciphertext: &[u8]) -> Result<Vec<u8>> {
    Err(AppError::Crypto("Windows専用アプリです".into()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    /// Basic DPAPI round-trip: the decrypted bytes must equal the original input.
    #[test]
    #[cfg(windows)]
    fn encrypt_decrypt_roundtrip() {
        let mut plaintext = b"top-secret WireGuard private key material".to_vec();

        let ciphertext = encrypt(&plaintext).expect("encrypt failed");

        // Ciphertext must not contain the plaintext as a substring.
        assert!(
            !ciphertext
                .windows(plaintext.len())
                .any(|w| w == plaintext.as_slice()),
            "ciphertext must not contain plaintext verbatim"
        );

        let mut recovered = decrypt(&ciphertext).expect("decrypt failed");

        assert_eq!(
            recovered, plaintext,
            "decrypted bytes must equal original plaintext"
        );

        // Zeroize sensitive material after verification.
        plaintext.zeroize();
        recovered.zeroize();
    }

    /// The ciphertext blob must change across two encryptions of the same input
    /// (DPAPI uses a random session key per call, so blobs are non-deterministic).
    #[test]
    #[cfg(windows)]
    fn ciphertext_is_nondeterministic() {
        let plaintext = b"same input".as_ref();
        let blob1 = encrypt(plaintext).unwrap();
        let blob2 = encrypt(plaintext).unwrap();
        assert_ne!(blob1, blob2, "DPAPI blobs should differ across calls");
    }

    /// Decrypting a tampered blob must return an error, not garbage plaintext.
    #[test]
    #[cfg(windows)]
    fn tampered_ciphertext_is_rejected() {
        let mut blob = encrypt(b"sensitive data").unwrap();
        // Flip a byte in the middle of the blob.
        let mid = blob.len() / 2;
        blob[mid] ^= 0xFF;
        let result = decrypt(&blob);
        assert!(result.is_err(), "tampered blob must not decrypt successfully");
    }

    /// Empty plaintext must survive the round-trip without panicking.
    #[test]
    #[cfg(windows)]
    fn roundtrip_empty_plaintext() {
        let ct = encrypt(&[]).expect("encrypt empty slice failed");
        let pt = decrypt(&ct).expect("decrypt empty ciphertext failed");
        assert!(pt.is_empty());
    }
}
