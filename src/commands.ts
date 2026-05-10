/**
 * Type-safe wrappers around Tauri IPC commands.
 *
 * All Rust `Result<T, AppError>` commands throw a `string` on error
 * (because AppError implements `serde::Serialize` as a string).
 * Callers should catch and display those strings directly.
 */

import { invoke } from "@tauri-apps/api/core";
import { open }   from "@tauri-apps/plugin-dialog";
import type { StatusResponse, TunnelStats } from "./types";

/** Poll the backend for connection status. Never throws. */
export async function getStatus(): Promise<StatusResponse | null> {
  try {
    return await invoke<StatusResponse>("get_status");
  } catch {
    return null;
  }
}

/**
 * Open a file-picker limited to `.conf` files and return the selected path,
 * or `null` if the user cancelled.
 *
 * Separated from `importConfig` so the caller can collect a passphrase before
 * sending the path to the backend.
 */
export async function selectConfFile(): Promise<string | null> {
  const selected = await open({
    title: "WireGuard設定ファイルを選択",
    filters: [{ name: "WireGuard Config", extensions: ["conf"] }],
    multiple: false,
  });

  if (!selected) return null;
  return Array.isArray(selected) ? selected[0] : selected;
}

/**
 * Send the selected `.conf` path and passphrase to the backend for encryption.
 *
 * The backend reads the file, derives DPAPI entropy from `passphrase` via
 * PBKDF2, encrypts the config, and discards all plaintext. The passphrase
 * itself is never stored — neither on disk nor in the registry.
 *
 * Throws a descriptive string on error.
 */
export async function importConfig(filePath: string, passphrase: string): Promise<void> {
  await invoke("import_config", { filePath, passphrase });
}

/**
 * Bring the WireGuard tunnel up.
 *
 * `passphrase` is used backend-side to derive DPAPI entropy (PBKDF2) and
 * decrypt the stored config. It is zeroized in Rust memory immediately after
 * entropy derivation and is never stored.
 *
 * Throws a string on error (including wrong-passphrase errors).
 */
export async function connect(passphrase: string): Promise<void> {
  await invoke("connect", { passphrase });
}

/** Tear down the WireGuard tunnel. Throws a string on error. */
export async function disconnect(): Promise<void> {
  await invoke("disconnect");
}

/**
 * Delete the stored encrypted config from the registry.
 * The backend refuses this call while a tunnel is active.
 * Throws a string on error.
 */
export async function deleteConfig(): Promise<void> {
  await invoke("delete_config");
}

/**
 * Read live WireGuard peer statistics (TX/RX bytes, last handshake time).
 * Returns null when no tunnel is active or on error.
 */
export async function getTunnelStats(): Promise<TunnelStats | null> {
  try {
    return await invoke<TunnelStats | null>("tunnel_stats");
  } catch {
    return null;
  }
}

/**
 * Disconnect then immediately reconnect — use when the session is stale.
 *
 * Requires the passphrase for the same reason as `connect`.
 * Throws a string on error.
 */
export async function forceReconnect(passphrase: string): Promise<void> {
  await invoke("force_reconnect", { passphrase });
}
