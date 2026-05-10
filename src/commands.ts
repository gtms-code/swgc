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
 * Open a file-picker limited to `.conf` files, then send the selected
 * path to the backend for immediate encryption. Returns `true` on success.
 * Throws a descriptive string on error.
 */
export async function importConfig(): Promise<boolean> {
  // Tauri v2: single-select returns `string | null`
  const selected = await open({
    title: "WireGuard設定ファイルを選択",
    filters: [{ name: "WireGuard Config", extensions: ["conf"] }],
    multiple: false,
  });

  if (!selected) return false; // user cancelled

  const filePath = Array.isArray(selected) ? selected[0] : selected;

  // Backend reads the file, encrypts it, then discards the plaintext.
  // The filePath itself is not sensitive — only its contents are.
  await invoke("import_config", { filePath });
  return true;
}

/** Bring the WireGuard tunnel up. Throws a string on error. */
export async function connect(): Promise<void> {
  await invoke("connect");
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
 * Throws a string on error.
 */
export async function forceReconnect(): Promise<void> {
  await invoke("force_reconnect");
}
