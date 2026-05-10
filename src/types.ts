/** Backend connection status (mirrors Rust ConnectionStatus logic). */
export type ConnectionStatus =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting";

/** Response shape from the `get_status` Tauri command. */
export interface StatusResponse {
  has_config: boolean;
  is_connected: boolean;
  peer_endpoint?: string;
}

/** Per-peer statistics from the WireGuard kernel driver. */
export interface TunnelStats {
  tx_bytes: number;
  rx_bytes: number;
  /** Windows FILETIME (100-ns intervals since 1601-01-01). 0 = no handshake yet. */
  last_handshake: number;
}

/** Internal UI state. */
export interface AppState {
  status: ConnectionStatus;
  hasConfig: boolean;
  peerEndpoint?: string;
  errorMessage?: string;
  /** Unix timestamp (ms) when the current connection was established. */
  connectedAt?: number;
  tunnelStats?: TunnelStats;
}
