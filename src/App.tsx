import { useState, useEffect, useCallback, useRef } from "react";
import {
  getStatus,
  selectConfFile,
  importConfig,
  connect,
  disconnect,
  deleteConfig,
  getTunnelStats,
  forceReconnect,
} from "./commands";
import type { AppState } from "./types";

// ── Byte formatter ────────────────────────────────────────────────────────

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/** Convert Windows FILETIME (100-ns since 1601-01-01) → JS Date, or null if 0. */
function filetimeToDate(ft: number): Date | null {
  if (ft === 0) return null;
  const epochDiffMs = 11644473600000;
  const ms = ft / 10000 - epochDiffMs;
  return new Date(ms);
}

function formatHandshake(ft: number): string {
  const d = filetimeToDate(ft);
  if (!d) return "ハンドシェイク未確立";
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 60) return `${sec}秒前`;
  if (sec < 3600) return `${Math.floor(sec / 60)}分前`;
  return `${Math.floor(sec / 3600)}時間前`;
}

function handshakeAgeSec(ft: number): number {
  const d = filetimeToDate(ft);
  if (!d) return Infinity;
  return (Date.now() - d.getTime()) / 1000;
}

// ── Elapsed-time hook ─────────────────────────────────────────────────────

function useElapsedTime(startMs: number | undefined): string {
  const [elapsed, setElapsed] = useState("");

  useEffect(() => {
    if (!startMs) { setElapsed(""); return; }
    const tick = () => {
      const s = Math.floor((Date.now() - startMs) / 1000);
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      setElapsed(
        h > 0
          ? `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
          : `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
      );
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startMs]);

  return elapsed;
}

// ── Passphrase dialog state ───────────────────────────────────────────────

type PhraseFlow = "import" | "connect" | "reconnect";

interface PhraseDialog {
  open: boolean;
  flow: PhraseFlow | null;
  /** File path selected for import — null for connect/reconnect flows. */
  filePath: string | null;
  value: string;
  error: string | null;
}

const PHRASE_CLOSED: PhraseDialog = {
  open: false,
  flow: null,
  filePath: null,
  value: "",
  error: null,
};

// ── App ───────────────────────────────────────────────────────────────────

export default function App() {
  const [state, setState] = useState<AppState>({
    status: "disconnected",
    hasConfig: false,
  });
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [phraseDialog, setPhraseDialog] = useState<PhraseDialog>(PHRASE_CLOSED);
  const errorTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const elapsed = useElapsedTime(state.connectedAt);

  // ── Error auto-dismiss ──────────────────────────────────────────────────

  const setError = useCallback((msg: string) => {
    if (errorTimerRef.current) clearTimeout(errorTimerRef.current);
    setState((prev) => ({ ...prev, errorMessage: msg }));
    errorTimerRef.current = setTimeout(() => {
      setState((prev) => ({ ...prev, errorMessage: undefined }));
    }, 8000);
  }, []);

  // ── Status polling ──────────────────────────────────────────────────────

  const refreshStatus = useCallback(async () => {
    const result = await getStatus();
    if (!result) return;
    setState((prev) => {
      const nowConnected = result.is_connected;
      const connectedAt =
        nowConnected && prev.status !== "connected" ? Date.now() :
        nowConnected ? prev.connectedAt :
        undefined;
      return {
        ...prev,
        hasConfig: result.has_config,
        status: nowConnected ? "connected" : "disconnected",
        peerEndpoint: result.peer_endpoint,
        connectedAt,
        tunnelStats: nowConnected ? prev.tunnelStats : undefined,
      };
    });

    if (result.is_connected) {
      const stats = await getTunnelStats();
      if (stats) {
        setState((prev) => ({ ...prev, tunnelStats: stats }));
      }
    }
  }, []);

  useEffect(() => {
    refreshStatus();
    const id = setInterval(refreshStatus, 5000);
    return () => clearInterval(id);
  }, [refreshStatus]);

  // ── Passphrase dialog helpers ───────────────────────────────────────────

  const closePhraseDialog = useCallback(() => {
    setPhraseDialog(PHRASE_CLOSED);
  }, []);

  /** Called when the user confirms the passphrase dialog. */
  const handlePhraseConfirm = useCallback(async () => {
    const { flow, filePath, value: passphrase } = phraseDialog;

    if (!passphrase) {
      setPhraseDialog((prev) => ({ ...prev, error: "パスフレーズを入力してください" }));
      return;
    }

    // Close dialog and clear passphrase from React state before any async work.
    setPhraseDialog(PHRASE_CLOSED);

    try {
      if (flow === "import" && filePath) {
        await importConfig(filePath, passphrase);
        setState((prev) => ({ ...prev, hasConfig: true, errorMessage: undefined }));
      } else if (flow === "connect") {
        setState((prev) => ({ ...prev, status: "connecting", errorMessage: undefined }));
        await connect(passphrase);
        setState((prev) => ({ ...prev, status: "connected", connectedAt: Date.now() }));
      } else if (flow === "reconnect") {
        setState((prev) => ({ ...prev, status: "connecting", errorMessage: undefined }));
        await forceReconnect(passphrase);
        setState((prev) => ({ ...prev, status: "connected", connectedAt: Date.now() }));
      }
    } catch (err) {
      if (flow === "connect" || flow === "reconnect") {
        setState((prev) => ({ ...prev, status: "disconnected" }));
      }
      const prefix =
        flow === "import"    ? "インポートエラー" :
        flow === "connect"   ? "接続エラー" :
        "再接続エラー";
      setError(`${prefix}: ${err}`);
    }
  }, [phraseDialog, setError]);

  // ── Button handlers ─────────────────────────────────────────────────────

  /** Step 1 of import: pick file, then open passphrase dialog. */
  const handleImport = async () => {
    try {
      const filePath = await selectConfFile();
      if (!filePath) return; // user cancelled file picker
      setPhraseDialog({ open: true, flow: "import", filePath, value: "", error: null });
    } catch (err) {
      setError(`ファイル選択エラー: ${err}`);
    }
  };

  /** Open passphrase dialog for connect. */
  const handleConnect = () => {
    setPhraseDialog({ open: true, flow: "connect", filePath: null, value: "", error: null });
  };

  const handleDisconnect = async () => {
    setState((prev) => ({ ...prev, status: "disconnecting", errorMessage: undefined }));
    try {
      await disconnect();
      setState((prev) => ({ ...prev, status: "disconnected", connectedAt: undefined }));
    } catch (err) {
      setState((prev) => ({ ...prev, status: "connected" }));
      setError(`切断エラー: ${err}`);
    }
  };

  /** Open passphrase dialog for force-reconnect. */
  const handleForceReconnect = () => {
    setPhraseDialog({ open: true, flow: "reconnect", filePath: null, value: "", error: null });
  };

  const handleDeleteConfig = async () => {
    setShowDeleteConfirm(false);
    try {
      await deleteConfig();
      setState((prev) => ({
        ...prev,
        hasConfig: false,
        peerEndpoint: undefined,
        errorMessage: undefined,
      }));
    } catch (err) {
      setError(`設定削除エラー: ${err}`);
    }
  };

  // ── Derived state ────────────────────────────────────────────────────────

  const isConnected   = state.status === "connected";
  const isConnecting  = state.status === "connecting" || state.status === "disconnecting";
  const isBusy        = isConnecting;

  const hsAge     = state.tunnelStats ? handshakeAgeSec(state.tunnelStats.last_handshake) : 0;
  const isStale   = isConnected && !!state.tunnelStats && hsAge > 180;
  const isVeryStale = isConnected && !!state.tunnelStats && hsAge > 330;

  const statusLabel =
    state.status === "connected"     ? (isVeryStale ? "セッション期限切れ" : isStale ? "接続中 (セッション古い)" : "接続中") :
    state.status === "connecting"    ? "接続しています..." :
    state.status === "disconnecting" ? "切断しています..." :
    "未接続";

  const dotClass =
    isConnecting  ? "connecting" :
    isVeryStale   ? "stale-urgent" :
    isStale       ? "stale" :
    isConnected   ? "connected"  :
    "disconnected";

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="app">
      {/* Header */}
      <div className="app-header">
        <svg className="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
        <div>
          <h1>Secure WireGuard Client</h1>
          <div className="subtitle">鍵はOSが管理 — 平文は保存されません</div>
        </div>
      </div>

      {/* Status card */}
      <div className="status-section">
        <div className={`status-dot ${dotClass}`} />
        <div className="status-info">
          <div className={`status-label ${dotClass}`}>{statusLabel}</div>
          {isConnected && elapsed && (
            <div className="status-detail">接続時間: {elapsed}</div>
          )}
          {isConnected && state.peerEndpoint && (
            <div className="status-detail">エンドポイント: {state.peerEndpoint}</div>
          )}
          {isConnected && state.tunnelStats && (() => {
            const hs = state.tunnelStats.last_handshake;
            const hsText = formatHandshake(hs);
            const hsOk = hs !== 0 && !isStale;
            return (
              <>
                <div className={`status-detail${hsOk ? "" : isVeryStale ? " warn-urgent" : " warn"}`}>
                  🔑 {hsText}
                  {isVeryStale && " — 再接続してください"}
                  {isStale && !isVeryStale && " — セッションが古い"}
                </div>
                <div className="status-detail">
                  ↑ {formatBytes(state.tunnelStats.tx_bytes)} &nbsp;
                  ↓ {formatBytes(state.tunnelStats.rx_bytes)}
                </div>
              </>
            );
          })()}
          {!state.hasConfig && !isConnected && !isBusy && (
            <div className="status-detail">設定ファイルが未インポートです</div>
          )}
        </div>
      </div>

      {/* No-config notice */}
      {!state.hasConfig && !isBusy && (
        <div className="no-config-notice">
          WireGuard設定ファイル (.conf) をインポートして接続してください
        </div>
      )}

      {/* Error message */}
      {state.errorMessage && (
        <div
          className="error-message"
          role="alert"
          onClick={() => setState((p) => ({ ...p, errorMessage: undefined }))}
        >
          {state.errorMessage}
          <span className="error-dismiss">✕</span>
        </div>
      )}

      {/* Delete confirmation */}
      {showDeleteConfirm && (
        <div className="confirm-box">
          <div className="confirm-text">設定を削除しますか？再接続には再インポートが必要です。</div>
          <div className="confirm-actions">
            <button className="btn-confirm-cancel" onClick={() => setShowDeleteConfirm(false)}>
              キャンセル
            </button>
            <button className="btn-confirm-delete" onClick={handleDeleteConfig}>
              削除する
            </button>
          </div>
        </div>
      )}

      {/* Action buttons */}
      <div className="actions">
        <button
          className="btn-connect"
          onClick={handleConnect}
          disabled={!state.hasConfig || isConnected || isBusy}
          title={!state.hasConfig ? "先に設定をインポートしてください" : ""}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <path d="M5 12h14M12 5l7 7-7 7" />
          </svg>
          接続
        </button>

        {isStale && (
          <button
            className="btn-reconnect"
            onClick={handleForceReconnect}
            disabled={isBusy}
            title="セッションが古いため再接続します"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <polyline points="1 4 1 10 7 10" />
              <path d="M3.51 15a9 9 0 1 0 .49-4.5" />
            </svg>
            再接続
          </button>
        )}

        <button
          className="btn-disconnect"
          onClick={handleDisconnect}
          disabled={!isConnected || isBusy}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="6" x2="18" y2="18" />
          </svg>
          切断
        </button>

        <button
          className="btn-import"
          onClick={handleImport}
          disabled={isConnected || isBusy}
          title={isConnected ? "切断してから設定を変更してください" : ""}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
            <polyline points="17 8 12 3 7 8" />
            <line x1="12" y1="3" x2="12" y2="15" />
          </svg>
          設定をインポート (.conf)
        </button>

        {state.hasConfig && !isConnected && !isBusy && (
          <button
            className="btn-delete"
            onClick={() => setShowDeleteConfirm(true)}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="3 6 5 6 21 6" />
              <path d="M19 6l-1 14H6L5 6" />
              <path d="M10 11v6M14 11v6" />
              <path d="M9 6V4h6v2" />
            </svg>
            設定をリセット
          </button>
        )}
      </div>

      {/* Footer */}
      <div className="footer">
        秘密鍵は Windows DPAPI + パスフレーズで保護 — ディスクへの平文保存なし
      </div>

      {/* Passphrase dialog overlay */}
      {phraseDialog.open && (
        <div
          className="passphrase-overlay"
          onClick={(e) => { if (e.target === e.currentTarget) closePhraseDialog(); }}
        >
          <div className="passphrase-dialog">
            <div className="passphrase-title">
              {phraseDialog.flow === "import"    ? "設定をインポート" :
               phraseDialog.flow === "connect"   ? "VPNに接続" :
               "VPNに再接続"}
            </div>
            <div className="passphrase-hint">
              {phraseDialog.flow === "import"
                ? "設定ファイルの暗号化に使用するパスフレーズを入力してください。接続時にも同じパスフレーズが必要です。"
                : "インポート時に設定したパスフレーズを入力してください。"}
            </div>
            <input
              className={`passphrase-input${phraseDialog.error ? " passphrase-input-error" : ""}`}
              type="password"
              value={phraseDialog.value}
              onChange={(e) =>
                setPhraseDialog((prev) => ({ ...prev, value: e.target.value, error: null }))
              }
              onKeyDown={(e) => {
                if (e.key === "Enter") handlePhraseConfirm();
                if (e.key === "Escape") closePhraseDialog();
              }}
              autoFocus
              placeholder="パスフレーズ"
              autoComplete="off"
            />
            {phraseDialog.error && (
              <div className="passphrase-error">{phraseDialog.error}</div>
            )}
            <div className="passphrase-actions">
              <button className="btn-phrase-cancel" onClick={closePhraseDialog}>
                キャンセル
              </button>
              <button className="btn-phrase-ok" onClick={handlePhraseConfirm}>
                OK
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
