use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("暗号化エラー: {0}")]
    Crypto(String),

    #[error("設定ファイルエラー: {0}")]
    Config(String),

    #[error("WireGuardエラー: {0}")]
    WireGuard(String),

    #[error("IOエラー: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSONエラー: {0}")]
    Json(#[from] serde_json::Error),
}

// Tauri commands require errors to be serializable as strings.
// Use std::result::Result explicitly to avoid clash with our Result alias.
impl serde::Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
