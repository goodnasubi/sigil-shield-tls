//! 資源の上限と設定（ADR 0063 決定 4.4, 4.5）
//!
//! 上限は設定で変えられるが、範囲の外・無制限の値は受け付けず、起動を拒否する。

use std::fmt;

/// 固定の上限定数（ADR 0063 決定 4.2, 4.3, 4.5）
pub const MAX_CLIENT_HELLO_SIZE: usize = 16 * 1024; // 16 KiB
pub const MAX_HANDSHAKE_RECORD_COUNT: usize = 8; // 最大 8 レコード
pub const MAX_HANDSHAKE_READ_TOTAL: usize = 32 * 1024; // 32 KiB
pub const MAX_CONSECUTIVE_EMPTY_APP_DATA: usize = 16; // 連続 16 個
pub const MAX_EXTENSIONS_COUNT: usize = 64; // 拡張の数
pub const MAX_CIPHER_SUITES_COUNT: usize = 64; // スイートの数 (128 バイト / 2)
pub const MAX_KEY_SHARE_ENTRIES_COUNT: usize = 8; // key_share の項目数
pub const MAX_KEY_UPDATE_COUNT: usize = 16; // 受信する KeyUpdate
pub const MAX_CERT_CHAIN_COUNT: usize = 8; // 証明書チェーン 8 枚
pub const MAX_CERT_FILE_SIZE: usize = 64 * 1024; // 64 KiB
pub const MAX_SERVER_NAMES_COUNT: usize = 256; // 名前 256 個
pub const MAX_SAN_COUNT: usize = 100; // SAN 100 個
pub const MAX_ALPN_TOTAL_SIZE: usize = 1024; // ALPN 合計 1 KiB
pub const MAX_PLAIN_RECORD_PAYLOAD: usize = 16 * 1024; // 2^14 (16,384 バイト)
pub const MAX_ENCRYPTED_RECORD_PAYLOAD: usize = 16 * 1024 + 256; // 16,640 バイト

pub const MAX_MEMORY_ESTIMATE_LIMIT: usize = 256 * 1024 * 1024; // 256 MiB
pub const ESTIMATED_PER_CONN_MEMORY: usize = 64 * 1024; // 64 KiB

/// 設定エラー
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitError {
    OutOfRange {
        parameter: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },
    MemoryBudgetExceeded {
        estimated_bytes: usize,
        max_bytes: usize,
    },
}

impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange {
                parameter,
                value,
                min,
                max,
            } => {
                write!(
                    f,
                    "parameter '{}' value {} is out of allowed range [{}..={}]",
                    parameter, value, min, max
                )
            }
            Self::MemoryBudgetExceeded {
                estimated_bytes,
                max_bytes,
            } => {
                write!(
                    f,
                    "estimated memory usage {} bytes exceeds limit {} bytes",
                    estimated_bytes, max_bytes
                )
            }
        }
    }
}

impl std::error::Error for LimitError {}

/// 設定可能な資源上限構造体（ADR 0063 決定 4.4, 4.5）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldLimits {
    /// 同時接続数: 既定 1024, 範囲 1〜65536 (ただしメモリ上限による制約あり)
    pub max_connections: u32,
    /// ハンドシェイク中の同時接続数: 既定 64, 範囲 1〜1024
    pub max_handshaking_connections: u32,
    /// 接続元ごとの同時接続数: 既定 32, 範囲 1〜1024
    pub max_connections_per_source: u32,
    /// 接続元ごとのハンドシェイク中の接続数: 既定 4, 範囲 1〜64
    pub max_handshaking_per_source: u32,
    /// 鍵交換と署名を同時に計算する数: 既定 2, 範囲 1〜64
    pub max_concurrent_crypto_tasks: u32,
    /// ハンドシェイク全体の期限（秒）: 既定 10, 範囲 1〜60
    pub handshake_timeout_secs: u64,
    /// アイドル期限（秒）: 既定 60, 範囲 5〜3600
    pub idle_timeout_secs: u64,
    /// 書き込み期限（秒）: 既定 30, 範囲 1〜300
    pub write_timeout_secs: u64,
    /// 上流接続期限（秒）: 既定 3, 範囲 1〜30
    pub upstream_connect_timeout_secs: u64,
}

impl Default for ShieldLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_handshaking_connections: 64,
            max_connections_per_source: 32,
            max_handshaking_per_source: 4,
            max_concurrent_crypto_tasks: 2,
            handshake_timeout_secs: 10,
            idle_timeout_secs: 60,
            write_timeout_secs: 30,
            upstream_connect_timeout_secs: 3,
        }
    }
}

impl ShieldLimits {
    /// 上限パラメータの範囲を厳密に検証する。
    /// 範囲外・無制限の値は受け付けず、Errを返す。
    pub fn validate(&self) -> Result<(), LimitError> {
        // 同時接続数: 1〜65536
        if !(1..=65536).contains(&self.max_connections) {
            return Err(LimitError::OutOfRange {
                parameter: "max_connections",
                value: self.max_connections as u64,
                min: 1,
                max: 65536,
            });
        }

        // ハンドシェイク中の同時接続数: 1〜1024
        if !(1..=1024).contains(&self.max_handshaking_connections) {
            return Err(LimitError::OutOfRange {
                parameter: "max_handshaking_connections",
                value: self.max_handshaking_connections as u64,
                min: 1,
                max: 1024,
            });
        }

        // 接続元ごとの同時接続数: 1〜1024
        if !(1..=1024).contains(&self.max_connections_per_source) {
            return Err(LimitError::OutOfRange {
                parameter: "max_connections_per_source",
                value: self.max_connections_per_source as u64,
                min: 1,
                max: 1024,
            });
        }

        // 接続元ごとのハンドシェイク中の接続数: 1〜64
        if !(1..=64).contains(&self.max_handshaking_per_source) {
            return Err(LimitError::OutOfRange {
                parameter: "max_handshaking_per_source",
                value: self.max_handshaking_per_source as u64,
                min: 1,
                max: 64,
            });
        }

        // 鍵交換と署名を同時に計算する数: 1〜64
        if !(1..=64).contains(&self.max_concurrent_crypto_tasks) {
            return Err(LimitError::OutOfRange {
                parameter: "max_concurrent_crypto_tasks",
                value: self.max_concurrent_crypto_tasks as u64,
                min: 1,
                max: 64,
            });
        }

        // ハンドシェイク全体の期限: 1〜60 秒
        if !(1..=60).contains(&self.handshake_timeout_secs) {
            return Err(LimitError::OutOfRange {
                parameter: "handshake_timeout_secs",
                value: self.handshake_timeout_secs,
                min: 1,
                max: 60,
            });
        }

        // アイドル期限: 5〜3600 秒
        if !(5..=3600).contains(&self.idle_timeout_secs) {
            return Err(LimitError::OutOfRange {
                parameter: "idle_timeout_secs",
                value: self.idle_timeout_secs,
                min: 5,
                max: 3600,
            });
        }

        // 書き込み期限: 1〜300 秒
        if !(1..=300).contains(&self.write_timeout_secs) {
            return Err(LimitError::OutOfRange {
                parameter: "write_timeout_secs",
                value: self.write_timeout_secs,
                min: 1,
                max: 300,
            });
        }

        // 上流接続期限: 1〜30 秒
        if !(1..=30).contains(&self.upstream_connect_timeout_secs) {
            return Err(LimitError::OutOfRange {
                parameter: "upstream_connect_timeout_secs",
                value: self.upstream_connect_timeout_secs,
                min: 1,
                max: 30,
            });
        }

        // メモリ見積もり: 同時接続数 × 64 KiB が 256 MiB を超える組み合わせは拒否
        let estimated_bytes =
            (self.max_connections as usize).saturating_mul(ESTIMATED_PER_CONN_MEMORY);
        if estimated_bytes > MAX_MEMORY_ESTIMATE_LIMIT {
            return Err(LimitError::MemoryBudgetExceeded {
                estimated_bytes,
                max_bytes: MAX_MEMORY_ESTIMATE_LIMIT,
            });
        }

        Ok(())
    }
}
