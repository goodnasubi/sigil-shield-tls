//! TLS アラート（ADR 0063 決定 4.1、RFC 8446 §6）
//!
//! 解釈の誤りは致命的アラートと接続の終了にする。続行（fail-open）や後段への転送はしない。

use std::fmt;

/// アラートの深刻度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

/// アラート記述子（RFC 8446 §6.2）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    HandshakeFailure = 40,
    IllegalParameter = 47,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InternalError = 80,
    UnrecognizedName = 112,
    NoApplicationProtocol = 120,
}

impl AlertDescription {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CloseNotify),
            10 => Some(Self::UnexpectedMessage),
            20 => Some(Self::BadRecordMac),
            40 => Some(Self::HandshakeFailure),
            47 => Some(Self::IllegalParameter),
            50 => Some(Self::DecodeError),
            51 => Some(Self::DecryptError),
            70 => Some(Self::ProtocolVersion),
            80 => Some(Self::InternalError),
            112 => Some(Self::UnrecognizedName),
            120 => Some(Self::NoApplicationProtocol),
            _ => None,
        }
    }
}

/// TLS アラートメッセージ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    /// 致命的アラートを作成する
    pub fn fatal(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }

    /// アラートを TLS レコード層のバイト列（7 バイト）にエンコードする
    ///
    /// レコード形式:
    /// - 1 バイト: レコード種別 (0x15 = alert)
    /// - 2 バイト: 旧版 (0x0303 = TLS 1.2 互換表記)
    /// - 2 バイト: レコード長 (0x0002)
    /// - 1 バイト: アラート深刻度 (1 = warning, 2 = fatal)
    /// - 1 バイト: アラート記述子
    pub fn to_record_bytes(&self) -> [u8; 7] {
        [
            0x15, // ContentType::alert
            0x03,
            0x03, // legacy_record_version: TLS 1.2
            0x00,
            0x02, // length: 2 bytes
            self.level as u8,
            self.description as u8,
        ]
    }
}

/// sigil-shield-tls のエラー型
///
/// すべてのパース誤りや不整合は致命的アラートと接続の切断に結びつく。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldError {
    /// 致命的アラートを送信して接続を終了する
    Fatal(AlertDescription),
    /// 不完全なデータ（まだ必要なバイト数に達していない）
    Incomplete { needed: usize },
    /// 読み取りが前進しない、あるいは期限切れ
    TimeoutOrNoProgress,
    /// 接続切断
    ConnectionClosed,
}

impl ShieldError {
    pub fn decode_error() -> Self {
        Self::Fatal(AlertDescription::DecodeError)
    }

    pub fn illegal_parameter() -> Self {
        Self::Fatal(AlertDescription::IllegalParameter)
    }

    pub fn unexpected_message() -> Self {
        Self::Fatal(AlertDescription::UnexpectedMessage)
    }

    pub fn decrypt_error() -> Self {
        Self::Fatal(AlertDescription::DecryptError)
    }

    pub fn protocol_version() -> Self {
        Self::Fatal(AlertDescription::ProtocolVersion)
    }

    pub fn handshake_failure() -> Self {
        Self::Fatal(AlertDescription::HandshakeFailure)
    }

    pub fn unrecognized_name() -> Self {
        Self::Fatal(AlertDescription::UnrecognizedName)
    }

    pub fn no_application_protocol() -> Self {
        Self::Fatal(AlertDescription::NoApplicationProtocol)
    }

    pub fn internal_error() -> Self {
        Self::Fatal(AlertDescription::InternalError)
    }

    /// 送信すべき致命的アラートを取得する（存在する場合）
    pub fn fatal_alert(&self) -> Option<Alert> {
        match self {
            Self::Fatal(desc) => Some(Alert::fatal(*desc)),
            _ => None,
        }
    }
}

impl fmt::Display for ShieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fatal(desc) => write!(f, "fatal alert: {:?}", desc),
            Self::Incomplete { needed } => {
                write!(f, "incomplete input, needed at least {} bytes", needed)
            }
            Self::TimeoutOrNoProgress => write!(f, "timeout or read made no progress"),
            Self::ConnectionClosed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for ShieldError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_encoding() {
        let alert = Alert::fatal(AlertDescription::DecodeError);
        let bytes = alert.to_record_bytes();
        assert_eq!(bytes, [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50]);
    }

    #[test]
    fn test_alert_description_conversion() {
        assert_eq!(
            AlertDescription::from_u8(50),
            Some(AlertDescription::DecodeError)
        );
        assert_eq!(
            AlertDescription::from_u8(47),
            Some(AlertDescription::IllegalParameter)
        );
        assert_eq!(AlertDescription::from_u8(99), None);
    }
}
