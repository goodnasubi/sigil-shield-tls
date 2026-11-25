//! 暗号スイート定義と選択 (ADR 0063 決定 1, RFC 8446 §B.4)
//!
//! 3 スイート対応:
//! - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
//! - TLS_AES_128_GCM_SHA256 (0x1301)
//! - TLS_AES_256_GCM_SHA384 (0x1302)
//!
//! サーバー優先順: ChaCha20-Poly1305 > AES-128-GCM > AES-256-GCM

use crate::alert::{AlertDescription, ShieldError};
use crate::crypto::{aes_gcm_open, aes_gcm_seal, chacha20_poly1305_open, chacha20_poly1305_seal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TlsChacha20Poly1305Sha256,
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
}

impl CipherSuite {
    pub const TLS_AES_128_GCM_SHA256_CODE: u16 = 0x1301;
    pub const TLS_AES_256_GCM_SHA384_CODE: u16 = 0x1302;
    pub const TLS_CHACHA20_POLY1305_SHA256_CODE: u16 = 0x1303;

    pub fn from_u16(code: u16) -> Option<Self> {
        match code {
            Self::TLS_CHACHA20_POLY1305_SHA256_CODE => Some(Self::TlsChacha20Poly1305Sha256),
            Self::TLS_AES_128_GCM_SHA256_CODE => Some(Self::TlsAes128GcmSha256),
            Self::TLS_AES_256_GCM_SHA384_CODE => Some(Self::TlsAes256GcmSha384),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            Self::TlsChacha20Poly1305Sha256 => Self::TLS_CHACHA20_POLY1305_SHA256_CODE,
            Self::TlsAes128GcmSha256 => Self::TLS_AES_128_GCM_SHA256_CODE,
            Self::TlsAes256GcmSha384 => Self::TLS_AES_256_GCM_SHA384_CODE,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::TlsChacha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
            Self::TlsAes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            Self::TlsAes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
        }
    }

    /// AEAD 鍵長 (バイト)
    pub fn key_len(&self) -> usize {
        match self {
            Self::TlsChacha20Poly1305Sha256 => 32,
            Self::TlsAes128GcmSha256 => 16,
            Self::TlsAes256GcmSha384 => 32,
        }
    }

    /// AEAD IV 長 (バイト、TLS 1.3 では常に 12 バイト)
    pub fn iv_len(&self) -> usize {
        12
    }

    /// AEAD 認証タグ長 (バイト、常に 16 バイト)
    pub fn tag_len(&self) -> usize {
        16
    }

    /// ハッシュ出力長 (バイト)
    pub fn hash_len(&self) -> usize {
        match self {
            Self::TlsChacha20Poly1305Sha256 => 32,
            Self::TlsAes128GcmSha256 => 32,
            Self::TlsAes256GcmSha384 => 48,
        }
    }

    /// AEAD 暗号化
    pub fn seal(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ShieldError> {
        match self {
            Self::TlsChacha20Poly1305Sha256 => {
                let k: &[u8; 32] = key
                    .try_into()
                    .map_err(|_| ShieldError::Fatal(AlertDescription::InternalError))?;
                chacha20_poly1305_seal(k, iv, aad, plaintext)
            }
            Self::TlsAes128GcmSha256 | Self::TlsAes256GcmSha384 => {
                aes_gcm_seal(key, iv, aad, plaintext)
            }
        }
    }

    /// AEAD 復号および認証
    pub fn open(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, ShieldError> {
        match self {
            Self::TlsChacha20Poly1305Sha256 => {
                let k: &[u8; 32] = key
                    .try_into()
                    .map_err(|_| ShieldError::Fatal(AlertDescription::InternalError))?;
                chacha20_poly1305_open(k, iv, aad, ciphertext_and_tag)
            }
            Self::TlsAes128GcmSha256 | Self::TlsAes256GcmSha384 => {
                aes_gcm_open(key, iv, aad, ciphertext_and_tag)
            }
        }
    }
}

/// サーバー側の優先順位リスト（ADR 0063 決定 1）:
/// ソフトウェアでの定数時間実装において ChaCha20 が高速な見込みのため最優先
pub const SERVER_PREFERENCE_ORDER: &[CipherSuite] = &[
    CipherSuite::TlsChacha20Poly1305Sha256,
    CipherSuite::TlsAes128GcmSha256,
    CipherSuite::TlsAes256GcmSha384,
];

/// クライアントが提示した暗号スイート一覧から、サーバー優先順に基づき最初の 1 つを選択する
pub fn select_cipher_suite(client_suites: &[u16]) -> Result<CipherSuite, ShieldError> {
    for &server_suite in SERVER_PREFERENCE_ORDER {
        if client_suites.contains(&server_suite.as_u16()) {
            return Ok(server_suite);
        }
    }
    Err(ShieldError::Fatal(AlertDescription::HandshakeFailure))
}
