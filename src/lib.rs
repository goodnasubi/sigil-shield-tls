//! sigil-shield-tls
//!
//! TLS termination component for Sigil services.
//! ADR 0063 段 1〜3: 入口の解析、鍵スケジュールと保護レコード、ハンドシェイクの状態機械

pub mod alert;
pub mod cipher_suite;
pub mod client_hello;
pub mod crypto;
pub mod curve;
pub mod handshake;
pub mod key_schedule;
pub mod key_update;
pub mod limits;
pub mod record;
pub mod record_crypto;

pub use alert::{Alert, AlertDescription, AlertLevel, ShieldError};
pub use cipher_suite::{select_cipher_suite, CipherSuite, SERVER_PREFERENCE_ORDER};
pub use client_hello::{parse_client_hello, ClientHello, KeyShareEntry, ServerName};
pub use handshake::{
    EcdsaP256Signer, HandshakeOutcome, KeyAgreement, KeyAgreementOutput, RandomSource,
    ServerConfig, ServerHandshake, Signer, X25519Agreement,
};
pub use key_schedule::KeySchedule;
pub use key_update::{KeyUpdateRequest, KeyUpdateTracker, KEY_UPDATE_TX_LIMIT};
pub use limits::{LimitError, ShieldLimits};
pub use record::{parse_record_header, ContentType, HandshakeReassembler, RecordHeader};
pub use record_crypto::{make_nonce, RecordDirection, RecordProtection};
