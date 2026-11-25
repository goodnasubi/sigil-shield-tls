//! sigil-shield-tls
//!
//! TLS termination component for Sigil services.
//! ADR 0063 段 1: 入口の解析（レコード層、ClientHello、アラート、上限）

pub mod alert;
pub mod client_hello;
pub mod curve;
pub mod limits;
pub mod record;

pub use alert::{Alert, AlertDescription, AlertLevel, ShieldError};
pub use client_hello::{parse_client_hello, ClientHello, KeyShareEntry, ServerName};
pub use limits::{LimitError, ShieldLimits};
pub use record::{parse_record_header, ContentType, HandshakeReassembler, RecordHeader};
