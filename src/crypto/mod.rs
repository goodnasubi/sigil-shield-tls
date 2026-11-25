//! 暗号モジュール (`src/crypto/`)
//!
//! ADR 0063 段 2:
//! - SHA-256 および SHA-384
//! - HMAC-SHA-256 および HMAC-SHA-384
//! - HKDF (Extract, Expand, Expand-Label)
//! - AES-128 / AES-256（定数時間 S-box、GF(2^8) 逆元計算ベース）
//! - GHASH (GF(2^128))
//! - AES-128-GCM / AES-256-GCM
//! - ChaCha20
//! - Poly1305
//! - ChaCha20-Poly1305 AEAD

pub mod aes;
pub mod chacha20;
pub mod chacha20_poly1305;
pub mod gcm;
pub mod ghash;
pub mod hkdf;
pub mod hmac;
pub mod mod_common;
pub mod poly1305;
pub mod sha256;
pub mod sha384;

pub use aes::{aes_encrypt_block, aes_expand_key, aes_gmul, aes_sbox, aes_xtime};
pub use chacha20::{chacha20_block, chacha20_xor};
pub use chacha20_poly1305::{chacha20_poly1305_open, chacha20_poly1305_seal};
pub use gcm::{aes_gcm_open, aes_gcm_seal};
pub use ghash::{ghash, ghash_mul};
pub use hkdf::{
    build_hkdf_label, hkdf_expand_label_sha256, hkdf_expand_label_sha384, hkdf_expand_sha256,
    hkdf_expand_sha384, hkdf_extract_sha256, hkdf_extract_sha384,
};
pub use hmac::{hmac_sha256, hmac_sha384};
pub use mod_common::ct_eq;
pub use poly1305::poly1305_mac;
pub use sha256::{sha256, Sha256};
pub use sha384::{sha384, Sha384};
