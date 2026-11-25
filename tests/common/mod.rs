//! テスト用のヘルパー（正常な ClientHello の構築など）
#![allow(dead_code)]

pub mod fuzz;

use sigil_shield_tls::client_hello::{extension_type, named_group};

/// 最小限の正常な TLS 1.3 ClientHello バイト列（ハンドシェイクヘッダ含む）を構築する
pub fn build_valid_client_hello() -> Vec<u8> {
    let mut payload = Vec::new();

    // legacy_version: 0x0303
    payload.extend_from_slice(&[0x03, 0x03]);

    // random: 32 bytes
    payload.extend_from_slice(&[0x42; 32]);

    // legacy_session_id: 32 bytes
    payload.push(32);
    payload.extend_from_slice(&[0x11; 32]);

    // cipher_suites: 3 suites (6 bytes)
    // TLS_CHACHA20_POLY1305_SHA256 (0x1303), TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
    payload.extend_from_slice(&[0x00, 0x06]);
    payload.extend_from_slice(&[0x13, 0x03, 0x13, 0x01, 0x13, 0x02]);

    // legacy_compression_methods: [0x01, 0x00]
    payload.extend_from_slice(&[0x01, 0x00]);

    // 拡張部
    let mut extensions = Vec::new();

    // 1. supported_versions (0x002b)
    // list_len = 2, versions = [0x0304]
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

    // 2. server_name (0x0000)
    // host_name: "example.com" (11 bytes)
    // name_entry: 0x00 (type), 0x00, 0x0b (11), "example.com" -> 14 bytes
    // list_len: 14 bytes -> 0x00, 0x0e
    // ext_len: 16 bytes -> 0x00, 0x10
    let host = b"example.com";
    let sn_list_len = (3 + host.len()) as u16;
    extensions.extend_from_slice(&extension_type::SERVER_NAME.to_be_bytes());
    extensions.extend_from_slice(&(sn_list_len + 2).to_be_bytes());
    extensions.extend_from_slice(&sn_list_len.to_be_bytes());
    extensions.push(0x00); // host_name
    extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host);

    // 3. supported_groups (0x000a)
    // x25519 (0x001d), secp256r1 (0x0017) -> 4 bytes
    extensions.extend_from_slice(&extension_type::SUPPORTED_GROUPS.to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

    // 4. key_share (0x0033)
    // x25519 (0x001d) share: 32 bytes
    let key_data = [0x99; 32];
    let share_len = (4 + key_data.len()) as u16;
    extensions.extend_from_slice(&extension_type::KEY_SHARE.to_be_bytes());
    extensions.extend_from_slice(&(share_len + 2).to_be_bytes());
    extensions.extend_from_slice(&share_len.to_be_bytes());
    extensions.extend_from_slice(&named_group::X25519.to_be_bytes());
    extensions.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_data);

    // 5. signature_algorithms (0x000d)
    // ecdsa_secp256r1_sha256 (0x0403)
    extensions.extend_from_slice(&extension_type::SIGNATURE_ALGORITHMS.to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x04, 0x00, 0x02, 0x04, 0x03]);

    // 6. ALPN (0x0010)
    // "http/1.1" (8 bytes) -> entry: 1 + 8 = 9 bytes
    extensions
        .extend_from_slice(&extension_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION.to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x09, 0x08]);
    extensions.extend_from_slice(b"http/1.1");

    // 拡張全体の長さを付加
    payload.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    payload.extend_from_slice(&extensions);

    // ハンドシェイクヘッダ（4 バイト: HandshakeType 1 byte + Length 3 bytes）
    let mut msg = Vec::new();
    msg.push(0x01); // ClientHello
    let len = payload.len();
    msg.push(((len >> 16) & 0xFF) as u8);
    msg.push(((len >> 8) & 0xFF) as u8);
    msg.push((len & 0xFF) as u8);
    msg.extend_from_slice(&payload);

    msg
}

/// TLS レコードにラップする（5 バイトヘッダ付加）
pub fn wrap_in_record(content_type: u8, version: u16, payload: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + payload.len());
    rec.push(content_type);
    rec.extend_from_slice(&version.to_be_bytes());
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(payload);
    rec
}
