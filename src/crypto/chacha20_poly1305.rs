//! ChaCha20-Poly1305 AEAD 実装 (RFC 8439)

use super::chacha20::{chacha20_block, chacha20_xor};
use super::mod_common::ct_eq;
use super::poly1305::poly1305_mac;
use crate::alert::{AlertDescription, ShieldError};

pub fn chacha20_poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ShieldError> {
    // カウンタ 0 のブロックから最初の 32 バイトを取り出して一元 Poly1305 鍵とする
    let block0 = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block0[..32]);

    // カウンタ 1 から暗号化
    let ciphertext = chacha20_xor(key, 1, nonce, plaintext);

    // MAC 入力の構築: pad16(aad) || pad16(ct) || len_aad (8 バイト LE) || len_ct (8 バイト LE)
    let mut mac_data = Vec::with_capacity(aad.len() + 16 + ciphertext.len() + 16 + 16);
    mac_data.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    mac_data.resize(mac_data.len() + aad_pad, 0);

    mac_data.extend_from_slice(&ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    mac_data.resize(mac_data.len() + ct_pad, 0);

    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    let tag = poly1305_mac(&poly_key, &mac_data);

    let mut out = ciphertext;
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, ShieldError> {
    if ciphertext_and_tag.len() < 16 {
        return Err(ShieldError::Fatal(AlertDescription::BadRecordMac));
    }

    let ct_len = ciphertext_and_tag.len() - 16;
    let ciphertext = &ciphertext_and_tag[..ct_len];
    let expected_tag = &ciphertext_and_tag[ct_len..];

    // 一元 Poly1305 鍵
    let block0 = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block0[..32]);

    // MAC 入力の構築
    let mut mac_data = Vec::with_capacity(aad.len() + 16 + ciphertext.len() + 16 + 16);
    mac_data.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    mac_data.resize(mac_data.len() + aad_pad, 0);

    mac_data.extend_from_slice(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    mac_data.resize(mac_data.len() + ct_pad, 0);

    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    let computed_tag = poly1305_mac(&poly_key, &mac_data);

    // 定数時間照合
    if !ct_eq(&computed_tag, expected_tag) {
        return Err(ShieldError::Fatal(AlertDescription::BadRecordMac));
    }

    // カウンタ 1 から復号
    let plaintext = chacha20_xor(key, 1, nonce, ciphertext);
    Ok(plaintext)
}
