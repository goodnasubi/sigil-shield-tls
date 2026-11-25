//! AES-GCM AEAD 実装 (AES-128-GCM, AES-256-GCM)
//! 96 ビット IV、128 ビット認証タグ、定数時間タグ照合

use super::aes::{aes_encrypt_block, aes_expand_key};
use super::ghash::ghash;
use super::mod_common::ct_eq;
use crate::alert::{AlertDescription, ShieldError};

pub fn aes_gcm_seal(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ShieldError> {
    assert!(key.len() == 16 || key.len() == 32);
    let round_keys = aes_expand_key(key);

    // H = AES_K(0^16)
    let zero_block = [0u8; 16];
    let h = aes_encrypt_block(&round_keys, &zero_block);

    // J0 = IV || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;

    // tag_mask = AES_K(J0)
    let tag_mask = aes_encrypt_block(&round_keys, &j0);

    // CTR モードでの暗号化 (カウンタは J0 + 1 から開始)
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
    let mut counter_val = 1u32;
    let mut offset = 0;

    while offset < plaintext.len() {
        counter_val = counter_val.wrapping_add(1);
        let mut cb = [0u8; 16];
        cb[..12].copy_from_slice(iv);
        cb[12..16].copy_from_slice(&counter_val.to_be_bytes());

        let keystream = aes_encrypt_block(&round_keys, &cb);
        let chunk_len = std::cmp::min(16, plaintext.len() - offset);
        for i in 0..chunk_len {
            ciphertext.push(plaintext[offset + i] ^ keystream[i]);
        }
        offset += chunk_len;
    }

    // GHASH で認証タグを計算
    let s = ghash(&h, aad, &ciphertext);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ tag_mask[i];
    }

    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

pub fn aes_gcm_open(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, ShieldError> {
    if ciphertext_and_tag.len() < 16 {
        return Err(ShieldError::Fatal(AlertDescription::BadRecordMac));
    }
    assert!(key.len() == 16 || key.len() == 32);

    let ciphertext_len = ciphertext_and_tag.len() - 16;
    let ciphertext = &ciphertext_and_tag[..ciphertext_len];
    let expected_tag = &ciphertext_and_tag[ciphertext_len..];

    let round_keys = aes_expand_key(key);

    // H = AES_K(0^16)
    let zero_block = [0u8; 16];
    let h = aes_encrypt_block(&round_keys, &zero_block);

    // J0 = IV || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;

    // tag_mask = AES_K(J0)
    let tag_mask = aes_encrypt_block(&round_keys, &j0);

    // GHASH でタグを計算
    let s = ghash(&h, aad, ciphertext);
    let mut computed_tag = [0u8; 16];
    for i in 0..16 {
        computed_tag[i] = s[i] ^ tag_mask[i];
    }

    // 定数時間タグ照合
    if !ct_eq(&computed_tag, expected_tag) {
        return Err(ShieldError::Fatal(AlertDescription::BadRecordMac));
    }

    // CTR モードでの復号 (カウンタは J0 + 1 から開始)
    let mut plaintext = Vec::with_capacity(ciphertext_len);
    let mut counter_val = 1u32;
    let mut offset = 0;

    while offset < ciphertext_len {
        counter_val = counter_val.wrapping_add(1);
        let mut cb = [0u8; 16];
        cb[..12].copy_from_slice(iv);
        cb[12..16].copy_from_slice(&counter_val.to_be_bytes());

        let keystream = aes_encrypt_block(&round_keys, &cb);
        let chunk_len = std::cmp::min(16, ciphertext_len - offset);
        for i in 0..chunk_len {
            plaintext.push(ciphertext[offset + i] ^ keystream[i]);
        }
        offset += chunk_len;
    }

    Ok(plaintext)
}
