//! HKDF 実装 (RFC 5869, RFC 8446 §7.1)

use super::hmac::{hmac_sha256, hmac_sha384};

pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let default_salt = [0u8; 32];
    let actual_salt = if salt.is_empty() {
        &default_salt[..]
    } else {
        salt
    };
    hmac_sha256(actual_salt, ikm)
}

pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    assert!(out_len <= 255 * 32);
    let mut okm = Vec::with_capacity(out_len);
    let mut t = [0u8; 32];
    let mut step = 0u8;

    while okm.len() < out_len {
        step += 1;
        let mut msg = Vec::with_capacity(if step == 1 { 0 } else { 32 } + info.len() + 1);
        if step > 1 {
            msg.extend_from_slice(&t);
        }
        msg.extend_from_slice(info);
        msg.push(step);

        t = hmac_sha256(prk, &msg);
        let needed = out_len - okm.len();
        if needed < 32 {
            okm.extend_from_slice(&t[..needed]);
        } else {
            okm.extend_from_slice(&t);
        }
    }

    okm
}

pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let default_salt = [0u8; 48];
    let actual_salt = if salt.is_empty() {
        &default_salt[..]
    } else {
        salt
    };
    hmac_sha384(actual_salt, ikm)
}

pub fn hkdf_expand_sha384(prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    assert!(out_len <= 255 * 48);
    let mut okm = Vec::with_capacity(out_len);
    let mut t = [0u8; 48];
    let mut step = 0u8;

    while okm.len() < out_len {
        step += 1;
        let mut msg = Vec::with_capacity(if step == 1 { 0 } else { 48 } + info.len() + 1);
        if step > 1 {
            msg.extend_from_slice(&t);
        }
        msg.extend_from_slice(info);
        msg.push(step);

        t = hmac_sha384(prk, &msg);
        let needed = out_len - okm.len();
        if needed < 48 {
            okm.extend_from_slice(&t[..needed]);
        } else {
            okm.extend_from_slice(&t);
        }
    }

    okm
}

/// HkdfLabel 構造体のバイト列を構築する (RFC 8446 §7.1)
/// ラベルに "tls13 " プレフィックスを付与する
pub fn build_hkdf_label(length: u16, label: &str, context: &[u8]) -> Vec<u8> {
    let prefix = b"tls13 ";
    let full_label_len = prefix.len() + label.len();
    assert!(full_label_len <= 255);
    assert!(context.len() <= 255);

    let mut out = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.push(full_label_len as u8);
    out.extend_from_slice(prefix);
    out.extend_from_slice(label.as_bytes());
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}

pub fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &str,
    context: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let hkdf_label = build_hkdf_label(out_len as u16, label, context);
    hkdf_expand_sha256(secret, &hkdf_label, out_len)
}

pub fn hkdf_expand_label_sha384(
    secret: &[u8],
    label: &str,
    context: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let hkdf_label = build_hkdf_label(out_len as u16, label, context);
    hkdf_expand_sha384(secret, &hkdf_label, out_len)
}
