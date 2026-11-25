//! ECDSA P-256 署名（RFC 6979 の決定的 nonce）の既知回答試験。
//!
//! 出典:
//! - 先頭の `sample` の組は RFC 6979 付録 A.2.5（P-256, SHA-256）の公開ベクタ。
//! - 他の組は、独立の RFC 6979 実装（Python）で署名し、別の実装（OpenSSL 3.0.13、
//!   Python `cryptography` 経由）で検証が通ったもの。

use sigil_shield_tls::crypto::{
    ecdsa_p256_public_key, ecdsa_p256_sign, ecdsa_p256_verify, scalar_in_range, signature_to_der,
    RawSignature,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn key(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

/// (秘密鍵, メッセージ, r, s, 公開鍵)
const VECTORS: &[(&str, &str, &str, &str, &str)] = &[
    ("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", "73616d706c65", "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716", "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8", "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"),
    ("0000000000000000000000000000000000000000000000000000000000000001", "74657374", "7ecc900ec818b3d8cfdc18f45de25dc953e1b9ae1a07a0d9cf8bd3f3e2c4bc86", "260e32d3a286ac502a62645d23a139398a9fe82f05de8e2e672a051a7c9cff9b", "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    ("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", "", "9a4460ec5a9484c194d61987c2d9bddb2ada0e708fdf51ae0fe5974d8580012d", "c3f2dbedc40a96ef521afd115ad45c3043e30d612fcdd411ec3833abd6715b4d", "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a"),
    ("6ab9f1eb8f7d3388f4f9d586f66e99fd54080df2c446f0e58668b09c08a16dd0", "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", "d17659586321cf6594591797269e4a53ca5756ea9b574bc80faf356d89d10d48", "965864757e350ae84f2c6c8134d273bfba850549a41ca9e70ea2007478889f65", "04be9ee19f365fee9d27ac8858a18d4f7527419062e2324938af15e7d234fa23f690682f89a1428bb8d67e3714395e620142783e6ec6b1976f6b8275160a17d0b9"),
    ("015f7e6bc5aeaf483724089e9252cc13b50951a6b69412522765cff4d780306e", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "c8e4cb78c32dedff15f02672ce719d8e4c777293c31287f85a0d2278531cd851", "6931c459ab04c8f84176522aed91a0e4b77185cfaf575328cca2412203f5d579", "04c0e7d9113804af675d9141ab1d6c3b0fba10423c76a2e01e99916bca4d7e3431089f7071d96da40399db1052b2bb2f510cf89009db80145402d0a02cc7879d13"),
];

#[test]
fn public_keys_match_independent_implementation() {
    for (d, _, _, _, public) in VECTORS {
        assert_eq!(hex(&ecdsa_p256_public_key(&key(d))), *public);
    }
}

#[test]
fn signatures_match_rfc6979_and_independent_vectors() {
    for (d, msg, r, s, _) in VECTORS {
        let sig = ecdsa_p256_sign(&key(d), &unhex(msg)).expect("署名できる");
        assert_eq!(hex(&sig.r), *r, "r (msg={msg})");
        assert_eq!(hex(&sig.s), *s, "s (msg={msg})");
    }
}

#[test]
fn der_encoding_is_minimal_and_positive() {
    // 先頭バイトが 0x80 以上の r は 0x00 を前置し、先頭が 0 の s は詰める
    let r = key("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    let s = key("007f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083");
    let der = signature_to_der(&sigil_shield_tls::crypto::RawSignature { r, s });
    let mut want = vec![0x30, 0x00];
    let mut body = vec![0x02, 0x21, 0x00];
    body.extend_from_slice(&r);
    body.extend_from_slice(&[0x02, 0x1f]);
    body.extend_from_slice(&s[1..]);
    want[1] = body.len() as u8;
    want.extend_from_slice(&body);
    assert_eq!(der, want);
    assert!(der.len() <= 72);
}

#[test]
fn private_scalar_range_check() {
    let n = key("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    assert!(!scalar_in_range(&[0u8; 32]));
    assert!(!scalar_in_range(&n));
    assert!(!scalar_in_range(&[0xff; 32]));
    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(scalar_in_range(&one));
    let n_minus_1 = key("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");
    assert!(scalar_in_range(&n_minus_1));
}

#[test]
fn verify_accepts_independent_signatures_and_rejects_changes() {
    for (_, msg, r, s, public) in VECTORS {
        let public: [u8; 65] = unhex(public).try_into().unwrap();
        let sig = RawSignature {
            r: key(r),
            s: key(s),
        };
        let msg = unhex(msg);
        assert!(ecdsa_p256_verify(&public, &msg, &sig));
        // メッセージ・r・s・公開鍵のどれを変えても通らない
        let mut other = msg.clone();
        other.push(0);
        assert!(!ecdsa_p256_verify(&public, &other, &sig));
        let mut bad = RawSignature { r: sig.r, s: sig.s };
        bad.r[31] ^= 1;
        assert!(!ecdsa_p256_verify(&public, &msg, &bad));
        let mut bad = RawSignature { r: sig.r, s: sig.s };
        bad.s[0] ^= 1;
        assert!(!ecdsa_p256_verify(&public, &msg, &bad));
        let mut off_curve = public;
        off_curve[64] ^= 1;
        assert!(!ecdsa_p256_verify(&off_curve, &msg, &sig));
        // r = 0 / s = 0
        let zero = RawSignature {
            r: [0; 32],
            s: sig.s,
        };
        assert!(!ecdsa_p256_verify(&public, &msg, &zero));
    }
}
