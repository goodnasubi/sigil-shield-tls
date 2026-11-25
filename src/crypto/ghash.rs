//! GHASH 実装 (GF(2^128) 演算)

/// GF(2^128) の要素間の乗算 (Z = X * H)
/// 各ビットごとのシフトと定数時間リダクション (多項式 x^128 + x^7 + x^2 + x + 1)
pub fn ghash_mul(x: &[u8; 16], h: &[u8; 16]) -> [u8; 16] {
    let mut z = 0u128;
    let mut v = u128::from_be_bytes(*h);
    let r: u128 = 0xe1000000000000000000000000000000;

    for &byte in x.iter() {
        for b in (0..8).rev() {
            let bit = (byte >> b) & 1;
            let mask = (bit as u128).wrapping_neg();
            z ^= v & mask;

            let carry = v & 1;
            let r_mask = carry.wrapping_neg();
            v = (v >> 1) ^ (r_mask & r);
        }
    }

    z.to_be_bytes()
}

/// GHASH 計算
pub fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // AAD のブロック処理
    let mut offset = 0;
    while offset < aad.len() {
        let mut block = [0u8; 16];
        let chunk_len = std::cmp::min(16, aad.len() - offset);
        block[..chunk_len].copy_from_slice(&aad[offset..offset + chunk_len]);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = ghash_mul(&y, h);
        offset += 16;
    }

    // 暗号文のブロック処理
    offset = 0;
    while offset < ciphertext.len() {
        let mut block = [0u8; 16];
        let chunk_len = std::cmp::min(16, ciphertext.len() - offset);
        block[..chunk_len].copy_from_slice(&ciphertext[offset..offset + chunk_len]);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = ghash_mul(&y, h);
        offset += 16;
    }

    // 長さブロック [len(AAD) in bits (64-bit BE) || len(C) in bits (64-bit BE)]
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ciphertext.len() as u64).wrapping_mul(8);
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());

    for i in 0..16 {
        y[i] ^= len_block[i];
    }
    ghash_mul(&y, h)
}
