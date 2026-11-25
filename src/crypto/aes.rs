//! AES ブロック暗号 (AES-128 / AES-256)
//!
//! 定数時間 S-box（GF(2^8) 逆元計算 x^254 およびアフィン変換ベース、表引きなし）

/// GF(2^8) での 2 倍 (xtime) - 既約多項式 x^8 + x^4 + x^3 + x + 1
#[inline(always)]
pub fn aes_xtime(v: u8) -> u8 {
    let hi = (v >> 7) & 1;
    (v << 1) ^ (hi.wrapping_neg() & 0x1b)
}

/// GF(2^8) 乗算（8 ステップ固定、定数時間）
#[inline(always)]
pub fn aes_gmul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut x = a;
    let mut y = b;
    for _ in 0..8 {
        let m = (y & 1).wrapping_neg();
        p ^= x & m;
        x = aes_xtime(x);
        y >>= 1;
    }
    p
}

/// 定数時間 S-box: 表引きを使わず GF(2^8) の逆元 x^254 を計算しアフィン変換を適用
#[inline(always)]
pub fn aes_sbox(x: u8) -> u8 {
    let x2 = aes_gmul(x, x);
    let x4 = aes_gmul(x2, x2);
    let x8 = aes_gmul(x4, x4);
    let x16 = aes_gmul(x8, x8);
    let x32 = aes_gmul(x16, x16);
    let x64 = aes_gmul(x32, x32);
    let x128 = aes_gmul(x64, x64);

    let mut inv = aes_gmul(x2, x4);
    inv = aes_gmul(inv, x8);
    inv = aes_gmul(inv, x16);
    inv = aes_gmul(inv, x32);
    inv = aes_gmul(inv, x64);
    inv = aes_gmul(inv, x128);

    let r1 = inv.rotate_left(1);
    let r2 = inv.rotate_left(2);
    let r3 = inv.rotate_left(3);
    let r4 = inv.rotate_left(4);

    inv ^ r1 ^ r2 ^ r3 ^ r4 ^ 0x63
}

/// 鍵展開（16 バイトまたは 32 バイト鍵）
pub fn aes_expand_key(key: &[u8]) -> Vec<u8> {
    let nk = key.len() / 4;
    assert!(nk == 4 || nk == 8);
    let total_words = 4 * (nk + 7); // 44 words (176 bytes) for AES-128, 60 words (240 bytes) for AES-256
    let mut w = Vec::with_capacity(total_words * 4);
    w.extend_from_slice(key);

    let mut rc = 1u8;
    let mut n = nk;
    let mut ctr = 0;

    while n < total_words {
        let p = (n - 1) * 4;
        let mut t0 = w[p];
        let mut t1 = w[p + 1];
        let mut t2 = w[p + 2];
        let mut t3 = w[p + 3];

        if ctr == 0 {
            let u0 = aes_sbox(t1) ^ rc;
            let u1 = aes_sbox(t2);
            let u2 = aes_sbox(t3);
            let u3 = aes_sbox(t0);
            t0 = u0;
            t1 = u1;
            t2 = u2;
            t3 = u3;
            rc = aes_xtime(rc);
        }

        if nk == 8 && ctr == 4 {
            t0 = aes_sbox(t0);
            t1 = aes_sbox(t1);
            t2 = aes_sbox(t2);
            t3 = aes_sbox(t3);
        }

        let q = (n - nk) * 4;
        w.push(w[q] ^ t0);
        w.push(w[q + 1] ^ t1);
        w.push(w[q + 2] ^ t2);
        w.push(w[q + 3] ^ t3);

        ctr += 1;
        if ctr == nk {
            ctr = 0;
        }
        n += 1;
    }

    w
}

/// 16 バイトブロックの AES 暗号化
pub fn aes_encrypt_block(round_keys: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let mut s = [0u8; 16];
    for i in 0..16 {
        s[i] = block[i] ^ round_keys[i];
    }

    let nr = round_keys.len() / 16 - 1; // 10 for AES-128, 14 for AES-256
    for round in 1..=nr {
        let mut t = [0u8; 16];
        for c in 0..4 {
            for r in 0..4 {
                let idx = r + 4 * ((c + r) % 4);
                t[c * 4 + r] = aes_sbox(s[idx]);
            }
        }

        let mut u = t;
        if round < nr {
            for col in 0..4 {
                let a0 = t[col * 4];
                let a1 = t[col * 4 + 1];
                let a2 = t[col * 4 + 2];
                let a3 = t[col * 4 + 3];

                u[col * 4] = aes_xtime(a0) ^ aes_xtime(a1) ^ a1 ^ a2 ^ a3;
                u[col * 4 + 1] = a0 ^ aes_xtime(a1) ^ aes_xtime(a2) ^ a2 ^ a3;
                u[col * 4 + 2] = a0 ^ a1 ^ aes_xtime(a2) ^ aes_xtime(a3) ^ a3;
                u[col * 4 + 3] = aes_xtime(a0) ^ a0 ^ a1 ^ a2 ^ aes_xtime(a3);
            }
        }

        let rk_offset = round * 16;
        for k in 0..16 {
            s[k] = u[k] ^ round_keys[rk_offset + k];
        }
    }

    s
}
