//! P-256 (secp256r1) 曲線上の点の検証（ADR 0063 決定 4.3）
//!
//! 暗号化や鍵交換は行わず、ClientHello の key_share に提示された公開点が
//! 曲線 y^2 = x^3 - 3x + b (mod p) 上にあるかを検証する。

/// secp256r1 の素数 p: 2^256 - 2^224 + 2^192 + 2^96 - 1
/// 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
pub const P256_P: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// 係数 b: 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
pub const P256_B: [u64; 4] = [
    0x3BCE_3C3E_27D2_604B,
    0x651D_06B0_CC53_B0F6,
    0xB3EB_BD55_7698_86BC,
    0x5AC6_35D8_AA3A_93E7,
];

/// 256 ビット符号なし整数（リトルエンディアン: words[0] が最下位）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// ビッグエンディアンの 32 バイトから U256 を生成
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut words = [0u64; 4];
        for (i, word) in words.iter_mut().enumerate() {
            let offset = (3 - i) * 8;
            *word = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        }
        Self(words)
    }

    /// self < other
    pub fn lt(&self, other: &Self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] < other.0[i] {
                return true;
            } else if self.0[i] > other.0[i] {
                return false;
            }
        }
        false
    }
}

/// 512 ビット整数（乗算の中間結果用）
#[derive(Debug, Clone, Copy)]
struct U512([u64; 8]);

impl U512 {
    const ZERO: Self = Self([0; 8]);

    fn shl1(&mut self) -> bool {
        let mut carry = 0u64;
        for w in &mut self.0 {
            let next_carry = *w >> 63;
            *w = (*w << 1) | carry;
            carry = next_carry;
        }
        carry != 0
    }
}

/// 256 ビット乗算: a * b -> U512
fn mul256(a: &U256, b: &U256) -> U512 {
    let mut res = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let prod = (a.0[i] as u128) * (b.0[j] as u128) + (res[i + j] as u128) + carry;
            res[i + j] = prod as u64;
            carry = prod >> 64;
        }
        res[i + 4] = carry as u64;
    }
    U512(res)
}

/// 512 ビット値を P-256 素数 p で割った余りを計算する（U512 mod p -> U256）
fn rem_p(val: &U512) -> U256 {
    let p = U256(P256_P);
    let rem = *val;

    // ビットシフト減算法で確実に mod p を求める
    // 512 ビットの最上位から p を引き算
    let mut quotient_remainder = U512::ZERO;

    for i in (0..512).rev() {
        let word_idx = i / 64;
        let bit_idx = i % 64;
        let bit = (rem.0[word_idx] >> bit_idx) & 1;

        quotient_remainder.shl1();
        quotient_remainder.0[0] |= bit;

        // もし quotient_remainder >= p (最上位比較)
        // ここで quotient_remainder は最大 257 ビットになるので、
        // 下位 4 ワードと 5 ワード目を見て p を引く
        let top_word = quotient_remainder.0[4];
        let mut should_sub = top_word > 0;
        if !should_sub {
            let cur_rem = U256([
                quotient_remainder.0[0],
                quotient_remainder.0[1],
                quotient_remainder.0[2],
                quotient_remainder.0[3],
            ]);
            should_sub = !cur_rem.lt(&p);
        }

        if should_sub {
            let mut borrow = 0u128;
            for j in 0..4 {
                let diff = (quotient_remainder.0[j] as u128)
                    .wrapping_sub(p.0[j] as u128)
                    .wrapping_sub(borrow);
                quotient_remainder.0[j] = diff as u64;
                borrow = (diff >> 127) & 1;
            }
            quotient_remainder.0[4] = quotient_remainder.0[4].wrapping_sub(borrow as u64);
        }
    }

    U256([
        quotient_remainder.0[0],
        quotient_remainder.0[1],
        quotient_remainder.0[2],
        quotient_remainder.0[3],
    ])
}

/// (a + b) mod p
pub fn add_mod_p(a: &U256, b: &U256) -> U256 {
    let p = U256(P256_P);
    let mut sum = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = (a.0[i] as u128) + (b.0[i] as u128) + carry;
        sum[i] = s as u64;
        carry = s >> 64;
    }
    let res = U256(sum);
    if carry > 0 || !res.lt(&p) {
        let mut diff = [0u64; 4];
        let mut borrow = 0u128;
        for i in 0..4 {
            let d = (sum[i] as u128)
                .wrapping_sub(p.0[i] as u128)
                .wrapping_sub(borrow);
            diff[i] = d as u64;
            borrow = (d >> 127) & 1;
        }
        U256(diff)
    } else {
        res
    }
}

/// (a - b) mod p
pub fn sub_mod_p(a: &U256, b: &U256) -> U256 {
    let p = U256(P256_P);
    if a.lt(b) {
        // (a + p) - b
        let a_plus_p = {
            let mut sum = [0u64; 4];
            let mut carry = 0u128;
            for i in 0..4 {
                let s = (a.0[i] as u128) + (p.0[i] as u128) + carry;
                sum[i] = s as u64;
                carry = s >> 64;
            }
            sum
        };
        let mut diff = [0u64; 4];
        let mut borrow = 0u128;
        for i in 0..4 {
            let d = (a_plus_p[i] as u128)
                .wrapping_sub(b.0[i] as u128)
                .wrapping_sub(borrow);
            diff[i] = d as u64;
            borrow = (d >> 127) & 1;
        }
        U256(diff)
    } else {
        let mut diff = [0u64; 4];
        let mut borrow = 0u128;
        for i in 0..4 {
            let d = (a.0[i] as u128)
                .wrapping_sub(b.0[i] as u128)
                .wrapping_sub(borrow);
            diff[i] = d as u64;
            borrow = (d >> 127) & 1;
        }
        U256(diff)
    }
}

/// (a * b) mod p
pub fn mul_mod_p(a: &U256, b: &U256) -> U256 {
    let prod = mul256(a, b);
    rem_p(&prod)
}

/// 65 バイトの非圧縮 secp256r1 公開点（0x04 || X || Y）が曲線上の点であるか判定する。
///
/// 判定条件:
/// 1. 先頭が 0x04 であること。
/// 2. 0 <= X < p かつ 0 <= Y < p であること。
/// 3. y^2 = x^3 - 3*x + b (mod p) が成立すること。
pub fn is_secp256r1_point_on_curve(point: &[u8]) -> bool {
    if point.len() != 65 || point[0] != 0x04 {
        return false;
    }

    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&point[1..33]);
    y_bytes.copy_from_slice(&point[33..65]);

    let x = U256::from_be_bytes(&x_bytes);
    let y = U256::from_be_bytes(&y_bytes);
    let p = U256(P256_P);

    // x, y < p
    if !x.lt(&p) || !y.lt(&p) {
        return false;
    }

    // left = y^2 mod p
    let left = mul_mod_p(&y, &y);

    // right = (x^3 - 3x + b) mod p
    let x2 = mul_mod_p(&x, &x);
    let x3 = mul_mod_p(&x2, &x);

    let three = U256([3, 0, 0, 0]);
    let three_x = mul_mod_p(&three, &x);

    let b = U256(P256_B);

    let x3_minus_3x = sub_mod_p(&x3, &three_x);
    let right = add_mod_p(&x3_minus_3x, &b);

    left == right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256r1_generator_point() {
        // NIST P-256 生成元 G (Base Point)
        // G_x = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
        // G_y = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        let mut g = [0u8; 65];
        g[0] = 0x04;
        let gx = hex_to_32bytes("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        let gy = hex_to_32bytes("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
        g[1..33].copy_from_slice(&gx);
        g[33..65].copy_from_slice(&gy);

        assert!(is_secp256r1_point_on_curve(&g));
    }

    #[test]
    fn test_secp256r1_invalid_points() {
        // 先頭が 0x04 でない
        let mut invalid_head = [0u8; 65];
        invalid_head[0] = 0x02;
        assert!(!is_secp256r1_point_on_curve(&invalid_head));

        // 長さが不正
        assert!(!is_secp256r1_point_on_curve(&[0x04; 64]));
        assert!(!is_secp256r1_point_on_curve(&[0x04; 66]));

        // 曲線上にない点（全ゼロなど）
        let mut zero_point = [0u8; 65];
        zero_point[0] = 0x04;
        assert!(!is_secp256r1_point_on_curve(&zero_point));
    }

    fn hex_to_32bytes(s: &str) -> [u8; 32] {
        let mut b = [0u8; 32];
        for i in 0..32 {
            b[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        b
    }
}
