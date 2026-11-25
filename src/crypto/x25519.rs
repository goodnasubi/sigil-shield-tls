//! X25519（RFC 7748）
//!
//! 体 GF(2^255 - 19) の元を 51 ビット × 5 肢で表す。スカラー倍はモンゴメリ梯子で、
//! 繰り返しの回数は 255 回で固定し、秘密のビットによる分岐・添字は使わない
//! （肢の入れ替えはマスクで行う）。

use super::mod_common::wipe;

const MASK51: u64 = (1 << 51) - 1;

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load = |i: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[i..i + 8]);
            u64::from_le_bytes(b)
        };
        // 最上位ビット（255 ビット目）は無視する（RFC 7748 §5）
        Fe([
            load(0) & MASK51,
            (load(6) >> 3) & MASK51,
            (load(12) >> 6) & MASK51,
            (load(19) >> 1) & MASK51,
            (load(24) >> 12) & MASK51,
        ])
    }

    fn carry(mut self) -> Fe {
        for _ in 0..2 {
            let c0 = self.0[0] >> 51;
            self.0[0] &= MASK51;
            self.0[1] += c0;
            let c1 = self.0[1] >> 51;
            self.0[1] &= MASK51;
            self.0[2] += c1;
            let c2 = self.0[2] >> 51;
            self.0[2] &= MASK51;
            self.0[3] += c2;
            let c3 = self.0[3] >> 51;
            self.0[3] &= MASK51;
            self.0[4] += c3;
            let c4 = self.0[4] >> 51;
            self.0[4] &= MASK51;
            self.0[0] += c4 * 19;
        }
        self
    }

    fn add(self, o: Fe) -> Fe {
        Fe([
            self.0[0] + o.0[0],
            self.0[1] + o.0[1],
            self.0[2] + o.0[2],
            self.0[3] + o.0[3],
            self.0[4] + o.0[4],
        ])
    }

    fn sub(self, o: Fe) -> Fe {
        // 2p を足してから引く（桁借りを避ける）
        const TWO_P0: u64 = 0xF_FFFF_FFFF_FFDA;
        const TWO_P: u64 = 0xF_FFFF_FFFF_FFFE;
        Fe([
            self.0[0] + TWO_P0 - o.0[0],
            self.0[1] + TWO_P - o.0[1],
            self.0[2] + TWO_P - o.0[2],
            self.0[3] + TWO_P - o.0[3],
            self.0[4] + TWO_P - o.0[4],
        ])
        .carry()
    }

    fn mul(self, o: Fe) -> Fe {
        let a = self.0;
        let b = o.0;
        let b19 = [b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let mut t0 =
            m(a[0], b[0]) + m(a[1], b19[3]) + m(a[2], b19[2]) + m(a[3], b19[1]) + m(a[4], b19[0]);
        let mut t1 =
            m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b19[3]) + m(a[3], b19[2]) + m(a[4], b19[1]);
        let mut t2 =
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b19[3]) + m(a[4], b19[2]);
        let mut t3 =
            m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b19[3]);
        let mut t4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        let c = (t0 >> 51) as u64;
        t1 += c as u128;
        let r0 = (t0 as u64) & MASK51;
        let c = (t1 >> 51) as u64;
        t2 += c as u128;
        let r1 = (t1 as u64) & MASK51;
        let c = (t2 >> 51) as u64;
        t3 += c as u128;
        let r2 = (t2 as u64) & MASK51;
        let c = (t3 >> 51) as u64;
        t4 += c as u128;
        let r3 = (t3 as u64) & MASK51;
        let c = (t4 >> 51) as u64;
        let r4 = (t4 as u64) & MASK51;
        t0 = (r0 as u128) + (c as u128) * 19;
        let r0 = (t0 as u64) & MASK51;
        let r1 = r1 + (t0 >> 51) as u64;
        Fe([r0, r1, r2, r3, r4]).carry()
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    fn mul_small(self, k: u64) -> Fe {
        let mut t = [0u128; 5];
        for (i, limb) in self.0.iter().enumerate() {
            t[i] = (*limb as u128) * (k as u128);
        }
        let mut out = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..5 {
            let v = t[i] + carry;
            out[i] = (v as u64) & MASK51;
            carry = v >> 51;
        }
        out[0] += (carry as u64) * 19;
        Fe(out).carry()
    }

    /// 自乗を n 回繰り返す
    fn square_n(self, n: usize) -> Fe {
        let mut x = self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }

    /// 逆元 self^(p-2)。指数は公開の定数。
    fn invert(self) -> Fe {
        let z2 = self.square();
        let z9 = z2.square().square().mul(self);
        let z11 = z9.mul(z2);
        let z_5_0 = z11.square().mul(z9);
        let z_10_0 = z_5_0.square_n(5).mul(z_5_0);
        let z_20_0 = z_10_0.square_n(10).mul(z_10_0);
        let z_40_0 = z_20_0.square_n(20).mul(z_20_0);
        let z_50_0 = z_40_0.square_n(10).mul(z_10_0);
        let z_100_0 = z_50_0.square_n(50).mul(z_50_0);
        let z_200_0 = z_100_0.square_n(100).mul(z_100_0);
        let z_250_0 = z_200_0.square_n(50).mul(z_50_0);
        z_250_0.square_n(5).mul(z11)
    }

    /// 完全に約分した 32 バイトのリトルエンディアン表現
    fn to_bytes(self) -> [u8; 32] {
        let mut t = self.carry().carry().0;
        // 最終的な p の引き算: q = (t + 19) >> 255
        let mut q = (t[0] + 19) >> 51;
        q = (t[1] + q) >> 51;
        q = (t[2] + q) >> 51;
        q = (t[3] + q) >> 51;
        q = (t[4] + q) >> 51;
        t[0] += 19 * q;
        let mut c = t[0] >> 51;
        t[0] &= MASK51;
        for limb in t.iter_mut().skip(1) {
            *limb += c;
            c = *limb >> 51;
            *limb &= MASK51;
        }
        let mut out = [0u8; 32];
        let v0 = t[0] | (t[1] << 51);
        let v1 = (t[1] >> 13) | (t[2] << 38);
        let v2 = (t[2] >> 26) | (t[3] << 25);
        let v3 = (t[3] >> 39) | (t[4] << 12);
        out[0..8].copy_from_slice(&v0.to_le_bytes());
        out[8..16].copy_from_slice(&v1.to_le_bytes());
        out[16..24].copy_from_slice(&v2.to_le_bytes());
        out[24..32].copy_from_slice(&v3.to_le_bytes());
        out
    }

    fn cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let x = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= x;
            b.0[i] ^= x;
        }
    }
}

/// RFC 7748 §5 のスカラーのクランプ
fn clamp(scalar: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// X25519(k, u)。結果が全ゼロ（低位の点）かどうかは呼び出し側が検査する。
pub fn x25519(scalar: &[u8; 32], u_coordinate: &[u8; 32]) -> [u8; 32] {
    let mut k = clamp(scalar);
    let x1 = Fe::from_bytes(u_coordinate);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= kt;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = kt;
        let a = x2.add(z2).carry();
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3).carry();
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).carry().square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul_small(121665)).carry());
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    let out = x2.mul(z2.invert()).to_bytes();
    wipe(&mut k);
    out
}

/// 公開鍵 = X25519(秘密鍵, 9)
pub fn x25519_public_key(private: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(private, &base)
}
