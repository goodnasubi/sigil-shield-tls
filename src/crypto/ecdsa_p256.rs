//! ECDSA P-256 署名（SHA-256、RFC 6979 の決定的 nonce）
//!
//! ADR 0063 決定 1.4 / ADR 0064 決定 2 の方針に沿う。
//!
//! - 体の演算は 4 × 64 ビット肢のモンゴメリ乗算（p と n）。常に [0, m) に約分する。
//! - 点の演算は a = -3 の完全射影加法公式（Renes–Costello–Batina、2015）。例外の場合分けがない。
//! - スカラー倍は 256 回固定で、毎回「二倍・加算・マスクによる選択」を行う。
//!   秘密のビットによる分岐・添字・反復回数は使わない。
//! - nonce は RFC 6979 §3.2–3.4（HMAC-SHA-256）。4 候補を固定の手順で処理し、
//!   範囲違反・`r = 0`・`s = 0` はマスクで無効にして、最初の有効な組を選ぶ。
//!   4 候補がすべて無効なら `None`（確率は約 2^-128 を下回る）。
//! - 逆元は費馬の小定理（p − 2、n − 2 は公開の指数）。
//! - 秘密鍵・作業領域は使い終わりに volatile 書き込みで消去する。コンパイラが作る一時値と
//!   レジスタの内容は消せない。

use super::hmac::hmac_sha256;
use super::mod_common::wipe;
use super::sha256::sha256;

type Limbs = [u64; 4];

const P_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
const N_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const B_BYTES: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];
const GX_BYTES: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const GY_BYTES: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

fn from_be(bytes: &[u8; 32]) -> Limbs {
    let mut out = [0u64; 4];
    for (i, limb) in out.iter_mut().enumerate() {
        let off = (3 - i) * 8;
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[off..off + 8]);
        *limb = u64::from_be_bytes(w);
    }
    out
}

fn to_be(limbs: &Limbs) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let off = (3 - i) * 8;
        out[off..off + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// a - b と借りの有無（借りがあれば 1）
fn sub_borrow(a: &Limbs, b: &Limbs) -> (Limbs, u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = (b1 | b2) as u64;
    }
    (out, borrow)
}

/// a + b と桁上がり
fn add_carry(a: &Limbs, b: &Limbs) -> (Limbs, u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        out[i] = s2;
        carry = (c1 | c2) as u64;
    }
    (out, carry)
}

/// mask が全ビット 1 なら a、0 なら b
fn select(mask: u64, a: &Limbs, b: &Limbs) -> Limbs {
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = (a[i] & mask) | (b[i] & !mask);
    }
    out
}

/// 1 のとき全ビット 1 のマスクにする
fn mask_of(bit: u64) -> u64 {
    0u64.wrapping_sub(bit & 1)
}

/// a が 0 なら 1、そうでなければ 0
fn is_zero(a: &Limbs) -> u64 {
    let v = a[0] | a[1] | a[2] | a[3];
    // v == 0 のとき 1
    ((v | v.wrapping_neg()) >> 63) ^ 1
}

/// a < b なら 1
fn lt(a: &Limbs, b: &Limbs) -> u64 {
    sub_borrow(a, b).1
}

#[derive(Clone, Copy)]
struct Field {
    m: Limbs,
    n0: u64,
    r2: Limbs,
    one: Limbs,
}

impl Field {
    fn new(modulus: &[u8; 32]) -> Field {
        let m = from_be(modulus);
        // m^-1 mod 2^64（ニュートン法）
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        let n0 = inv.wrapping_neg();
        // m > 2^255 なので R mod m = 2^256 - m
        let (r1, _) = sub_borrow(&[0; 4], &m);
        let mut f = Field {
            m,
            n0,
            r2: [0; 4],
            one: r1,
        };
        let mut r2 = r1;
        for _ in 0..256 {
            r2 = f.add(&r2, &r2);
        }
        f.r2 = r2;
        f
    }

    fn add(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let (s, carry) = add_carry(a, b);
        let (d, borrow) = sub_borrow(&s, &self.m);
        // carry == 1 または s >= m なら d を採る
        let use_d = mask_of(carry | (borrow ^ 1));
        select(use_d, &d, &s)
    }

    fn sub(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let (d, borrow) = sub_borrow(a, b);
        let (s, _) = add_carry(&d, &self.m);
        select(mask_of(borrow), &s, &d)
    }

    fn mul(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let mut t = [0u64; 6];
        for &bi in b.iter() {
            let mut c = 0u128;
            for j in 0..4 {
                let v = t[j] as u128 + (a[j] as u128) * (bi as u128) + c;
                t[j] = v as u64;
                c = v >> 64;
            }
            let v = t[4] as u128 + c;
            t[4] = v as u64;
            t[5] = (v >> 64) as u64;
            let q = t[0].wrapping_mul(self.n0);
            let v = t[0] as u128 + (q as u128) * (self.m[0] as u128);
            let mut c = v >> 64;
            for j in 1..4 {
                let v = t[j] as u128 + (q as u128) * (self.m[j] as u128) + c;
                t[j - 1] = v as u64;
                c = v >> 64;
            }
            let v = t[4] as u128 + c;
            t[3] = v as u64;
            t[4] = t[5] + (v >> 64) as u64;
            t[5] = 0;
        }
        let r = [t[0], t[1], t[2], t[3]];
        let (d, borrow) = sub_borrow(&r, &self.m);
        let use_d = mask_of(t[4] | (borrow ^ 1));
        select(use_d, &d, &r)
    }

    fn enter(&self, a: &Limbs) -> Limbs {
        self.mul(a, &self.r2)
    }

    fn leave(&self, a: &Limbs) -> Limbs {
        self.mul(a, &[1, 0, 0, 0])
    }

    /// a^e（e は公開の指数、ビッグエンディアン 32 バイト）。a はモンゴメリ形。
    fn pow_public(&self, a: &Limbs, e: &Limbs) -> Limbs {
        let mut acc = self.one;
        for i in (0..256).rev() {
            acc = self.mul(&acc, &acc);
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                acc = self.mul(&acc, a);
            }
        }
        acc
    }

    /// 逆元（モンゴメリ形）。m − 2 は公開の定数。
    fn invert(&self, a: &Limbs) -> Limbs {
        let (e, _) = sub_borrow(&self.m, &[2, 0, 0, 0]);
        self.pow_public(a, &e)
    }
}

#[derive(Clone, Copy)]
struct Point {
    x: Limbs,
    y: Limbs,
    z: Limbs,
}

struct Curve {
    p: Field,
    n: Field,
    b: Limbs,
    g: Point,
}

impl Curve {
    fn new() -> Curve {
        let p = Field::new(&P_BYTES);
        let n = Field::new(&N_BYTES);
        let b = p.enter(&from_be(&B_BYTES));
        let g = Point {
            x: p.enter(&from_be(&GX_BYTES)),
            y: p.enter(&from_be(&GY_BYTES)),
            z: p.one,
        };
        Curve { p, n, b, g }
    }

    fn identity(&self) -> Point {
        Point {
            x: [0; 4],
            y: self.p.one,
            z: [0; 4],
        }
    }

    /// 完全加法公式（a = -3、RCB 2015 Algorithm 4）
    fn add(&self, p1: &Point, p2: &Point) -> Point {
        let f = &self.p;
        let b = &self.b;
        let t0 = f.mul(&p1.x, &p2.x);
        let t1 = f.mul(&p1.y, &p2.y);
        let t2 = f.mul(&p1.z, &p2.z);
        let t3 = f.add(&p1.x, &p1.y);
        let t4 = f.add(&p2.x, &p2.y);
        let t3 = f.mul(&t3, &t4);
        let t4 = f.add(&t0, &t1);
        let t3 = f.sub(&t3, &t4);
        let t4 = f.add(&p1.y, &p1.z);
        let x3 = f.add(&p2.y, &p2.z);
        let t4 = f.mul(&t4, &x3);
        let x3 = f.add(&t1, &t2);
        let t4 = f.sub(&t4, &x3);
        let x3 = f.add(&p1.x, &p1.z);
        let y3 = f.add(&p2.x, &p2.z);
        let x3 = f.mul(&x3, &y3);
        let y3 = f.add(&t0, &t2);
        let y3 = f.sub(&x3, &y3);
        let z3 = f.mul(b, &t2);
        let x3 = f.sub(&y3, &z3);
        let z3 = f.add(&x3, &x3);
        let x3 = f.add(&x3, &z3);
        let z3 = f.sub(&t1, &x3);
        let x3 = f.add(&t1, &x3);
        let y3 = f.mul(b, &y3);
        let t1 = f.add(&t2, &t2);
        let t2 = f.add(&t1, &t2);
        let y3 = f.sub(&y3, &t2);
        let y3 = f.sub(&y3, &t0);
        let t1 = f.add(&y3, &y3);
        let y3 = f.add(&t1, &y3);
        let t1 = f.add(&t0, &t0);
        let t0 = f.add(&t1, &t0);
        let t0 = f.sub(&t0, &t2);
        let t1 = f.mul(&t4, &y3);
        let t2 = f.mul(&t0, &y3);
        let y3 = f.mul(&x3, &z3);
        let y3 = f.add(&y3, &t2);
        let x3 = f.mul(&t3, &x3);
        let x3 = f.sub(&x3, &t1);
        let z3 = f.mul(&t4, &z3);
        let t1 = f.mul(&t3, &t0);
        let z3 = f.add(&z3, &t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// 完全二倍公式（a = -3、RCB 2015 Algorithm 6）
    fn double(&self, p1: &Point) -> Point {
        let f = &self.p;
        let b = &self.b;
        let t0 = f.mul(&p1.x, &p1.x);
        let t1 = f.mul(&p1.y, &p1.y);
        let t2 = f.mul(&p1.z, &p1.z);
        let t3 = f.mul(&p1.x, &p1.y);
        let t3 = f.add(&t3, &t3);
        let z3 = f.mul(&p1.x, &p1.z);
        let z3 = f.add(&z3, &z3);
        let y3 = f.mul(b, &t2);
        let y3 = f.sub(&y3, &z3);
        let x3 = f.add(&y3, &y3);
        let y3 = f.add(&x3, &y3);
        let x3 = f.sub(&t1, &y3);
        let y3 = f.add(&t1, &y3);
        let y3 = f.mul(&x3, &y3);
        let x3 = f.mul(&x3, &t3);
        let t3 = f.add(&t2, &t2);
        let t2 = f.add(&t2, &t3);
        let z3 = f.mul(b, &z3);
        let z3 = f.sub(&z3, &t2);
        let z3 = f.sub(&z3, &t0);
        let t3 = f.add(&z3, &z3);
        let z3 = f.add(&z3, &t3);
        let t3 = f.add(&t0, &t0);
        let t0 = f.add(&t3, &t0);
        let t0 = f.sub(&t0, &t2);
        let t0 = f.mul(&t0, &z3);
        let y3 = f.add(&y3, &t0);
        let t0 = f.mul(&p1.y, &p1.z);
        let t0 = f.add(&t0, &t0);
        let z3 = f.mul(&t0, &z3);
        let x3 = f.sub(&x3, &z3);
        let z3 = f.mul(&t0, &t1);
        let z3 = f.add(&z3, &z3);
        let z3 = f.add(&z3, &z3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn select_point(&self, mask: u64, a: &Point, b: &Point) -> Point {
        Point {
            x: select(mask, &a.x, &b.x),
            y: select(mask, &a.y, &b.y),
            z: select(mask, &a.z, &b.z),
        }
    }

    /// k·P。256 回固定で、各回に二倍・加算・マスク選択を行う。
    fn scalar_mult(&self, k: &Limbs, point: &Point) -> Point {
        let mut acc = self.identity();
        for i in (0..256).rev() {
            acc = self.double(&acc);
            let sum = self.add(&acc, point);
            let bit = (k[i / 64] >> (i % 64)) & 1;
            acc = self.select_point(mask_of(bit), &sum, &acc);
        }
        acc
    }

    /// アフィン座標の x（通常形）。Z = 0（無限遠点）では 0。
    fn affine(&self, p: &Point) -> (Limbs, Limbs) {
        let zinv = self.p.invert(&p.z);
        let x = self.p.mul(&p.x, &zinv);
        let y = self.p.mul(&p.y, &zinv);
        (self.p.leave(&x), self.p.leave(&y))
    }
}

/// 1 <= d < n なら true（結果は公開してよい）
pub fn scalar_in_range(bytes: &[u8; 32]) -> bool {
    let d = from_be(bytes);
    let n = from_be(&N_BYTES);
    (lt(&d, &n) & (is_zero(&d) ^ 1)) == 1
}

/// SEC1 の非圧縮点（65 バイト）で公開鍵を返す。`private` は 1 <= d < n であること。
pub fn ecdsa_p256_public_key(private: &[u8; 32]) -> [u8; 65] {
    let curve = Curve::new();
    let mut d = from_be(private);
    let point = curve.scalar_mult(&d, &curve.g);
    let (x, y) = curve.affine(&point);
    d = [0; 4];
    let _ = d;
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&to_be(&x));
    out[33..65].copy_from_slice(&to_be(&y));
    out
}

/// 署名（r, s）。各 32 バイトのビッグエンディアン。
pub struct RawSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// ECDSA P-256 署名（SHA-256 を 1 回適用する）。4 候補がすべて無効なら `None`。
pub fn ecdsa_p256_sign(private: &[u8; 32], message: &[u8]) -> Option<RawSignature> {
    let curve = Curve::new();
    let h = sha256(message);
    let mut d = from_be(private);
    let n = curve.n.m;

    // bits2int(h) mod n
    let e_raw = from_be(&h);
    let (e_sub, e_borrow) = sub_borrow(&e_raw, &n);
    let e = select(mask_of(e_borrow), &e_raw, &e_sub);

    // RFC 6979 §3.2: K, V の初期化
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];
    let x_octets = to_be(&d);
    let h_octets = to_be(&e);
    let mut buf = Vec::with_capacity(32 + 1 + 32 + 32);
    for (sep, _) in [(0x00u8, 0), (0x01u8, 1)] {
        buf.clear();
        buf.extend_from_slice(&v);
        buf.push(sep);
        buf.extend_from_slice(&x_octets);
        buf.extend_from_slice(&h_octets);
        k = hmac_sha256(&k, &buf);
        v = hmac_sha256(&k, &v);
    }

    let d_m = curve.n.enter(&d);
    let mut chosen_r = [0u64; 4];
    let mut chosen_s = [0u64; 4];
    let mut taken = 0u64; // 1 になったら以降の候補は採らない
    for _ in 0..4 {
        v = hmac_sha256(&k, &v);
        let cand = from_be(&v);
        let in_range = lt(&cand, &n) & (is_zero(&cand) ^ 1);
        // 範囲外のときは 1 に差し替えて計算を続ける（結果は使わない）
        let k_eff = select(mask_of(in_range), &cand, &[1, 0, 0, 0]);

        let point = curve.scalar_mult(&k_eff, &curve.g);
        let (x, _) = curve.affine(&point);
        // r = x mod n（x < p < 2n なので 1 回の条件付き引き算）
        let (x_sub, x_borrow) = sub_borrow(&x, &n);
        let r = select(mask_of(x_borrow), &x, &x_sub);

        let r_m = curve.n.enter(&r);
        let e_m = curve.n.enter(&e);
        let k_m = curve.n.enter(&k_eff);
        let kinv = curve.n.invert(&k_m);
        let inner = curve.n.add(&e_m, &curve.n.mul(&r_m, &d_m));
        let s_m = curve.n.mul(&kinv, &inner);
        let s = curve.n.leave(&s_m);

        let valid = in_range & (is_zero(&r) ^ 1) & (is_zero(&s) ^ 1);
        let take = valid & (taken ^ 1);
        let tm = mask_of(take);
        chosen_r = select(tm, &r, &chosen_r);
        chosen_s = select(tm, &s, &chosen_s);
        taken |= valid;

        // 次の候補のための更新（RFC 6979 §3.2 step h.3）
        buf.clear();
        buf.extend_from_slice(&v);
        buf.push(0x00);
        k = hmac_sha256(&k, &buf);
        v = hmac_sha256(&k, &v);
    }

    let mut x_octets = x_octets;
    wipe(&mut x_octets);
    wipe(&mut k);
    wipe(&mut v);
    wipe(&mut buf);
    d = [0; 4];
    let _ = d;

    if taken == 1 {
        Some(RawSignature {
            r: to_be(&chosen_r),
            s: to_be(&chosen_s),
        })
    } else {
        None
    }
}

/// 署名を DER（SEQUENCE { INTEGER r, INTEGER s }、最短形）に符号化する
pub fn signature_to_der(sig: &RawSignature) -> Vec<u8> {
    fn der_int(v: &[u8; 32]) -> Vec<u8> {
        let start = v.iter().position(|&b| b != 0).unwrap_or(31);
        let body = &v[start..];
        let mut out = vec![0x02];
        if body[0] & 0x80 != 0 {
            out.push(body.len() as u8 + 1);
            out.push(0);
        } else {
            out.push(body.len() as u8);
        }
        out.extend_from_slice(body);
        out
    }
    let r = der_int(&sig.r);
    let s = der_int(&sig.s);
    let mut out = vec![0x30, (r.len() + s.len()) as u8];
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// 検証（公開の値だけを扱うので、定数時間ではない。試験と自己検査のためにある）。
///
/// 署名は `1 <= r, s < n`、公開鍵は SEC1 の非圧縮点で曲線上にあること。
pub fn ecdsa_p256_verify(public: &[u8; 65], message: &[u8], sig: &RawSignature) -> bool {
    let curve = Curve::new();
    if public[0] != 0x04 {
        return false;
    }
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&public[1..33]);
    yb.copy_from_slice(&public[33..65]);
    let p = from_be(&P_BYTES);
    let (x, y) = (from_be(&xb), from_be(&yb));
    if lt(&x, &p) == 0 || lt(&y, &p) == 0 {
        return false;
    }
    let f = &curve.p;
    let xm = f.enter(&x);
    let ym = f.enter(&y);
    // y^2 = x^3 - 3x + b
    let lhs = f.mul(&ym, &ym);
    let x3 = f.mul(&f.mul(&xm, &xm), &xm);
    let three_x = f.add(&f.add(&xm, &xm), &xm);
    let rhs = f.add(&f.sub(&x3, &three_x), &curve.b);
    if lhs != rhs {
        return false;
    }
    let n = curve.n.m;
    let (r, s) = (from_be(&sig.r), from_be(&sig.s));
    if is_zero(&r) == 1 || is_zero(&s) == 1 || lt(&r, &n) == 0 || lt(&s, &n) == 0 {
        return false;
    }
    let h = sha256(message);
    let e_raw = from_be(&h);
    let (e_sub, e_borrow) = sub_borrow(&e_raw, &n);
    let e = select(mask_of(e_borrow), &e_raw, &e_sub);
    let sinv = curve.n.invert(&curve.n.enter(&s));
    let u1 = curve.n.leave(&curve.n.mul(&curve.n.enter(&e), &sinv));
    let u2 = curve.n.leave(&curve.n.mul(&curve.n.enter(&r), &sinv));
    let q = Point {
        x: xm,
        y: ym,
        z: f.one,
    };
    let sum = curve.add(
        &curve.scalar_mult(&u1, &curve.g),
        &curve.scalar_mult(&u2, &q),
    );
    if is_zero(&sum.z) == 1 {
        return false;
    }
    let (ax, _) = curve.affine(&sum);
    let (ax_sub, ax_borrow) = sub_borrow(&ax, &n);
    let v = select(mask_of(ax_borrow), &ax, &ax_sub);
    v == r
}
