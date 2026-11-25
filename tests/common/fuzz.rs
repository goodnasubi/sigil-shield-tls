//! 自前のファジング枠組み（ADR 0020 決定 2, ADR 0063 決定 4.7）
//!
//! - 依存クレートなし
//! - splitmix64 乱数（種から決定論的生成）
//! - ランダムバイト列生成およびコーパスの変異

#![allow(dead_code)]

pub const DEFAULT_SEED: u64 = 0x5167_11fa_c0de_0001;

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    pub fn chance(&mut self, num: usize, den: usize) -> bool {
        self.below(den) < num
    }

    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }

    /// 指定長までのランダムなバイト列を生成する
    pub fn random_bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        let mut res = Vec::with_capacity(len);
        for _ in 0..len {
            res.push(self.next_u8());
        }
        res
    }

    /// バイト列を変異させる（ビット反転、バイト置換、挿入、削除、切り詰め）
    pub fn mutate(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return self.random_bytes(16);
        }

        let mut res = data.to_vec();
        let ops = 1 + self.below(4);

        for _ in 0..ops {
            if res.is_empty() {
                res.push(self.next_u8());
                continue;
            }
            match self.below(5) {
                0 => {
                    // 1 ビット反転
                    let idx = self.below(res.len());
                    let bit = 1 << self.below(8);
                    res[idx] ^= bit;
                }
                1 => {
                    // バイト置換
                    let idx = self.below(res.len());
                    res[idx] = self.next_u8();
                }
                2 => {
                    // バイト挿入
                    let idx = self.below(res.len() + 1);
                    res.insert(idx, self.next_u8());
                }
                3 => {
                    // バイト削除
                    let idx = self.below(res.len());
                    res.remove(idx);
                }
                4 => {
                    // 切り詰め
                    let new_len = self.below(res.len());
                    res.truncate(new_len);
                }
                _ => {}
            }
        }
        res
    }
}
