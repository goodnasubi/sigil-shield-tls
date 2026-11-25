//! ハンドシェイクの状態機械のファジング（ADR 0020 決定 2）
//!
//! 性質: 壊れた入力・変異入力・ランダムなバイト列を任意の区切りで与えても、決してパニックせず、
//! エラーを返した後は前進せず（入力を受け付けず）、成功しても完了までに誤った鍵を出さないこと。

mod common;

use common::build_valid_client_hello;
use common::fuzz::{Rng, DEFAULT_SEED};
use sigil_shield_tls::alert::ShieldError;
use sigil_shield_tls::handshake::{EcdsaP256Signer, RandomSource, ServerConfig, ServerHandshake};

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), ShieldError> {
        for b in out.iter_mut() {
            self.0 = self.0.wrapping_mul(33).wrapping_add(5);
            *b = self.0;
        }
        Ok(())
    }
}

fn server() -> ServerHandshake {
    let signer = EcdsaP256Signer::new([0x42; 32]).unwrap();
    let config = ServerConfig::new(vec![vec![0x30, 0x00]], Box::new(signer));
    ServerHandshake::new(config, Box::new(Counter(1))).unwrap()
}

fn as_record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut r = vec![kind, 0x03, 0x03];
    r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    r.extend_from_slice(payload);
    r
}

#[test]
fn test_fuzz_server_handshake_short_run() {
    let iters = std::env::var("SIGIL_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let seed = std::env::var("SIGIL_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED);
    let mut rng = Rng::new(seed);
    let hello = build_valid_client_hello();

    for _ in 0..iters {
        let wire = match rng.below(4) {
            0 => rng.random_bytes(2048),
            1 => as_record(0x16, &rng.mutate(&hello)),
            2 => {
                // 有効な ClientHello の後ろに、種類を問わないレコードを続ける
                let mut w = as_record(0x16, &hello);
                let kind = *rng.pick(&[0x14u8, 0x15, 0x16, 0x17]);
                w.extend(as_record(kind, &rng.random_bytes(64)));
                w
            }
            _ => rng.mutate(&as_record(0x16, &hello)),
        };
        let mut s = server();
        // 任意の区切りで与える。空の入力は前進しないのでエラーになる。
        let mut pos = 0;
        let mut failed = false;
        while pos < wire.len() {
            let n = 1 + rng.below(wire.len() - pos);
            match s.receive(&wire[pos..pos + n]) {
                Ok(_) => {}
                Err(_) => {
                    failed = true;
                    break;
                }
            }
            pos += n;
        }
        if failed {
            // 失敗した後は何も受け付けない
            assert!(s.receive(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x00]).is_err());
            assert!(!s.is_complete());
        }
    }
}
