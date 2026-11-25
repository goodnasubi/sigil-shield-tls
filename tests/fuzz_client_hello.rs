//! ClientHello 解析のファジング（ADR 0020 決定 2, ADR 0063 決定 4.7）
//!
//! 性質: 任意の壊れた入力・変異入力・ランダムバイト列に対して決してパニックせず、
//! 適切に Result (Ok または致命的アラート ShieldError) を返すこと。

mod common;

use common::build_valid_client_hello;
use common::fuzz::{Rng, DEFAULT_SEED};
use sigil_shield_tls::client_hello::parse_client_hello;

#[test]
fn test_fuzz_client_hello_short_run() {
    let iters = std::env::var("SIGIL_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);

    let seed = std::env::var("SIGIL_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED);

    let mut rng = Rng::new(seed);
    let corpus_valid = build_valid_client_hello();

    for _ in 0..iters {
        let input = match rng.below(3) {
            0 => {
                // 完全ランダムなバイト列 (0〜1024 バイト)
                rng.random_bytes(1024)
            }
            1 => {
                // 有効な ClientHello を変異させたバイト列
                rng.mutate(&corpus_valid)
            }
            _ => {
                // 先頭だけハンドシェイクヘッダにしてランダム化
                let mut b = vec![0x01];
                let len = rng.below(512);
                b.push(((len >> 16) & 0xFF) as u8);
                b.push(((len >> 8) & 0xFF) as u8);
                b.push((len & 0xFF) as u8);
                b.extend(rng.random_bytes(len));
                b
            }
        };

        // パニックしないことを検証
        let _ = parse_client_hello(&input);
    }
}
