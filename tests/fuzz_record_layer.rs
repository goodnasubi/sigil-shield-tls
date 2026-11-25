//! レコード層の読み取りと再構成のファジング（ADR 0020 決定 2, ADR 0063 決定 4.7）
//!
//! 性質: 任意の壊れたレコード、ランダムなチャンク分割、変異ストリームに対して
//! 決してパニックせず、適切に Result を返すこと。

mod common;

use common::build_valid_client_hello;
use common::fuzz::{Rng, DEFAULT_SEED};
use sigil_shield_tls::record::{parse_record_header, HandshakeReassembler};

#[test]
fn test_fuzz_record_layer_short_run() {
    let iters = std::env::var("SIGIL_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);

    let seed = std::env::var("SIGIL_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED);

    let mut rng = Rng::new(seed);
    let valid_ch = build_valid_client_hello();
    let valid_record = common::wrap_in_record(0x16, 0x0303, &valid_ch);

    for _ in 0..iters {
        // 1. レコードヘッダ単体パースのファジング
        let raw_hdr = rng.random_bytes(10);
        let is_enc = rng.chance(1, 2);
        let _ = parse_record_header(&raw_hdr, is_enc);

        // 2. HandshakeReassembler のファジング
        let mut reassembler = HandshakeReassembler::new();

        match rng.below(3) {
            0 => {
                // 完全ランダムなストリームを複数チャンクで投入
                let num_chunks = 1 + rng.below(5);
                for _ in 0..num_chunks {
                    let chunk = rng.random_bytes(256);
                    if chunk.is_empty() {
                        let _ = reassembler.feed_bytes(&chunk);
                        break;
                    }
                    if reassembler.feed_bytes(&chunk).is_err() {
                        break;
                    }
                }
            }
            1 => {
                // 有効なレコードを変異させて投入
                let mutated = rng.mutate(&valid_record);
                let _ = reassembler.feed_bytes(&mutated);
            }
            _ => {
                // 有効なレコードをランダムな位置で複数に切り刻んで投入
                let mut pos = 0;
                while pos < valid_record.len() {
                    let chunk_len = 1 + rng.below(valid_record.len() - pos);
                    let chunk = &valid_record[pos..pos + chunk_len];
                    pos += chunk_len;
                    if let Ok(Some(msg)) = reassembler.feed_bytes(chunk) {
                        assert_eq!(msg, valid_ch);
                        break;
                    }
                }
            }
        }
    }
}
