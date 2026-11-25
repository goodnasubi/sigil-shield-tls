//! 暗号スイート優先順の実測テストと記録 (ADR 0063 決定 1, 段 2)
//!
//! ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM の暗号化・復号速度を実測し、
//! スイート優先順位の妥当性を評価・記録する。

use sigil_shield_tls::cipher_suite::SERVER_PREFERENCE_ORDER;
use sigil_shield_tls::key_schedule::KeySchedule;
use sigil_shield_tls::record::ContentType;
use sigil_shield_tls::record_crypto::{RecordDirection, RecordProtection};
use std::time::Instant;

#[test]
fn test_cipher_suite_bench_and_record() {
    let chunk_size = 16384; // 16 KiB
    let iterations = 10;
    let payload = vec![0x3Au8; chunk_size];

    let mut results = Vec::new();

    for &suite in SERVER_PREFERENCE_ORDER {
        let ks = KeySchedule::new(suite);
        let secret = vec![0x42u8; suite.hash_len()];

        let mut tx = RecordProtection::new(RecordDirection::Transmit, suite, secret.clone(), &ks);
        let mut rx = RecordProtection::new(RecordDirection::Receive, suite, secret, &ks);

        let start = Instant::now();
        let mut total_bytes = 0usize;

        for _ in 0..iterations {
            let sealed = tx
                .seal_record(ContentType::ApplicationData, &payload, 0)
                .unwrap();
            let (_, plain, _) = rx.open_record(&sealed).unwrap();
            total_bytes += plain.len();
        }

        let elapsed = start.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();
        let mb_processed = (total_bytes as f64) / (1024.0 * 1024.0);
        let throughput_mb_s = mb_processed / elapsed_secs;

        results.push((suite, elapsed, throughput_mb_s));
        println!(
            "CipherSuite: {:<32} | Time: {:>8.3} ms | Throughput: {:>7.2} MB/s",
            suite.name(),
            elapsed.as_secs_f64() * 1000.0,
            throughput_mb_s
        );
    }

    // 優先順位（ChaCha20-Poly1305 > AES-128-GCM > AES-256-GCM）の確認
    println!("\n=== 実測結果サマリー ===");
    for (i, (suite, elapsed, mb_s)) in results.iter().enumerate() {
        println!(
            "{}. {:<32}: {:.2} MB/s ({:.2} ms / {} records)",
            i + 1,
            suite.name(),
            mb_s,
            elapsed.as_secs_f64() * 1000.0,
            iterations
        );
    }

    // ChaCha20 は純粋ソフトウェア（定数時間 S-box なし）のため、
    // 定数時間 GF(2^8) 逆元計算の AES よりも大幅に高速であることを検証
    let chacha_speed = results[0].2;
    let aes128_speed = results[1].2;
    assert!(
        chacha_speed > aes128_speed,
        "ChaCha20 ({:.2} MB/s) should be faster than constant-time AES-128 ({:.2} MB/s)",
        chacha_speed,
        aes128_speed
    );
}
