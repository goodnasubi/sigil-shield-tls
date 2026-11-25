//! 読み取りの前進と期限の不変条件試験（ADR 0063 決定 4.4）
//!
//! 「各ループは、入力を 1 バイト以上消費するか、上限に達して終えることを不変条件とする。
//! 消費せずに繰り返す経路を置かない。」

mod common;

use common::build_valid_client_hello;
use sigil_shield_tls::alert::ShieldError;
use sigil_shield_tls::record::HandshakeReassembler;

#[test]
fn test_zero_bytes_read_terminates_immediately() {
    let mut reassembler = HandshakeReassembler::new();
    // 0 バイト読み取り（前進なし） -> 即座に TimeoutOrNoProgress エラーで終了
    let res = reassembler.feed_bytes(&[]);
    assert_eq!(res, Err(ShieldError::TimeoutOrNoProgress));
}

#[test]
fn test_progress_invariant_byte_by_byte() {
    let client_hello = build_valid_client_hello();
    let record = common::wrap_in_record(0x16, 0x0303, &client_hello);

    let mut reassembler = HandshakeReassembler::new();

    // 1 バイトずつストリームに投入する
    // 各ステップで必ず 1 バイト消費され、読み取り総量が単調増加し、
    // 無限ループや消費なしの空転が発生しないことを検証する
    let mut last_total = 0;
    for (i, &byte) in record.iter().enumerate() {
        let chunk = [byte];
        let res = reassembler
            .feed_bytes(&chunk)
            .expect("valid stream progress");
        let current_total = reassembler.total_read_bytes();

        // 不変条件: 呼び出しごとに入力長 (1 バイト) だけ前進していること
        assert_eq!(current_total, last_total + 1);
        last_total = current_total;

        if i == record.len() - 1 {
            assert_eq!(res, Some(client_hello.clone()));
        } else {
            assert_eq!(res, None);
        }
    }
}

#[test]
fn test_progress_invariant_no_infinite_loop_on_partial_data() {
    let mut reassembler = HandshakeReassembler::new();
    // ヘッダ途中のデータ（3 バイト）
    let partial_header = [0x16, 0x03, 0x03];
    let res = reassembler.feed_bytes(&partial_header).expect("buffering");
    assert_eq!(res, None);
    assert_eq!(reassembler.total_read_bytes(), 3);

    // さらに 2 バイト投入してヘッダを完成させる
    let header_tail = [0x00, 0x0A]; // length = 10
    let res2 = reassembler
        .feed_bytes(&header_tail)
        .expect("header complete");
    assert_eq!(res2, None);
    assert_eq!(reassembler.total_read_bytes(), 5);

    // ペイロードがまだ不足しているため、空転せず入力を待つ
    // ここで 0 バイトを投入すると正しく終了する
    assert_eq!(
        reassembler.feed_bytes(&[]),
        Err(ShieldError::TimeoutOrNoProgress)
    );
}
