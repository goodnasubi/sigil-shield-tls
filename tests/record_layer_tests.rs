//! レコード層の読み取りと再構成の試験（ADR 0063 決定 4.2）
//!
//! - 先頭 5 バイトの検査（種別・旧版・長さ）
//! - ハンドシェイクメッセージの再構成（最大 16 KiB、最大 8 レコード）
//! - 長さ 0 のハンドシェイクレコードの拒否
//! - 暗号化後の長さ 0 の application_data の連続 16 個制限
//! - ハンドシェイク前の読み取り総量 32 KiB 制限
//! - 負の例（長さの過不足、重複、範囲外、全ゼロ、0 長レコードの連続、分割された ClientHello の境界）

mod common;

use common::{build_valid_client_hello, wrap_in_record};
use sigil_shield_tls::alert::{AlertDescription, ShieldError};
use sigil_shield_tls::record::{parse_record_header, ContentType, HandshakeReassembler};

#[test]
fn test_record_header_valid() {
    // 正常な 4 種別、旧版 0x0301 と 0x0303
    for ct in [0x14, 0x15, 0x16, 0x17] {
        for ver in [0x0301, 0x0303] {
            let buf = [ct, (ver >> 8) as u8, (ver & 0xFF) as u8, 0x00, 0x10];
            let header = parse_record_header(&buf, false).expect("valid header");
            assert_eq!(header.content_type, ContentType::from_u8(ct).unwrap());
            assert_eq!(header.legacy_version, ver);
            assert_eq!(header.length, 16);
        }
    }
}

#[test]
fn test_record_header_invalid_content_type() {
    // 未知の種別 (0x00, 0x18, 0xFF 等) -> unexpected_message
    for invalid_ct in [0x00, 0x13, 0x18, 0x20, 0xFF] {
        let buf = [invalid_ct, 0x03, 0x03, 0x00, 0x05];
        assert_eq!(
            parse_record_header(&buf, false),
            Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage))
        );
    }
}

#[test]
fn test_record_header_invalid_legacy_version() {
    // 0x0301, 0x0303 以外の旧版 -> protocol_version
    for invalid_ver in [0x0200, 0x0300, 0x0302, 0x0304, 0x0400] {
        let buf = [
            0x16,
            (invalid_ver >> 8) as u8,
            (invalid_ver & 0xFF) as u8,
            0x00,
            0x05,
        ];
        assert_eq!(
            parse_record_header(&buf, false),
            Err(ShieldError::Fatal(AlertDescription::ProtocolVersion))
        );
    }
}

#[test]
fn test_record_header_length_limits() {
    // 平文の最大長 2^14 = 16,384
    let valid_plain = [0x16, 0x03, 0x03, 0x40, 0x00]; // 16384
    assert!(parse_record_header(&valid_plain, false).is_ok());

    // 平文の超過 16,385 -> decode_error
    let overflow_plain = [0x16, 0x03, 0x03, 0x40, 0x01];
    assert_eq!(
        parse_record_header(&overflow_plain, false),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );

    // 暗号化後の最大長 2^14 + 256 = 16,640
    let valid_enc = [0x17, 0x03, 0x03, 0x41, 0x00]; // 16640
    assert!(parse_record_header(&valid_enc, true).is_ok());

    // 暗号化後の超過 16,641 -> decode_error
    let overflow_enc = [0x17, 0x03, 0x03, 0x41, 0x01];
    assert_eq!(
        parse_record_header(&overflow_enc, true),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

#[test]
fn test_record_header_zero_length_handshake_rejected() {
    // 長さ 0 のハンドシェイクレコードは拒否する (RFC 8446 §5.1, 決定 4.2)
    let zero_len_hs = [0x16, 0x03, 0x03, 0x00, 0x00];
    assert_eq!(
        parse_record_header(&zero_len_hs, false),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

#[test]
fn test_record_header_all_zeros() {
    // 全ゼロの入力 (5 バイト) -> 未知の種別 0x00 で unexpected_message
    let all_zeros = [0x00; 5];
    assert_eq!(
        parse_record_header(&all_zeros, false),
        Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage))
    );
}

#[test]
fn test_record_header_incomplete() {
    // 5 バイト未満
    let incomplete = [0x16, 0x03, 0x03];
    assert_eq!(
        parse_record_header(&incomplete, false),
        Err(ShieldError::Incomplete { needed: 2 })
    );
}

#[test]
fn test_reassemble_single_record() {
    let client_hello = build_valid_client_hello();
    let record = wrap_in_record(0x16, 0x0303, &client_hello);

    let mut reassembler = HandshakeReassembler::new();
    let res = reassembler
        .feed_bytes(&record)
        .expect("reassemble succeeds");
    assert_eq!(res, Some(client_hello));
    assert_eq!(reassembler.record_count(), 1);
}

#[test]
fn test_reassemble_split_client_hello_boundary() {
    let client_hello = build_valid_client_hello();
    assert!(client_hello.len() > 100);

    // 2 つのレコードに分割
    let part1 = &client_hello[..50];
    let part2 = &client_hello[50..];

    let rec1 = wrap_in_record(0x16, 0x0303, part1);
    let rec2 = wrap_in_record(0x16, 0x0303, part2);

    let mut reassembler = HandshakeReassembler::new();
    let res1 = reassembler.feed_bytes(&rec1).expect("first part");
    assert_eq!(res1, None);

    let res2 = reassembler.feed_bytes(&rec2).expect("second part");
    assert_eq!(res2, Some(client_hello.clone()));
    assert_eq!(reassembler.record_count(), 2);
}

#[test]
fn test_reassemble_max_8_records() {
    let client_hello = build_valid_client_hello();
    // ちょうど 8 つのレコードに均等分割
    let chunk_size = client_hello.len().div_ceil(8);
    let mut reassembler = HandshakeReassembler::new();

    let chunks: Vec<&[u8]> = client_hello.chunks(chunk_size).collect();
    assert_eq!(chunks.len(), 8);

    for (i, chunk) in chunks.iter().enumerate() {
        let rec = wrap_in_record(0x16, 0x0303, chunk);
        let res = reassembler.feed_bytes(&rec).expect("chunk feed");
        if i == 7 {
            assert_eq!(res, Some(client_hello.clone()));
        } else {
            assert_eq!(res, None);
        }
    }
    assert_eq!(reassembler.record_count(), 8);
}

#[test]
fn test_reassemble_exceed_max_8_records() {
    let client_hello = build_valid_client_hello();
    // 9 つのレコードに分割 -> 8 個を超えたら decode_error
    let chunk_size = client_hello.len().div_ceil(9);
    let mut reassembler = HandshakeReassembler::new();

    let chunks: Vec<&[u8]> = client_hello.chunks(chunk_size).collect();
    assert_eq!(chunks.len(), 9);

    for (i, chunk) in chunks.iter().enumerate() {
        let rec = wrap_in_record(0x16, 0x0303, chunk);
        let res = reassembler.feed_bytes(&rec);
        if i < 8 {
            assert_eq!(res.unwrap(), None);
        } else {
            // 9 レコード目でエラー
            assert_eq!(res, Err(ShieldError::Fatal(AlertDescription::DecodeError)));
            return;
        }
    }
    panic!("should have failed at 9th record");
}

#[test]
fn test_reassemble_interrupted_by_other_content_type() {
    let client_hello = build_valid_client_hello();
    let part1 = &client_hello[..50];

    let rec1 = wrap_in_record(0x16, 0x0303, part1);
    // 途中に Alert レコードが割り込む
    let rec_alert = wrap_in_record(0x15, 0x0303, &[0x02, 50]);

    let mut reassembler = HandshakeReassembler::new();
    reassembler.feed_bytes(&rec1).unwrap();

    let res = reassembler.feed_bytes(&rec_alert);
    assert_eq!(
        res,
        Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage))
    );

    // 途中に空の application_data レコードが割り込む場合も拒否されること（P2 指摘）
    let mut reassembler2 = HandshakeReassembler::new();
    reassembler2.feed_bytes(&rec1).unwrap();
    let empty_app_data = wrap_in_record(0x17, 0x0303, &[]);
    let res2 = reassembler2.feed_bytes(&empty_app_data);
    assert_eq!(
        res2,
        Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage))
    );
}

#[test]
fn test_reassemble_consecutive_empty_app_data_limit() {
    let mut reassembler = HandshakeReassembler::new();
    let empty_app_data = wrap_in_record(0x17, 0x0303, &[]);

    // 16 回までは許容
    for _ in 0..16 {
        assert!(reassembler.feed_bytes(&empty_app_data).is_ok());
    }

    // 17 回目で unexpected_message
    assert_eq!(
        reassembler.feed_bytes(&empty_app_data),
        Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage))
    );
}

#[test]
fn test_reassemble_total_read_limit_32kib() {
    let mut reassembler = HandshakeReassembler::new();
    // 32 KiB (32,768 バイト) を超えて読み取ろうとしたら decode_error
    let large_input = vec![0x16; 32 * 1024 + 1];
    let res = reassembler.feed_bytes(&large_input);
    assert_eq!(res, Err(ShieldError::Fatal(AlertDescription::DecodeError)));
}

#[test]
fn test_reassemble_message_size_exceeds_16kib() {
    let mut reassembler = HandshakeReassembler::new();
    // メッセージヘッダで 16 KiB + 1 を主張するハンドシェイクレコード
    let mut payload = vec![0x01, 0x00, 0x40, 0x01]; // ClientHello length = 16385
    payload.extend_from_slice(&[0x00; 100]);
    let rec = wrap_in_record(0x16, 0x0303, &payload);

    let res = reassembler.feed_bytes(&rec);
    assert_eq!(res, Err(ShieldError::Fatal(AlertDescription::DecodeError)));
}
