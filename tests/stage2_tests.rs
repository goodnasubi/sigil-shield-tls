//! ADR 0063 段 2: 鍵スケジュールと保護レコードのテスト
//!
//! - 鍵スケジュールと保護レコードのラウンドトリップおよびサーバー側処理テスト
//! - 鍵更新の境界テスト（送信 2^23 直前・一致・超過、受信 16 回直前・一致・超過）
//! - AEAD 失敗テスト（破損データで即座に bad_record_mac を返し継続しない）
//! - 平文断片長上限、全ゼロ内部平文の拒否、トランケーション

use sigil_shield_tls::alert::{AlertDescription, ShieldError};
use sigil_shield_tls::cipher_suite::{select_cipher_suite, CipherSuite, SERVER_PREFERENCE_ORDER};
use sigil_shield_tls::key_schedule::KeySchedule;
use sigil_shield_tls::key_update::{
    KeyUpdateMessage, KeyUpdateRequest, KeyUpdateTracker, KEY_UPDATE_TX_LIMIT,
};
use sigil_shield_tls::limits::{
    MAX_ENCRYPTED_RECORD_PAYLOAD, MAX_KEY_UPDATE_COUNT, MAX_PLAIN_RECORD_PAYLOAD,
};
use sigil_shield_tls::record::ContentType;
use sigil_shield_tls::record_crypto::{make_nonce, RecordDirection, RecordProtection};

#[test]
fn test_cipher_suite_selection_and_preference() {
    // サーバー優先順: ChaCha20-Poly1305 > AES-128-GCM > AES-256-GCM
    assert_eq!(
        SERVER_PREFERENCE_ORDER[0],
        CipherSuite::TlsChacha20Poly1305Sha256
    );
    assert_eq!(SERVER_PREFERENCE_ORDER[1], CipherSuite::TlsAes128GcmSha256);
    assert_eq!(SERVER_PREFERENCE_ORDER[2], CipherSuite::TlsAes256GcmSha384);

    // クライアントが複数提示した場合、サーバー優先順が最も高いものが選ばれる
    let all_suites = [
        CipherSuite::TLS_AES_256_GCM_SHA384_CODE,
        CipherSuite::TLS_AES_128_GCM_SHA256_CODE,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256_CODE,
    ];
    let selected = select_cipher_suite(&all_suites).unwrap();
    assert_eq!(selected, CipherSuite::TlsChacha20Poly1305Sha256);

    let aes_suites = [
        CipherSuite::TLS_AES_256_GCM_SHA384_CODE,
        CipherSuite::TLS_AES_128_GCM_SHA256_CODE,
    ];
    let selected_aes = select_cipher_suite(&aes_suites).unwrap();
    assert_eq!(selected_aes, CipherSuite::TlsAes128GcmSha256);

    let single_aes256 = [CipherSuite::TLS_AES_256_GCM_SHA384_CODE];
    let selected_aes256 = select_cipher_suite(&single_aes256).unwrap();
    assert_eq!(selected_aes256, CipherSuite::TlsAes256GcmSha384);

    // 未知・非対応スイートのみ提示された場合は handshake_failure
    let unsupported = [0x002f, 0x0035, 0xc013];
    assert_eq!(
        select_cipher_suite(&unsupported),
        Err(ShieldError::Fatal(AlertDescription::HandshakeFailure))
    );
}

#[test]
fn test_key_schedule_derivation_flow() {
    // 各暗号スイートでハンドシェイクからアプリケーション秘密までの導出フローを検証
    for &suite in SERVER_PREFERENCE_ORDER {
        let ks = KeySchedule::new(suite);

        let early_secret = ks.early_secret();
        assert_eq!(early_secret.len(), suite.hash_len());

        let synthetic_shared_secret = vec![0x42u8; 32];
        let handshake_secret = ks.handshake_secret(&early_secret, &synthetic_shared_secret);
        assert_eq!(handshake_secret.len(), suite.hash_len());

        let transcript_hash = ks.empty_hash();
        let client_hs_secret =
            ks.client_handshake_traffic_secret(&handshake_secret, &transcript_hash);
        let server_hs_secret =
            ks.server_handshake_traffic_secret(&handshake_secret, &transcript_hash);
        assert_eq!(client_hs_secret.len(), suite.hash_len());
        assert_eq!(server_hs_secret.len(), suite.hash_len());
        assert_ne!(client_hs_secret, server_hs_secret);

        let master_secret = ks.master_secret(&handshake_secret);
        assert_eq!(master_secret.len(), suite.hash_len());

        let client_app_secret =
            ks.client_application_traffic_secret_0(&master_secret, &transcript_hash);
        let server_app_secret =
            ks.server_application_traffic_secret_0(&master_secret, &transcript_hash);
        assert_eq!(client_app_secret.len(), suite.hash_len());
        assert_eq!(server_app_secret.len(), suite.hash_len());
        assert_ne!(client_app_secret, server_app_secret);

        // 鍵と IV の導出
        let (c_key, c_iv) = ks.derive_traffic_key_iv(&client_app_secret);
        let (s_key, s_iv) = ks.derive_traffic_key_iv(&server_app_secret);
        assert_eq!(c_key.len(), suite.key_len());
        assert_eq!(c_iv.len(), suite.iv_len());
        assert_eq!(s_key.len(), suite.key_len());
        assert_eq!(s_iv.len(), suite.iv_len());
        assert_ne!(c_key, s_key);
        assert_ne!(c_iv, s_iv);

        // 次世代トラフィック秘密
        let next_c_secret = ks.next_traffic_secret(&client_app_secret);
        assert_eq!(next_c_secret.len(), suite.hash_len());
        assert_ne!(next_c_secret, client_app_secret);
    }
}

#[test]
fn test_record_protection_roundtrip_all_suites() {
    let test_payloads: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xAA],
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        vec![0x55; 16],
        vec![0x77; 17],
        vec![0x33; 1024],
        vec![0x99; MAX_PLAIN_RECORD_PAYLOAD], // 最大平文断片長 16,384 バイト
    ];

    let paddings = [0, 1, 15, 64];

    for &suite in SERVER_PREFERENCE_ORDER {
        let ks = KeySchedule::new(suite);
        let app_secret =
            ks.client_application_traffic_secret_0(&ks.early_secret(), &ks.empty_hash());

        let mut tx =
            RecordProtection::new(RecordDirection::Transmit, suite, app_secret.clone(), &ks);
        let mut rx = RecordProtection::new(RecordDirection::Receive, suite, app_secret, &ks);

        for payload in &test_payloads {
            for &pad in &paddings {
                // パディングを付加した暗号化後の長さが上限を超えない範囲で試験
                if payload.len() + 1 + pad + suite.tag_len() > MAX_ENCRYPTED_RECORD_PAYLOAD {
                    continue;
                }

                let content_type = ContentType::ApplicationData;
                let sealed = tx.seal_record(content_type, payload, pad).unwrap();

                // ヘッダ (5 バイト) + 暗号文 + タグ (16 バイト)
                assert_eq!(sealed.len(), 5 + payload.len() + 1 + pad + 16);

                let (decrypted_type, decrypted_data, consumed) = rx.open_record(&sealed).unwrap();
                assert_eq!(decrypted_type, content_type);
                assert_eq!(&decrypted_data, payload);
                assert_eq!(consumed, sealed.len());
            }
        }

        // シーケンス番号の整合性を確認
        assert_eq!(tx.sequence_number, rx.sequence_number);
    }
}

#[test]
fn test_nonce_construction() {
    let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    // シーケンス番号 0
    let nonce0 = make_nonce(&iv, 0);
    assert_eq!(nonce0, iv);

    // シーケンス番号 1 (最下位バイトのみ XOR)
    let nonce1 = make_nonce(&iv, 1);
    let mut expected1 = iv;
    expected1[11] ^= 1;
    assert_eq!(nonce1, expected1);

    // シーケンス番号 0x0102030405060708
    let seq: u64 = 0x0102030405060708;
    let nonce_seq = make_nonce(&iv, seq);
    let mut expected_seq = iv;
    let seq_b = seq.to_be_bytes();
    for i in 0..8 {
        expected_seq[4 + i] ^= seq_b[i];
    }
    assert_eq!(nonce_seq, expected_seq);
}

#[test]
fn test_aead_failure_triggers_bad_record_mac_and_poisons_opener() {
    let suite = CipherSuite::TlsChacha20Poly1305Sha256;
    let ks = KeySchedule::new(suite);
    let secret = vec![0x11u8; suite.hash_len()];

    let mut tx = RecordProtection::new(RecordDirection::Transmit, suite, secret.clone(), &ks);
    let mut rx = RecordProtection::new(RecordDirection::Receive, suite, secret, &ks);

    let plain = b"hello secret message";
    let mut sealed = tx
        .seal_record(ContentType::ApplicationData, plain, 0)
        .unwrap();

    // 暗号文またはタグの 1 バイトを破損させる
    let last_idx = sealed.len() - 1;
    sealed[last_idx] ^= 0xFF;

    // 認証失敗で即座に bad_record_mac を返すこと
    let res = rx.open_record(&sealed);
    assert_eq!(res, Err(ShieldError::Fatal(AlertDescription::BadRecordMac)));
    assert!(rx.is_poisoned);

    // ポイズニング後: 正しいレコードを渡しても読み続けず、即座に bad_record_mac を返すこと
    let valid_sealed = tx
        .seal_record(ContentType::ApplicationData, b"next message", 0)
        .unwrap();
    let res_after = rx.open_record(&valid_sealed);
    assert_eq!(
        res_after,
        Err(ShieldError::Fatal(AlertDescription::BadRecordMac))
    );
}

#[test]
fn test_unexpected_message_on_all_zero_inner_plaintext() {
    // 内部平文が全ゼロ（種別を持たない）の場合、unexpected_message になること
    let suite = CipherSuite::TlsAes128GcmSha256;
    let ks = KeySchedule::new(suite);
    let secret = vec![0x22u8; suite.hash_len()];

    let mut rx = RecordProtection::new(RecordDirection::Receive, suite, secret, &ks);

    // 全ゼロ平文 (例えば 10 バイトの 0) を直接 AEAD 暗号化して不正レコードを作る
    let zeros = [0u8; 10];
    let encrypted_len = zeros.len() + 16;
    let aad = [
        ContentType::ApplicationData as u8,
        0x03,
        0x03,
        (encrypted_len >> 8) as u8,
        (encrypted_len & 0xff) as u8,
    ];
    let nonce = make_nonce(&rx.iv, rx.sequence_number);
    let ct = rx.suite.seal(&rx.key, &nonce, &aad, &zeros).unwrap();

    let mut bad_record = Vec::new();
    bad_record.extend_from_slice(&aad);
    bad_record.extend_from_slice(&ct);

    let res = rx.open_record(&bad_record);
    assert_eq!(
        res,
        Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage))
    );
}

#[test]
fn test_plain_fragment_length_boundary() {
    let suite = CipherSuite::TlsAes128GcmSha256;
    let ks = KeySchedule::new(suite);
    let secret = vec![0x33u8; suite.hash_len()];
    let mut tx = RecordProtection::new(RecordDirection::Transmit, suite, secret, &ks);

    // 2^14 (16,384 バイト) は正常に暗号化可能
    let max_plain = vec![0xAAu8; MAX_PLAIN_RECORD_PAYLOAD];
    assert!(tx
        .seal_record(ContentType::ApplicationData, &max_plain, 0)
        .is_ok());

    // 2^14 + 1 バイトは DecodeError で拒否
    let over_plain = vec![0xBBu8; MAX_PLAIN_RECORD_PAYLOAD + 1];
    assert_eq!(
        tx.seal_record(ContentType::ApplicationData, &over_plain, 0),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

#[test]
fn test_key_update_record_and_sequence_number_reset() {
    let suite = CipherSuite::TlsAes256GcmSha384;
    let ks = KeySchedule::new(suite);
    let secret = vec![0x55u8; suite.hash_len()];

    let mut tx = RecordProtection::new(RecordDirection::Transmit, suite, secret.clone(), &ks);
    let mut rx = RecordProtection::new(RecordDirection::Receive, suite, secret, &ks);

    // 1 回送受信
    let r1 = tx
        .seal_record(ContentType::ApplicationData, b"msg1", 0)
        .unwrap();
    let (_, d1, _) = rx.open_record(&r1).unwrap();
    assert_eq!(d1, b"msg1");
    assert_eq!(tx.sequence_number, 1);
    assert_eq!(rx.sequence_number, 1);

    // 鍵更新の適用
    tx.update_key(&ks);
    rx.update_key(&ks);

    // シーケンス番号が 0 にリセットされること
    assert_eq!(tx.sequence_number, 0);
    assert_eq!(rx.sequence_number, 0);

    // 更新後の新しい鍵で送受信が成立すること
    let r2 = tx
        .seal_record(ContentType::ApplicationData, b"msg2", 0)
        .unwrap();
    let (_, d2, _) = rx.open_record(&r2).unwrap();
    assert_eq!(d2, b"msg2");
    assert_eq!(tx.sequence_number, 1);
    assert_eq!(rx.sequence_number, 1);
}

#[test]
fn test_key_update_boundaries() {
    // 1. 送信レコード数 2^23 の境界テスト
    let mut tracker = KeyUpdateTracker::new();

    // 2^23 - 2 の状態
    tracker.records_sent = KEY_UPDATE_TX_LIMIT - 2;
    assert!(!tracker.should_trigger_tx_update());
    assert!(tracker.can_send_record().is_ok());

    // 1 レコード送信して 2^23 - 1 に到達（直前: 更新トリガー発生）
    let need_update = tracker.record_sent().unwrap();
    assert!(need_update);
    assert!(tracker.should_trigger_tx_update());
    assert_eq!(tracker.records_sent, KEY_UPDATE_TX_LIMIT - 1);
    assert!(tracker.can_send_record().is_ok());

    // 1 レコード送信して 2^23 に到達（一致）
    let _ = tracker.record_sent().unwrap();
    assert_eq!(tracker.records_sent, KEY_UPDATE_TX_LIMIT);

    // 2^23 超過: 更新できずさらに送信しようとするとエラー終了
    assert_eq!(
        tracker.can_send_record(),
        Err(ShieldError::Fatal(AlertDescription::InternalError))
    );
    assert_eq!(
        tracker.record_sent(),
        Err(ShieldError::Fatal(AlertDescription::InternalError))
    );

    // 鍵更新が行われたら 0 にリセットされて再び送信可能
    tracker.on_tx_key_updated();
    assert_eq!(tracker.records_sent, 0);
    assert!(tracker.can_send_record().is_ok());

    // 2. 受信 KeyUpdate 回数 (16 回制限) の境界テスト
    let mut rx_tracker = KeyUpdateTracker::new();

    // 15 回目（直前）
    for _ in 0..MAX_KEY_UPDATE_COUNT - 1 {
        assert!(rx_tracker
            .handle_received_key_update(KeyUpdateRequest::UpdateNotRequested)
            .is_ok());
    }
    assert_eq!(rx_tracker.received_key_update_count, 15);

    // 16 回目（一致: 上限ちょうどまで受理可能）
    assert!(rx_tracker
        .handle_received_key_update(KeyUpdateRequest::UpdateRequested)
        .is_ok());
    assert_eq!(rx_tracker.received_key_update_count, 16);

    // 17 回目（超過: 16 回を超えたら unexpected_message）
    assert_eq!(
        rx_tracker.handle_received_key_update(KeyUpdateRequest::UpdateNotRequested),
        Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage))
    );
}

#[test]
fn test_key_update_message_encoding_decoding() {
    // update_not_requested
    let encoded0 = KeyUpdateMessage::encode(KeyUpdateRequest::UpdateNotRequested);
    assert_eq!(encoded0, [24, 0, 0, 1, 0]);
    assert_eq!(
        KeyUpdateMessage::decode(&encoded0),
        Ok(KeyUpdateRequest::UpdateNotRequested)
    );

    // update_requested
    let encoded1 = KeyUpdateMessage::encode(KeyUpdateRequest::UpdateRequested);
    assert_eq!(encoded1, [24, 0, 0, 1, 1]);
    assert_eq!(
        KeyUpdateMessage::decode(&encoded1),
        Ok(KeyUpdateRequest::UpdateRequested)
    );

    // 不正な request_update 値 (例: 2) -> illegal_parameter
    let invalid_req = [24, 0, 0, 1, 2];
    assert_eq!(
        KeyUpdateMessage::decode(&invalid_req),
        Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
    );

    // 長さ不正 (例: 長さ 2) -> decode_error
    let invalid_len = [24, 0, 0, 2, 0, 0];
    assert_eq!(
        KeyUpdateMessage::decode(&invalid_len),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );

    // 余計なバイト -> decode_error
    let extra_bytes = [24, 0, 0, 1, 0, 99];
    assert_eq!(
        KeyUpdateMessage::decode(&extra_bytes),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

#[test]
fn test_poly1305_codex_reproduced_tamper_rejected() {
    // Codex Cloud レビュー P1 指摘の再現テスト:
    // 全ゼロ鍵・ノンス、AAD "aad"、64 バイトのゼロ平文で、
    // 最初の暗号文バイトに 31 を XOR した場合に確実に BadRecordMac で拒否されること
    use sigil_shield_tls::crypto::{chacha20_poly1305_open, chacha20_poly1305_seal};

    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"aad";
    let pt = [0u8; 64];

    let mut sealed = chacha20_poly1305_seal(&key, &nonce, aad, &pt).unwrap();

    // 最初の暗号文バイトを 31 で XOR
    sealed[0] ^= 31;

    let res = chacha20_poly1305_open(&key, &nonce, aad, &sealed);
    assert_eq!(
        res,
        Err(ShieldError::Fatal(AlertDescription::BadRecordMac)),
        "改ざんされた暗号文は必ず BadRecordMac で拒否されなければならない"
    );
}

#[test]
fn test_poly1305_known_answers() {
    // Poly1305 既知回答テスト (RFC 8439 付録 A.3 ベクタ)
    use sigil_shield_tls::crypto::poly1305_mac;

    // Vector #1: key 32 バイト全ゼロ、msg 64 バイト全ゼロ -> tag 16 バイト全ゼロ
    let k1 = [0u8; 32];
    let m1 = [0u8; 64];
    assert_eq!(poly1305_mac(&k1, &m1), [0u8; 16]);

    // Vector #5: r = [2, 0, ...], s = [0; 16], msg = [0xff; 16] -> tag = [3, 0, ...]
    let mut k5 = [0u8; 32];
    k5[0] = 2;
    let m5 = [0xffu8; 16];
    let mut expected5 = [0u8; 16];
    expected5[0] = 3;
    assert_eq!(poly1305_mac(&k5, &m5), expected5);

    // Vector #9: r = [2, 0, ...], s = [0; 16], msg = [0xfd, 0xff, ..., 0xff] -> tag = [0xfa, 0xff, ..., 0xff]
    let mut k9 = [0u8; 32];
    k9[0] = 2;
    let mut m9 = [0xffu8; 16];
    m9[0] = 0xfd;
    let mut expected9 = [0xffu8; 16];
    expected9[0] = 0xfa;
    assert_eq!(poly1305_mac(&k9, &m9), expected9);
}

#[test]
fn test_chacha20_poly1305_tamper_every_byte() {
    use sigil_shield_tls::crypto::{chacha20_poly1305_open, chacha20_poly1305_seal};

    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"test authenticated data";
    let pt = b"the quick brown fox jumps over the lazy dog";

    let sealed = chacha20_poly1305_seal(&key, &nonce, aad, pt).unwrap();

    // 暗号文とタグの全バイトについて、各バイトの改変が例外なく検知されること
    for i in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[i] ^= 0x01;
        assert_eq!(
            chacha20_poly1305_open(&key, &nonce, aad, &tampered),
            Err(ShieldError::Fatal(AlertDescription::BadRecordMac)),
            "byte index {i} 改ざんが検出されませんでした"
        );
    }
}
