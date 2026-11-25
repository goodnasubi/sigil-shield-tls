//! ClientHello 解析の試験（ADR 0063 決定 4.3）
//!
//! 決定 4.3 の表の全行の正常系・負の例を網羅的に試験する。

mod common;

use common::build_valid_client_hello;
use sigil_shield_tls::alert::{AlertDescription, ShieldError};
use sigil_shield_tls::client_hello::{extension_type, named_group, parse_client_hello, ServerName};

#[test]
fn test_valid_client_hello_parses_successfully() {
    let msg = build_valid_client_hello();
    let ch = parse_client_hello(&msg).expect("valid ClientHello should parse");

    assert_eq!(ch.legacy_version, 0x0303);
    assert_eq!(ch.random, [0x42; 32]);
    assert_eq!(ch.legacy_session_id.len(), 32);
    assert_eq!(ch.cipher_suites.len(), 3);
    assert_eq!(ch.legacy_compression_methods, vec![0x00]);
    assert_eq!(ch.supported_versions, vec![0x0304]);
    assert_eq!(
        ch.server_name,
        Some(ServerName::Valid("example.com".to_string()))
    );
    assert_eq!(ch.key_shares.len(), 1);
    assert_eq!(ch.key_shares[0].group, named_group::X25519);
    assert_eq!(ch.alpn_protocols, vec![b"http/1.1".to_vec()]);
}

// 1. メッセージヘッダの試験
#[test]
fn test_message_header_invalid_type() {
    let mut msg = build_valid_client_hello();
    msg[0] = 0x02; // ServerHello (not ClientHello)
    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage))
    );
}

#[test]
fn test_message_header_length_mismatch() {
    let mut msg = build_valid_client_hello();
    // 余りがある場合（実長より小さい長さをヘッダに記載）
    let orig_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
    let shorter_len = orig_len - 1;
    msg[1] = ((shorter_len >> 16) & 0xFF) as u8;
    msg[2] = ((shorter_len >> 8) & 0xFF) as u8;
    msg[3] = (shorter_len & 0xFF) as u8;
    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );

    // 不足している場合（実長より大きい長さを記載）
    let longer_len = orig_len + 1;
    msg[1] = ((longer_len >> 16) & 0xFF) as u8;
    msg[2] = ((longer_len >> 8) & 0xFF) as u8;
    msg[3] = (longer_len & 0xFF) as u8;
    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

// 2. legacy_version の試験 (0x0303 のみ、違反は illegal_parameter)
#[test]
fn test_legacy_version() {
    for ver in [0x0301, 0x0302, 0x0304, 0x0200] {
        let mut msg = build_valid_client_hello();
        msg[4] = (ver >> 8) as u8;
        msg[5] = (ver & 0xFF) as u8;
        assert_eq!(
            parse_client_hello(&msg),
            Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
        );
    }
}

// 3. random の試験 (32 バイト、不足は decode_error)
#[test]
fn test_random_truncated() {
    let mut msg = build_valid_client_hello();
    // 32 バイトの random の途中でメッセージを切り詰める
    msg.truncate(20);
    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

// 4. legacy_session_id の試験 (0〜32 バイト、違反は illegal_parameter)
#[test]
fn test_legacy_session_id_zero_length() {
    let mut msg = build_valid_client_hello();
    // session_id を 0 バイトにする
    let sess_id_len_pos = 4 + 2 + 32; // 38
    assert_eq!(msg[sess_id_len_pos], 32);
    // 32 バイトの session_id を削除し、長さを 0 に設定
    msg[sess_id_len_pos] = 0;
    msg.drain(sess_id_len_pos + 1..sess_id_len_pos + 1 + 32);

    // ヘッダのメッセージ長を更新
    let new_len = msg.len() - 4;
    msg[1] = ((new_len >> 16) & 0xFF) as u8;
    msg[2] = ((new_len >> 8) & 0xFF) as u8;
    msg[3] = (new_len & 0xFF) as u8;

    let ch = parse_client_hello(&msg).expect("0-length session id is valid");
    assert_eq!(ch.legacy_session_id.len(), 0);
}

#[test]
fn test_legacy_session_id_exceeds_32_bytes() {
    let mut msg = build_valid_client_hello();
    let sess_id_len_pos = 4 + 2 + 32; // 38
                                      // 長さを 33 に設定
    msg[sess_id_len_pos] = 33;
    msg.insert(sess_id_len_pos + 1, 0x99); // 33 バイト目

    let new_len = msg.len() - 4;
    msg[1] = ((new_len >> 16) & 0xFF) as u8;
    msg[2] = ((new_len >> 8) & 0xFF) as u8;
    msg[3] = (new_len & 0xFF) as u8;

    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
    );
}

// 5. cipher_suites の試験 (長さは偶数で 2〜128 バイト、違反は decode_error)
#[test]
fn test_cipher_suites_odd_length() {
    let mut msg = build_valid_client_hello();
    let cs_pos = 4 + 2 + 32 + 1 + 32; // 71
                                      // 長さを奇数 5 バイトに書き換える
    msg[cs_pos] = 0x00;
    msg[cs_pos + 1] = 0x05;
    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

#[test]
fn test_cipher_suites_zero_length() {
    let mut msg = build_valid_client_hello();
    let cs_pos = 4 + 2 + 32 + 1 + 32;
    msg[cs_pos] = 0x00;
    msg[cs_pos + 1] = 0x00;
    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

#[test]
fn test_cipher_suites_exceeds_128_bytes() {
    let mut msg = build_valid_client_hello();
    let cs_pos = 4 + 2 + 32 + 1 + 32;
    // 65 個 = 130 バイト
    let large_cs = [0x13, 0x01].repeat(65);
    msg.splice(cs_pos + 2..cs_pos + 2 + 6, large_cs.clone());
    let cs_len = large_cs.len() as u16;
    msg[cs_pos] = (cs_len >> 8) as u8;
    msg[cs_pos + 1] = (cs_len & 0xFF) as u8;

    let new_len = msg.len() - 4;
    msg[1] = ((new_len >> 16) & 0xFF) as u8;
    msg[2] = ((new_len >> 8) & 0xFF) as u8;
    msg[3] = (new_len & 0xFF) as u8;

    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

// 6. legacy_compression_methods の試験 (ちょうど 1 バイトで値は 0、違反は illegal_parameter)
#[test]
fn test_legacy_compression_methods() {
    // 0x01, 0x01 (値が 0 ではない)
    let mut msg = build_valid_client_hello();
    let comp_pos = 4 + 2 + 32 + 1 + 32 + 2 + 6; // 79
    msg[comp_pos] = 0x01; // length: 1
    msg[comp_pos + 1] = 0x01; // value: 1
    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
    );

    // 長さが 0
    let mut msg2 = build_valid_client_hello();
    msg2[comp_pos] = 0x00;
    msg2.remove(comp_pos + 1);
    let new_len = msg2.len() - 4;
    msg2[1] = ((new_len >> 16) & 0xFF) as u8;
    msg2[2] = ((new_len >> 8) & 0xFF) as u8;
    msg2[3] = (new_len & 0xFF) as u8;
    assert_eq!(
        parse_client_hello(&msg2),
        Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
    );
}

// 7. 拡張の一覧の試験 (重複は illegal_parameter、PSK は最後、未知の拡張は読み飛ばす)
#[test]
fn test_duplicate_extension_rejected() {
    let mut msg = build_valid_client_hello();
    // 末尾に supported_groups 拡張をもう一度追加して重複させる
    let dup_ext = [0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d];
    msg.extend_from_slice(&dup_ext);

    // 拡張部全体の長さを更新
    let ext_total_len_pos = 4 + 2 + 32 + 1 + 32 + 2 + 6 + 1 + 1;
    let old_ext_len =
        u16::from_be_bytes([msg[ext_total_len_pos], msg[ext_total_len_pos + 1]]) as usize;
    let new_ext_len = (old_ext_len + dup_ext.len()) as u16;
    msg[ext_total_len_pos] = (new_ext_len >> 8) as u8;
    msg[ext_total_len_pos + 1] = (new_ext_len & 0xFF) as u8;

    let new_len = msg.len() - 4;
    msg[1] = ((new_len >> 16) & 0xFF) as u8;
    msg[2] = ((new_len >> 8) & 0xFF) as u8;
    msg[3] = (new_len & 0xFF) as u8;

    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
    );
}

#[test]
fn test_pre_shared_key_not_last_rejected() {
    let mut msg = build_valid_client_hello();
    // PSK 拡張 (0x0029) を先頭の拡張として挿入
    let psk_ext = [0x00, 0x29, 0x00, 0x02, 0x00, 0x00];
    let ext_pos = 4 + 2 + 32 + 1 + 32 + 2 + 6 + 1 + 1 + 2;
    msg.splice(ext_pos..ext_pos, psk_ext);

    let ext_total_len_pos = ext_pos - 2;
    let old_ext_len =
        u16::from_be_bytes([msg[ext_total_len_pos], msg[ext_total_len_pos + 1]]) as usize;
    let new_ext_len = (old_ext_len + psk_ext.len()) as u16;
    msg[ext_total_len_pos] = (new_ext_len >> 8) as u8;
    msg[ext_total_len_pos + 1] = (new_ext_len & 0xFF) as u8;

    let new_len = msg.len() - 4;
    msg[1] = ((new_len >> 16) & 0xFF) as u8;
    msg[2] = ((new_len >> 8) & 0xFF) as u8;
    msg[3] = (new_len & 0xFF) as u8;

    // PSK の後に別の拡張があるので illegal_parameter
    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
    );
}

#[test]
fn test_unknown_extension_skipped() {
    let mut msg = build_valid_client_hello();
    // 未知の拡張 (0x9999, 4 バイトデータ) を追加
    let unknown_ext = [0x99, 0x99, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
    msg.extend_from_slice(&unknown_ext);

    let ext_total_len_pos = 4 + 2 + 32 + 1 + 32 + 2 + 6 + 1 + 1;
    let old_ext_len =
        u16::from_be_bytes([msg[ext_total_len_pos], msg[ext_total_len_pos + 1]]) as usize;
    let new_ext_len = (old_ext_len + unknown_ext.len()) as u16;
    msg[ext_total_len_pos] = (new_ext_len >> 8) as u8;
    msg[ext_total_len_pos + 1] = (new_ext_len & 0xFF) as u8;

    let new_len = msg.len() - 4;
    msg[1] = ((new_len >> 16) & 0xFF) as u8;
    msg[2] = ((new_len >> 8) & 0xFF) as u8;
    msg[3] = (new_len & 0xFF) as u8;

    let ch = parse_client_hello(&msg).expect("unknown extension should be skipped");
    assert!(ch.extensions_present.contains(&0x9999));
}

// 8. supported_versions の試験 (必須、0x0304 がなければ protocol_version)
#[test]
fn test_supported_versions_missing_tls13() {
    let mut msg = build_valid_client_hello();
    // supported_versions の 0x0304 を 0x0303 に書き換え
    // 0x002b 拡張の位置を探す
    let mut found = false;
    for i in 0..msg.len() - 6 {
        if msg[i] == 0x00 && msg[i + 1] == 0x2b && msg[i + 2] == 0x00 && msg[i + 3] == 0x03 {
            msg[i + 5] = 0x03;
            msg[i + 6] = 0x03; // TLS 1.2 only
            found = true;
            break;
        }
    }
    assert!(found);
    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::ProtocolVersion))
    );
}

// 9. key_share の試験 (8 項目以下、重複拒否、x25519 32バイト、secp256r1 65バイト・曲線上の点)
#[test]
fn test_key_share_x25519_invalid_len() {
    let mut msg = build_valid_client_hello();
    // key_share の x25519 を 31 バイトにする
    for i in 0..msg.len() - 8 {
        if msg[i] == 0x00 && msg[i + 1] == 0x33 {
            // key_share ext
            // x25519 length は i + 8, i + 9
            msg[i + 8] = 0x00;
            msg[i + 9] = 0x1f; // 31 bytes
            msg.remove(i + 10); // 1 byte 削除
                                // client_shares_len
            let cs_len = u16::from_be_bytes([msg[i + 4], msg[i + 5]]) - 1;
            msg[i + 4] = (cs_len >> 8) as u8;
            msg[i + 5] = (cs_len & 0xFF) as u8;
            // ext_len
            let ext_len = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) - 1;
            msg[i + 2] = (ext_len >> 8) as u8;
            msg[i + 3] = (ext_len & 0xFF) as u8;
            break;
        }
    }

    let ext_total_len_pos = 4 + 2 + 32 + 1 + 32 + 2 + 6 + 1 + 1;
    let old_ext_len =
        u16::from_be_bytes([msg[ext_total_len_pos], msg[ext_total_len_pos + 1]]) as usize;
    let new_ext_len = (old_ext_len - 1) as u16;
    msg[ext_total_len_pos] = (new_ext_len >> 8) as u8;
    msg[ext_total_len_pos + 1] = (new_ext_len & 0xFF) as u8;

    let new_len = msg.len() - 4;
    msg[1] = ((new_len >> 16) & 0xFF) as u8;
    msg[2] = ((new_len >> 8) & 0xFF) as u8;
    msg[3] = (new_len & 0xFF) as u8;

    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
    );
}

#[test]
fn test_key_share_secp256r1_valid_and_invalid_points() {
    // 正常な secp256r1 点を含む ClientHello
    let mut msg = build_valid_client_hello();
    // secp256r1 生成元 G
    let gx =
        hex::decode("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296").unwrap();
    let gy =
        hex::decode("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5").unwrap();
    let mut g_point = vec![0x04];
    g_point.extend_from_slice(&gx);
    g_point.extend_from_slice(&gy);

    // key_share エントリを secp256r1 に置き換え
    for i in 0..msg.len() - 8 {
        if msg[i] == 0x00 && msg[i + 1] == 0x33 {
            // entry: group(2) + len(2) + data(65) = 69 bytes
            let mut new_entry = Vec::new();
            new_entry.extend_from_slice(&named_group::SECP256R1.to_be_bytes());
            new_entry.extend_from_slice(&(g_point.len() as u16).to_be_bytes());
            new_entry.extend_from_slice(&g_point);

            let old_ext_len = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
            let entry_len = new_entry.len() as u16;
            let ext_len = entry_len + 2;

            let mut new_ks_ext = Vec::new();
            new_ks_ext.extend_from_slice(&extension_type::KEY_SHARE.to_be_bytes());
            new_ks_ext.extend_from_slice(&ext_len.to_be_bytes());
            new_ks_ext.extend_from_slice(&entry_len.to_be_bytes());
            new_ks_ext.extend_from_slice(&new_entry);

            msg.splice(i..i + 4 + old_ext_len, new_ks_ext);
            break;
        }
    }

    // 拡張部全体長とメッセージ長を再計算
    fixup_lengths(&mut msg);

    let ch = parse_client_hello(&msg).expect("valid secp256r1 point");
    assert_eq!(ch.key_shares[0].group, named_group::SECP256R1);

    // 負の例: 曲線上にない点（全ゼロ）に置き換えると illegal_parameter
    let mut bad_msg = msg.clone();
    for i in 0..bad_msg.len() - 65 {
        if bad_msg[i] == 0x04 && &bad_msg[i + 1..i + 33] == gx.as_slice() {
            // 全ゼロに書き換え (先頭 0x04 だけ維持)
            for j in 1..65 {
                bad_msg[i + j] = 0x00;
            }
            break;
        }
    }
    assert_eq!(
        parse_client_hello(&bad_msg),
        Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
    );
}

// 10. server_name の試験 (ホスト名 1 つ、末尾のドットや IP リテラルは Invalid 扱い、複数や重複は illegal_parameter)
#[test]
fn test_server_name_normalization_and_invalid_forms() {
    let mut msg = build_valid_client_hello();
    // 大文字 "EXAMPLE.COM" -> 小文字 "example.com"
    replace_host_name(&mut msg, b"EXAMPLE.COM");
    let ch = parse_client_hello(&msg).expect("valid mixed case host");
    assert_eq!(
        ch.server_name,
        Some(ServerName::Valid("example.com".to_string()))
    );

    // 末尾の `.` -> Invalid (一致しない名前と同じ扱い)
    let mut msg_dot = build_valid_client_hello();
    replace_host_name(&mut msg_dot, b"example.com.");
    let ch_dot = parse_client_hello(&msg_dot).expect("trailing dot parsed");
    assert_eq!(
        ch_dot.server_name,
        Some(ServerName::Invalid(b"example.com.".to_vec()))
    );

    // IPv4 リテラル -> Invalid
    let mut msg_ip = build_valid_client_hello();
    replace_host_name(&mut msg_ip, b"127.0.0.1");
    let ch_ip = parse_client_hello(&msg_ip).expect("ip literal parsed");
    assert_eq!(
        ch_ip.server_name,
        Some(ServerName::Invalid(b"127.0.0.1".to_vec()))
    );
}

fn find_extension_in_msg(msg: &[u8], target_type: u16) -> Option<(usize, usize)> {
    if msg.len() < 4 + 2 + 32 + 1 {
        return None;
    }
    let mut pos = 4 + 2 + 32;
    let sess_len = msg[pos] as usize;
    pos += 1 + sess_len;
    if pos + 2 > msg.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([msg[pos], msg[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= msg.len() {
        return None;
    }
    let comp_len = msg[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > msg.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([msg[pos], msg[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;
    if ext_end > msg.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ext_len = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) as usize;
        if ext_type == target_type {
            return Some((pos, ext_len));
        }
        pos += 4 + ext_len;
    }
    None
}

#[test]
fn test_server_name_multiple_names_rejected() {
    let mut msg = build_valid_client_hello();
    if let Some((i, old_ext_len)) = find_extension_in_msg(&msg, extension_type::SERVER_NAME) {
        let mut list_data = Vec::new();
        list_data.push(0x00);
        list_data.extend_from_slice(&(b"a.com".len() as u16).to_be_bytes());
        list_data.extend_from_slice(b"a.com");
        list_data.push(0x00);
        list_data.extend_from_slice(&(b"b.com".len() as u16).to_be_bytes());
        list_data.extend_from_slice(b"b.com");

        let list_len = list_data.len() as u16;
        let ext_len = list_len + 2;

        let mut new_ext = Vec::new();
        new_ext.extend_from_slice(&extension_type::SERVER_NAME.to_be_bytes());
        new_ext.extend_from_slice(&ext_len.to_be_bytes());
        new_ext.extend_from_slice(&list_len.to_be_bytes());
        new_ext.extend_from_slice(&list_data);

        msg.splice(i..i + 4 + old_ext_len, new_ext);
    }
    fixup_lengths(&mut msg);

    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::IllegalParameter))
    );
}

// 11. ALPN の試験 (1〜255 バイト、合計 1 KiB 以下)
#[test]
fn test_alpn_empty_proto_rejected() {
    let mut msg = build_valid_client_hello();
    if let Some((i, old_ext_len)) =
        find_extension_in_msg(&msg, extension_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
    {
        let new_ext = [0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0x00];
        msg.splice(i..i + 4 + old_ext_len, new_ext);
    }
    fixup_lengths(&mut msg);

    assert_eq!(
        parse_client_hello(&msg),
        Err(ShieldError::Fatal(AlertDescription::DecodeError))
    );
}

fn replace_host_name(msg: &mut Vec<u8>, new_host: &[u8]) {
    if let Some((i, old_ext_len)) = find_extension_in_msg(msg, extension_type::SERVER_NAME) {
        let sn_list_len = (3 + new_host.len()) as u16;
        let ext_len = sn_list_len + 2;
        let mut new_ext = Vec::new();
        new_ext.extend_from_slice(&extension_type::SERVER_NAME.to_be_bytes());
        new_ext.extend_from_slice(&ext_len.to_be_bytes());
        new_ext.extend_from_slice(&sn_list_len.to_be_bytes());
        new_ext.push(0x00);
        new_ext.extend_from_slice(&(new_host.len() as u16).to_be_bytes());
        new_ext.extend_from_slice(new_host);

        msg.splice(i..i + 4 + old_ext_len, new_ext);
    }
    fixup_lengths(msg);
}

fn fixup_lengths(msg: &mut [u8]) {
    let mut pos = 4 + 2 + 32;
    let sess_len = msg[pos] as usize;
    pos += 1 + sess_len;
    let cs_len = u16::from_be_bytes([msg[pos], msg[pos + 1]]) as usize;
    pos += 2 + cs_len;
    let comp_len = msg[pos] as usize;
    pos += 1 + comp_len;

    let ext_total_len_pos = pos;
    let ext_data_len = msg.len() - (ext_total_len_pos + 2);
    msg[ext_total_len_pos] = ((ext_data_len >> 8) & 0xFF) as u8;
    msg[ext_total_len_pos + 1] = (ext_data_len & 0xFF) as u8;

    let total_msg_len = msg.len() - 4;
    msg[1] = ((total_msg_len >> 16) & 0xFF) as u8;
    msg[2] = ((total_msg_len >> 8) & 0xFF) as u8;
    msg[3] = (total_msg_len & 0xFF) as u8;
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        let mut b = Vec::with_capacity(s.len() / 2);
        for i in 0..s.len() / 2 {
            let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
            b.push(byte);
        }
        Ok(b)
    }
}
