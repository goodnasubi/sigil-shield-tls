//! ClientHello の解析（ADR 0063 決定 4.3）
//!
//! 表のすべての行の規則を厳密に実装する。
//! メッセージ・legacy_version・random・legacy_session_id・cipher_suites・
//! legacy_compression_methods・拡張の一覧・supported_versions・supported_groups・
//! key_share・signature_algorithms・server_name・application_layer_protocol_negotiation

#![allow(clippy::chunks_exact_to_as_chunks)]

use crate::alert::{AlertDescription, ShieldError};
use crate::curve::is_secp256r1_point_on_curve;
use crate::limits::{
    MAX_ALPN_TOTAL_SIZE, MAX_CIPHER_SUITES_COUNT, MAX_CLIENT_HELLO_SIZE, MAX_EXTENSIONS_COUNT,
    MAX_KEY_SHARE_ENTRIES_COUNT,
};

/// 拡張種別の定数（IANA / RFC 8446）
pub mod extension_type {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 0x0010;
    pub const PRE_SHARED_KEY: u16 = 0x0029;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const KEY_SHARE: u16 = 0x0033;
}

/// NamedGroup の定数
pub mod named_group {
    pub const SECP256R1: u16 = 0x0017;
    pub const X25519: u16 = 0x001d;
}

/// 解析済み ServerName（ADR 0063 決定 2.4）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerName {
    /// 正規化された有効なホスト名（ASCII 小文字）
    Valid(String),
    /// 構文不正または使用不可な名前（末尾のドット、IPリテラル、253バイト超過等）
    /// 一致しない名前と同じ扱いにする
    Invalid(Vec<u8>),
}

/// KeyShare エントリ
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: u16,
    pub key_exchange: Vec<u8>,
}

/// 解析済み ClientHello
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub legacy_compression_methods: Vec<u8>,
    pub server_name: Option<ServerName>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub key_shares: Vec<KeyShareEntry>,
    pub signature_algorithms: Vec<u16>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub extensions_present: Vec<u16>,
}

/// ClientHello メッセージ（4 バイトのハンドシェイクヘッダ含む）を解析する
pub fn parse_client_hello(msg: &[u8]) -> Result<ClientHello, ShieldError> {
    // 全体長が 16 KiB を超えてはならない
    if msg.len() > MAX_CLIENT_HELLO_SIZE {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }

    if msg.len() < 4 {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }

    // メッセージ種別が client_hello (1) であること
    if msg[0] != 0x01 {
        return Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage));
    }

    // 3 バイトの長さが実長と一致し、全てを消費して余りがないこと
    let msg_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
    if msg.len() != 4 + msg_len {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }

    let payload = &msg[4..];
    let mut pos = 0;

    // legacy_version: 0x0303
    if pos + 2 > payload.len() {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    let legacy_version = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    pos += 2;
    if legacy_version != 0x0303 {
        return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
    }

    // random: 32 バイト
    if pos + 32 > payload.len() {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&payload[pos..pos + 32]);
    pos += 32;

    // legacy_session_id: 0〜32 バイト
    if pos >= payload.len() {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    let session_id_len = payload[pos] as usize;
    pos += 1;
    if session_id_len > 32 {
        return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
    }
    if pos + session_id_len > payload.len() {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    let legacy_session_id = payload[pos..pos + session_id_len].to_vec();
    pos += session_id_len;

    // cipher_suites: 長さは偶数で 2〜128 バイト（64 個以下）。未知のものは読み飛ばす
    if pos + 2 > payload.len() {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    let cs_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    if !(2..=MAX_CIPHER_SUITES_COUNT * 2).contains(&cs_len) || !cs_len.is_multiple_of(2) {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    if pos + cs_len > payload.len() {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    for chunk in payload[pos..pos + cs_len].chunks_exact(2) {
        cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    pos += cs_len;

    // legacy_compression_methods: ちょうど 1 バイトで値は 0
    if pos >= payload.len() {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    let comp_len = payload[pos] as usize;
    pos += 1;
    if comp_len != 1 {
        return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
    }
    if pos >= payload.len() {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    if payload[pos] != 0x00 {
        return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
    }
    let legacy_compression_methods = vec![payload[pos]];
    pos += 1;

    // 拡張の一覧
    let mut server_name = None;
    let mut supported_versions = None;
    let mut supported_groups = Vec::new();
    let mut key_shares = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut alpn_protocols = Vec::new();
    let mut extensions_present = Vec::new();

    if pos == payload.len() {
        // 拡張部がない場合、supported_versions が欠如しているため protocol_version
        return Err(ShieldError::Fatal(AlertDescription::ProtocolVersion));
    }

    if pos + 2 > payload.len() {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }
    let ext_total_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    // 全体の長さが残りと一致すること（余りも不足も不可）
    if ext_total_len != payload.len() - pos {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }

    let ext_end = pos + ext_total_len;
    let mut ext_count = 0;
    let mut psk_seen = false;

    while pos < ext_end {
        if pos + 4 > ext_end {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        ext_count += 1;
        // 拡張は 64 個以下
        if ext_count > MAX_EXTENSIONS_COUNT {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        // 同じ種別の重複は拒否
        if extensions_present.contains(&ext_type) {
            return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
        }

        // pre_shared_key があれば最後
        if psk_seen {
            return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
        }
        if ext_type == extension_type::PRE_SHARED_KEY {
            psk_seen = true;
        }

        extensions_present.push(ext_type);
        let ext_data = &payload[pos..pos + ext_len];
        pos += ext_len;

        match ext_type {
            extension_type::SUPPORTED_VERSIONS => {
                // 必須。リストは奇数でなく、偶数バイトで 254 バイト以下。0x0304 がなければ protocol_version
                if ext_data.is_empty() {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let list_len = ext_data[0] as usize;
                if list_len == 0
                    || !list_len.is_multiple_of(2)
                    || list_len > 254
                    || list_len + 1 != ext_data.len()
                {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let mut versions = Vec::with_capacity(list_len / 2);
                let mut has_tls13 = false;
                for chunk in ext_data[1..1 + list_len].chunks_exact(2) {
                    let v = u16::from_be_bytes([chunk[0], chunk[1]]);
                    if v == 0x0304 {
                        has_tls13 = true;
                    }
                    versions.push(v);
                }
                if !has_tls13 {
                    return Err(ShieldError::Fatal(AlertDescription::ProtocolVersion));
                }
                supported_versions = Some(versions);
            }
            extension_type::SUPPORTED_GROUPS => {
                // 偶数バイト。64 個以下（128 バイト以下）。未知のグループは読み飛ばす
                if ext_data.len() < 2 {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if list_len == 0
                    || !list_len.is_multiple_of(2)
                    || list_len > 128
                    || list_len + 2 != ext_data.len()
                {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                for chunk in ext_data[2..2 + list_len].chunks_exact(2) {
                    supported_groups.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                }
            }
            extension_type::KEY_SHARE => {
                // 全体の長さと各項目の長さが一致する。8 項目以下。グループの重複は拒否。
                // x25519 は 32 バイトちょうど。secp256r1 は 65 バイトで先頭が 0x04 かつ曲線上の点
                if ext_data.len() < 2 {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let client_shares_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if client_shares_len + 2 != ext_data.len() {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let mut ks_pos = 2;
                let ks_end = 2 + client_shares_len;
                let mut seen_groups = Vec::new();

                while ks_pos < ks_end {
                    if ks_pos + 4 > ks_end {
                        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                    }
                    let group = u16::from_be_bytes([ext_data[ks_pos], ext_data[ks_pos + 1]]);
                    let key_len =
                        u16::from_be_bytes([ext_data[ks_pos + 2], ext_data[ks_pos + 3]]) as usize;
                    ks_pos += 4;

                    if ks_pos + key_len > ks_end {
                        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                    }

                    if key_shares.len() >= MAX_KEY_SHARE_ENTRIES_COUNT {
                        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                    }

                    // グループの重複は拒否 (illegal_parameter)
                    if seen_groups.contains(&group) {
                        return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
                    }
                    seen_groups.push(group);

                    let key_exchange = ext_data[ks_pos..ks_pos + key_len].to_vec();
                    ks_pos += key_len;

                    match group {
                        named_group::X25519 => {
                            if key_len != 32 {
                                return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
                            }
                        }
                        named_group::SECP256R1
                            if key_len != 65
                                || key_exchange[0] != 0x04
                                || !is_secp256r1_point_on_curve(&key_exchange) =>
                        {
                            return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
                        }
                        _ => {
                            // 未知のグループは読み飛ばす
                        }
                    }

                    key_shares.push(KeyShareEntry {
                        group,
                        key_exchange,
                    });
                }
            }
            extension_type::SIGNATURE_ALGORITHMS => {
                // 偶数バイト。64 個以下
                if ext_data.len() < 2 {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if list_len == 0
                    || !list_len.is_multiple_of(2)
                    || list_len > 128
                    || list_len + 2 != ext_data.len()
                {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                for chunk in ext_data[2..2 + list_len].chunks_exact(2) {
                    signature_algorithms.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                }
            }
            extension_type::SERVER_NAME => {
                // 決定 2.4 の規則。リストの長さと名前の長さが一致する。
                // ホスト名を 1 つだけ含む。重複する種別や複数の名前は illegal_parameter
                if ext_data.len() < 2 {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let sn_list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if sn_list_len + 2 != ext_data.len() {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                if sn_list_len < 3 {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let name_type = ext_data[2];
                // RFC 6066: host_name は 0
                if name_type != 0 {
                    return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
                }
                let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                // リスト内に 1 つの名前のみ。余りや不足があれば illegal_parameter または decode_error
                if 2 + 3 + name_len != ext_data.len() {
                    return Err(ShieldError::Fatal(AlertDescription::IllegalParameter));
                }

                let raw_name = &ext_data[5..5 + name_len];
                server_name = Some(parse_and_validate_sni_hostname(raw_name));
            }
            extension_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                // 各名前は 1〜255 バイト。合計 1 KiB 以下
                if ext_data.len() < 2 {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let alpn_list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if alpn_list_len + 2 != ext_data.len()
                    || alpn_list_len > MAX_ALPN_TOTAL_SIZE
                    || alpn_list_len == 0
                {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
                let mut alpn_pos = 2;
                let alpn_end = 2 + alpn_list_len;
                while alpn_pos < alpn_end {
                    let proto_len = ext_data[alpn_pos] as usize;
                    alpn_pos += 1;
                    if proto_len == 0 || alpn_pos + proto_len > alpn_end {
                        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                    }
                    alpn_protocols.push(ext_data[alpn_pos..alpn_pos + proto_len].to_vec());
                    alpn_pos += proto_len;
                }
            }
            _ => {
                // 未知の拡張は長さだけ検査して読み飛ばす
            }
        }
    }

    // supported_versions は必須
    let supported_versions =
        supported_versions.ok_or(ShieldError::Fatal(AlertDescription::ProtocolVersion))?;

    Ok(ClientHello {
        legacy_version,
        random,
        legacy_session_id,
        cipher_suites,
        legacy_compression_methods,
        server_name,
        supported_versions,
        supported_groups,
        key_shares,
        signature_algorithms,
        alpn_protocols,
        extensions_present,
    })
}

/// SNI ホスト名を検証・正規化する（決定 2.4）
///
/// 名前は ASCII の小文字に正規化する。
/// 末尾の `.`、IP アドレスのリテラル、使えない文字、253 バイトを超える長さ、
/// 63 バイトを超えるラベルは「一致しない名前と同じ（Invalid）」扱いにする。
fn parse_and_validate_sni_hostname(raw: &[u8]) -> ServerName {
    if raw.is_empty() || raw.len() > 253 {
        return ServerName::Invalid(raw.to_vec());
    }

    // 末尾の `.` は不一致扱い
    if raw.ends_with(b".") {
        return ServerName::Invalid(raw.to_vec());
    }

    // UTF-8 / ASCII 文字列への変換
    let s = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return ServerName::Invalid(raw.to_vec()),
    };

    // IP アドレスリテラルの検査 (IPv4 または IPv6)
    if s.parse::<std::net::IpAddr>().is_ok() {
        return ServerName::Invalid(raw.to_vec());
    }

    // ラベルの検査と正規化
    let mut normalized = String::with_capacity(s.len());
    let mut first_label = true;

    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return ServerName::Invalid(raw.to_vec());
        }

        if !first_label {
            normalized.push('.');
        }
        first_label = false;

        for ch in label.chars() {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                normalized.push(ch.to_ascii_lowercase());
            } else {
                return ServerName::Invalid(raw.to_vec());
            }
        }
    }

    ServerName::Valid(normalized)
}
