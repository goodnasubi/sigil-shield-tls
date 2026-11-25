//! TLS レコード層の読み取りと再構成（ADR 0063 決定 4.2, 4.4）
//!
//! - 先頭 5 バイトの検査（種別・旧版・長さ）
//! - ハンドシェイクメッセージの再構成（最大 16 KiB、最大 8 レコード）
//! - 長さ 0 のハンドシェイクレコードの拒否
//! - 暗号化後の長さ 0 の application_data の連続 16 個制限
//! - ハンドシェイク前の読み取り総量 32 KiB 制限
//! - 消費せずに繰り返さない不変条件（決定 4.4）

use crate::alert::{AlertDescription, ShieldError};
use crate::limits::{
    MAX_CLIENT_HELLO_SIZE, MAX_CONSECUTIVE_EMPTY_APP_DATA, MAX_ENCRYPTED_RECORD_PAYLOAD,
    MAX_HANDSHAKE_READ_TOTAL, MAX_HANDSHAKE_RECORD_COUNT, MAX_PLAIN_RECORD_PAYLOAD,
};

/// TLS レコード種別（ContentType, RFC 8446 §5.1）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 0x14, // 20
    Alert = 0x15,            // 21
    Handshake = 0x16,        // 22
    ApplicationData = 0x17,  // 23
}

impl ContentType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x14 => Some(Self::ChangeCipherSpec),
            0x15 => Some(Self::Alert),
            0x16 => Some(Self::Handshake),
            0x17 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// TLS レコードヘッダ（5 バイト）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub content_type: ContentType,
    pub legacy_version: u16,
    pub length: u16,
}

/// レコードの先頭 5 バイトを検査する（決定 4.2）
pub fn parse_record_header(buf: &[u8], is_encrypted: bool) -> Result<RecordHeader, ShieldError> {
    if buf.len() < 5 {
        return Err(ShieldError::Incomplete {
            needed: 5 - buf.len(),
        });
    }

    // 種別が既知（change_cipher_spec, alert, handshake, application_data）であること
    let content_type = match ContentType::from_u8(buf[0]) {
        Some(ct) => ct,
        None => return Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage)),
    };

    // 旧版が 0x0301 (TLS 1.0) または 0x0303 (TLS 1.2) であること
    let legacy_version = u16::from_be_bytes([buf[1], buf[2]]);
    if legacy_version != 0x0301 && legacy_version != 0x0303 {
        return Err(ShieldError::Fatal(AlertDescription::ProtocolVersion));
    }

    // 長さの検査: 2^14 (平文) または 2^14 + 256 (暗号化後)
    let length = u16::from_be_bytes([buf[3], buf[4]]);
    let max_len = if is_encrypted {
        MAX_ENCRYPTED_RECORD_PAYLOAD
    } else {
        MAX_PLAIN_RECORD_PAYLOAD
    };

    if length as usize > max_len {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }

    // 長さ 0 のハンドシェイクレコードは拒否する (RFC 8446 §5.1, 決定 4.2)
    if content_type == ContentType::Handshake && length == 0 {
        return Err(ShieldError::Fatal(AlertDescription::DecodeError));
    }

    Ok(RecordHeader {
        content_type,
        legacy_version,
        length,
    })
}

/// ハンドシェイクメッセージの再構成器
#[derive(Debug, Default)]
pub struct HandshakeReassembler {
    /// 未処理の入力ストリームバッファ
    stream_buf: Vec<u8>,
    /// 再構成中のハンドシェイクメッセージバッファ
    assembled_bytes: Vec<u8>,
    /// 期待されるハンドシェイクメッセージ全体の長さ（ヘッダ4バイト含む）
    expected_message_len: Option<usize>,
    /// 読み取ったレコード数
    record_count: usize,
    /// ハンドシェイク完了までに読み取った総バイト数
    total_read_bytes: usize,
    /// 暗号化後の長さ 0 の application_data レコードの連続受信回数
    consecutive_empty_app_data: usize,
}

impl HandshakeReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// 総読み取りバイト数
    pub fn total_read_bytes(&self) -> usize {
        self.total_read_bytes
    }

    /// 処理したレコード数
    pub fn record_count(&self) -> usize {
        self.record_count
    }

    /// 入力バイト列を受け取り、再構成を進める。
    ///
    /// 不変条件（決定 4.4）:
    /// - 入力バイト列 `input` が空でない場合、必ず内部バッファに取り込み前進する。
    /// - 読み取り総量上限 32 KiB を超過した場合はエラーで終了する。
    ///
    /// 完全な ClientHello メッセージが完成した場合、4 バイトのハンドシェイクヘッダを含む
    /// バイト列を `Some(Vec<u8>)` で返す。
    pub fn feed_bytes(&mut self, input: &[u8]) -> Result<Option<Vec<u8>>, ShieldError> {
        if input.is_empty() {
            // 入力 0 バイトで前進しない呼び出しは終了
            return Err(ShieldError::TimeoutOrNoProgress);
        }

        // ハンドシェイク前の読み取り総量上限（32 KiB）の検査
        self.total_read_bytes = self
            .total_read_bytes
            .checked_add(input.len())
            .ok_or_else(ShieldError::decode_error)?;

        if self.total_read_bytes > MAX_HANDSHAKE_READ_TOTAL {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        self.stream_buf.extend_from_slice(input);

        // レコードを順次解析して再構成
        loop {
            if self.stream_buf.len() < 5 {
                // ヘッダに足りないため、さらに入力を待つ（前進済み）
                return Ok(None);
            }

            // 先頭 5 バイトを検査
            let header = parse_record_header(&self.stream_buf[..5], false)?;
            let record_len = header.length as usize;
            let full_record_len = 5 + record_len;

            if self.stream_buf.len() < full_record_len {
                // レコード全体の到着を待つ
                return Ok(None);
            }

            // 1 レコード分を消費
            let record_payload = self.stream_buf[5..full_record_len].to_vec();
            self.stream_buf.drain(..full_record_len);

            // 長さ 0 の application_data の検査（暗号化前でも安全のため同様に追跡）
            if header.content_type == ContentType::ApplicationData && record_len == 0 {
                self.consecutive_empty_app_data += 1;
                if self.consecutive_empty_app_data > MAX_CONSECUTIVE_EMPTY_APP_DATA {
                    return Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage));
                }
                continue;
            } else {
                self.consecutive_empty_app_data = 0;
            }

            // 再構成の途中に他の種別のレコードが割り込んだら unexpected_message
            if !self.assembled_bytes.is_empty() && header.content_type != ContentType::Handshake {
                return Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage));
            }

            if header.content_type != ContentType::Handshake {
                // ClientHello 再構成段階で Handshake 以外のレコードが単体で届いた場合
                // （例えば予期しない Alert や ApplicationData）
                return Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage));
            }

            // ハンドシェイクレコードの処理
            self.record_count += 1;
            if self.record_count > MAX_HANDSHAKE_RECORD_COUNT {
                return Err(ShieldError::Fatal(AlertDescription::DecodeError));
            }

            self.assembled_bytes.extend_from_slice(&record_payload);

            // ClientHello 1 つにつき最大 16 KiB
            if self.assembled_bytes.len() > MAX_CLIENT_HELLO_SIZE {
                return Err(ShieldError::Fatal(AlertDescription::DecodeError));
            }

            // ヘッダ（先頭 4 バイト: HandshakeType 1 byte + Length 3 bytes）が揃ったら長さを確定
            if self.expected_message_len.is_none() && self.assembled_bytes.len() >= 4 {
                let msg_len = ((self.assembled_bytes[1] as usize) << 16)
                    | ((self.assembled_bytes[2] as usize) << 8)
                    | (self.assembled_bytes[3] as usize);
                let full_msg_len = 4 + msg_len;

                if full_msg_len > MAX_CLIENT_HELLO_SIZE {
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }

                self.expected_message_len = Some(full_msg_len);
            }

            if let Some(expected_len) = self.expected_message_len {
                if self.assembled_bytes.len() == expected_len {
                    // 完成
                    let result = std::mem::take(&mut self.assembled_bytes);
                    self.expected_message_len = None;
                    return Ok(Some(result));
                } else if self.assembled_bytes.len() > expected_len {
                    // 長さの食い違い（超過）
                    return Err(ShieldError::Fatal(AlertDescription::DecodeError));
                }
            }
        }
    }
}
