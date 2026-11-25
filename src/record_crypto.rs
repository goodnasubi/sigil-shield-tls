//! TLS 1.3 保護レコード (ADR 0063 決定 1.3, RFC 8446 §5.2, §5.3)
//!
//! - 方向別の 64 ビットシーケンス番号（1 つの鍵ごとに 0 から開始、鍵更新で 0 にリセット）
//! - Nonce の構成 (12 バイト IV と 64 ビットシーケンス番号の XOR)
//! - レコード暗号化 (5 バイトヘッダ AAD、内部平文構築、末尾パディング対応)
//! - レコード復号と検査:
//!   - 内部平文 2^14 + 1 (16,385) バイト以下、平文断片 2^14 (16,384) バイト以下、暗号文 2^14 + 256 (16,640) バイト以下
//!   - 内部平文が全ゼロなら unexpected_message
//!   - ハンドシェイクの平文断片長 0 なら decode_error (RFC 8446 §5.1)
//!   - AEAD 認証失敗時は bad_record_mac で即座に終了し読み続けない (poisoning)

use crate::alert::{AlertDescription, ShieldError};
use crate::cipher_suite::CipherSuite;
use crate::key_schedule::KeySchedule;
use crate::limits::{MAX_ENCRYPTED_RECORD_PAYLOAD, MAX_PLAIN_RECORD_PAYLOAD};
use crate::record::{parse_record_header, ContentType};

/// レコードの転送方向 (送信または受信)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDirection {
    Transmit,
    Receive,
}

/// 64 ビットシーケンス番号と 12 バイト IV から Nonce を構成する (RFC 8446 §5.3)
pub fn make_nonce(iv: &[u8; 12], sequence_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = sequence_number.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

/// 保護レコード送受信状態
#[derive(Debug, Clone)]
pub struct RecordProtection {
    pub direction: RecordDirection,
    pub suite: CipherSuite,
    pub traffic_secret: Vec<u8>,
    pub key: Vec<u8>,
    pub iv: [u8; 12],
    pub sequence_number: u64,
    /// AEAD 認証失敗フラグ: 失敗時は true となり以降の処理を遮断する
    pub is_poisoned: bool,
}

impl RecordProtection {
    pub fn new(
        direction: RecordDirection,
        suite: CipherSuite,
        traffic_secret: Vec<u8>,
        key_schedule: &KeySchedule,
    ) -> Self {
        let (key, iv) = key_schedule.derive_traffic_key_iv(&traffic_secret);
        Self {
            direction,
            suite,
            traffic_secret,
            key,
            iv,
            sequence_number: 0,
            is_poisoned: false,
        }
    }

    /// レコードの暗号化
    ///
    /// 戻り値: 外側 5 バイトヘッダ + 暗号文 + 16 バイト認証タグ
    pub fn seal_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        padding_len: usize,
    ) -> Result<Vec<u8>, ShieldError> {
        if self.is_poisoned {
            return Err(ShieldError::Fatal(AlertDescription::InternalError));
        }

        // 平文断片長検査 (2^14 バイト以下)
        if plaintext.len() > MAX_PLAIN_RECORD_PAYLOAD {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        // 長さ 0 のハンドシェイク断片は拒否する (RFC 8446 §5.1)
        if content_type == ContentType::Handshake && plaintext.is_empty() {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        // TLSInnerPlaintext の構築: content || type || zeros(padding_len)
        let inner_len = match plaintext
            .len()
            .checked_add(1)
            .and_then(|l| l.checked_add(padding_len))
        {
            Some(len) => len,
            None => return Err(ShieldError::Fatal(AlertDescription::DecodeError)),
        };

        // RFC 8446 §5.4: TLSInnerPlaintext の長さは 2^14 + 1 バイト以下
        if inner_len > MAX_PLAIN_RECORD_PAYLOAD + 1 {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        let encrypted_len = inner_len + self.suite.tag_len();

        if encrypted_len > MAX_ENCRYPTED_RECORD_PAYLOAD {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        let mut inner_plaintext = Vec::with_capacity(inner_len);
        inner_plaintext.extend_from_slice(plaintext);
        inner_plaintext.push(content_type as u8);
        inner_plaintext.resize(inner_len, 0);

        // 外側レコードヘッダ (5 バイト): ContentType::ApplicationData (0x17), 0x0303, encrypted_len
        let aad = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            (encrypted_len >> 8) as u8,
            (encrypted_len & 0xff) as u8,
        ];

        let nonce = make_nonce(&self.iv, self.sequence_number);
        let ciphertext_and_tag = self.suite.seal(&self.key, &nonce, &aad, &inner_plaintext)?;

        self.sequence_number += 1;

        let mut record = Vec::with_capacity(5 + ciphertext_and_tag.len());
        record.extend_from_slice(&aad);
        record.extend_from_slice(&ciphertext_and_tag);
        Ok(record)
    }

    /// 保護レコードの復号と検査
    ///
    /// 戻り値: (内部 ContentType, 復号平文, 消費したレコード長)
    pub fn open_record(
        &mut self,
        record_bytes: &[u8],
    ) -> Result<(ContentType, Vec<u8>, usize), ShieldError> {
        // すでに認証失敗している場合は即座に遮断し読み続けない
        if self.is_poisoned {
            return Err(ShieldError::Fatal(AlertDescription::BadRecordMac));
        }

        if record_bytes.len() < 5 {
            return Err(ShieldError::Incomplete {
                needed: 5 - record_bytes.len(),
            });
        }

        let header = parse_record_header(record_bytes, true)?;

        // 保護レコードの外側種別は application_data でなければならない
        if header.content_type != ContentType::ApplicationData {
            return Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage));
        }

        let encrypted_len = header.length as usize;
        // 少なくとも 16 バイトタグ + 1 バイト内部種別が必要
        if encrypted_len < self.suite.tag_len() + 1 {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        let total_record_len = 5 + encrypted_len;
        if record_bytes.len() < total_record_len {
            return Err(ShieldError::Incomplete {
                needed: total_record_len - record_bytes.len(),
            });
        }

        let aad = &record_bytes[..5];
        let ciphertext_and_tag = &record_bytes[5..total_record_len];
        let nonce = make_nonce(&self.iv, self.sequence_number);

        let inner_plaintext = match self.suite.open(&self.key, &nonce, aad, ciphertext_and_tag) {
            Ok(pt) => pt,
            Err(e) => {
                // 認証失敗時は即座に毒入れ (poisoning) し以降読み続けない
                self.is_poisoned = true;
                return Err(e);
            }
        };

        // 内部平文長検査 (RFC 8446 §5.4: TLSInnerPlaintext の長さは 2^14 + 1 バイト以下)
        if inner_plaintext.len() > MAX_PLAIN_RECORD_PAYLOAD + 1 {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        // 内部平文のパース: 末尾の 0 パディングを除去し最後の非ゼロバイトを種別とする
        let last_nonzero = inner_plaintext.iter().rposition(|&b| b != 0);
        let type_idx = match last_nonzero {
            Some(idx) => idx,
            None => {
                // 内部平文が全ゼロ (種別を持たない) -> unexpected_message
                return Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage));
            }
        };

        let inner_type_byte = inner_plaintext[type_idx];
        let inner_content_type = ContentType::from_u8(inner_type_byte)
            .ok_or(ShieldError::Fatal(AlertDescription::UnexpectedMessage))?;

        let plain_fragment = &inner_plaintext[..type_idx];

        // 長さ 0 のハンドシェイク断片は拒否する (RFC 8446 §5.1)
        if inner_content_type == ContentType::Handshake && plain_fragment.is_empty() {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        // 平文断片長検査 (2^14 バイト以下)
        if plain_fragment.len() > MAX_PLAIN_RECORD_PAYLOAD {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }

        self.sequence_number += 1;
        Ok((
            inner_content_type,
            plain_fragment.to_vec(),
            total_record_len,
        ))
    }

    /// 鍵更新の適用:
    /// - 次世代 Traffic Secret を "traffic upd" で導出
    /// - 新しい key と iv を導出
    /// - シーケンス番号を 0 にリセット
    pub fn update_key(&mut self, key_schedule: &KeySchedule) {
        self.traffic_secret = key_schedule.next_traffic_secret(&self.traffic_secret);
        let (new_key, new_iv) = key_schedule.derive_traffic_key_iv(&self.traffic_secret);
        self.key = new_key;
        self.iv = new_iv;
        self.sequence_number = 0;
    }
}
