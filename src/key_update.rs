//! TLS 1.3 鍵更新 (ADR 0063 決定 1.3, RFC 8446 §4.6.3, §5.5)
//!
//! - KeyUpdate ハンドシェイクメッセージ (type 24, length 1, request_update = 0 または 1)
//! - 送信レコード数が 2^23 に達する前の更新トリガー、更新できず 2^23 超過時の終了
//! - 受信 KeyUpdate の受理、update_requested 時の送信鍵更新と応答、接続あたり 16 回制限（超過時 unexpected_message）

use crate::alert::{AlertDescription, ShieldError};
use crate::limits::MAX_KEY_UPDATE_COUNT;

/// 送信レコード数の上限 (2^23 = 8,388,608 レコード)
pub const KEY_UPDATE_TX_LIMIT: u64 = 1 << 23;

/// KeyUpdate 要求種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyUpdateRequest {
    UpdateNotRequested = 0,
    UpdateRequested = 1,
}

impl KeyUpdateRequest {
    pub fn from_u8(value: u8) -> Result<Self, ShieldError> {
        match value {
            0 => Ok(Self::UpdateNotRequested),
            1 => Ok(Self::UpdateRequested),
            _ => Err(ShieldError::Fatal(AlertDescription::IllegalParameter)),
        }
    }
}

/// KeyUpdate ハンドシェイクメッセージ (5 バイト)
/// - 1 バイト: ハンドシェイク種別 24 (0x18)
/// - 3 バイト: 長さ (0x000001)
/// - 1 バイト: request_update (0 または 1)
pub struct KeyUpdateMessage;

impl KeyUpdateMessage {
    pub const HANDSHAKE_TYPE: u8 = 24;

    /// KeyUpdate メッセージのエンコード (5 バイト)
    pub fn encode(request: KeyUpdateRequest) -> [u8; 5] {
        [Self::HANDSHAKE_TYPE, 0x00, 0x00, 0x01, request as u8]
    }

    /// KeyUpdate メッセージのデコード
    pub fn decode(buf: &[u8]) -> Result<KeyUpdateRequest, ShieldError> {
        if buf.len() < 5 {
            return Err(ShieldError::Incomplete {
                needed: 5 - buf.len(),
            });
        }
        if buf[0] != Self::HANDSHAKE_TYPE {
            return Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage));
        }
        let length = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
        if length != 1 {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }
        if buf.len() > 5 {
            return Err(ShieldError::Fatal(AlertDescription::DecodeError));
        }
        KeyUpdateRequest::from_u8(buf[4])
    }
}

/// 鍵更新追跡器
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUpdateTracker {
    /// 現在の送信鍵で送信したレコード数
    pub records_sent: u64,
    /// 受信した KeyUpdate メッセージの累積回数
    pub received_key_update_count: usize,
}

impl Default for KeyUpdateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyUpdateTracker {
    pub fn new() -> Self {
        Self {
            records_sent: 0,
            received_key_update_count: 0,
        }
    }

    /// レコード送信が可能か検査（2^23 に達して更新されないまま超過した場合はエラー）
    pub fn can_send_record(&self) -> Result<(), ShieldError> {
        if self.records_sent >= KEY_UPDATE_TX_LIMIT {
            // 2^23 を超える場合は接続を終える (ADR 0063 決定 1.3)
            return Err(ShieldError::Fatal(AlertDescription::InternalError));
        }
        Ok(())
    }

    /// 送信レコード数が 2^23 に達する前の更新トリガーか判定
    /// （2^23 - 1 に達した時点で更新を推奨/トリガー）
    pub fn should_trigger_tx_update(&self) -> bool {
        self.records_sent >= KEY_UPDATE_TX_LIMIT - 1
    }

    /// レコード送信を記録し、鍵更新が必要かを返す
    pub fn record_sent(&mut self) -> Result<bool, ShieldError> {
        self.can_send_record()?;
        self.records_sent += 1;
        Ok(self.should_trigger_tx_update())
    }

    /// 送信鍵の更新完了時に呼び出し、レコード数を 0 にリセット
    pub fn on_tx_key_updated(&mut self) {
        self.records_sent = 0;
    }

    /// 受信した KeyUpdate を処理する
    ///
    /// 戻り値:
    /// - `Ok(true)`: update_requested であり、送信鍵の更新と応答が必要
    /// - `Ok(false)`: update_not_requested であり、受信鍵のみ更新が必要
    /// - `Err`: 16 回超過時 (unexpected_message) またはパース不正
    pub fn handle_received_key_update(
        &mut self,
        request: KeyUpdateRequest,
    ) -> Result<bool, ShieldError> {
        self.received_key_update_count += 1;
        // 受信する KeyUpdate は接続あたり 16 回まで (ADR 0063 決定 1.3, 決定 4.5)
        if self.received_key_update_count > MAX_KEY_UPDATE_COUNT {
            return Err(ShieldError::Fatal(AlertDescription::UnexpectedMessage));
        }

        Ok(request == KeyUpdateRequest::UpdateRequested)
    }
}
