//! TLS 1.3 ハンドシェイクの状態機械（ADR 0063 決定 1、決定 1.2、決定 1.4）
//!
//! サーバー側の 1-RTT ハンドシェイクを扱う。
//!
//! - `ClientHello` → `ServerHello`（または `HelloRetryRequest` の後に 2 つ目の `ClientHello`）
//!   → `EncryptedExtensions` → `Certificate` → `CertificateVerify` → `Finished`
//!   → クライアントの `Finished`
//! - 鍵交換は `x25519`（段 3）。`secp256r1` は段 6 で [`KeyAgreement`] として加える。
//! - サーバー署名は `ecdsa_secp256r1_sha256` のみ（[`EcdsaP256Signer`]）。
//! - ALPN は `http/1.1` だけを選ぶ。
//! - PSK・0-RTT は受理しない。`pre_shared_key` は構造だけ検査して無視し、完全ハンドシェイクを行う。
//!   早期データのレコードは読み飛ばさず、致命的アラートで終える（読み飛ばしの予算は 0）。
//! - 互換モード（RFC 8446 付録 D.4）: `legacy_session_id` をそのまま返し、サーバーの最初の
//!   ハンドシェイクメッセージの直後に ChangeCipherSpec を 1 つ送る。クライアントの
//!   ChangeCipherSpec は ClientHello の後から Finished の前までに 1 つだけ受理して捨てる。
//!
//! 乱数・署名・鍵交換は呼び出し側から差し込む（[`RandomSource`]、[`Signer`]、[`KeyAgreement`]）。
//! 状態機械そのものは入出力を持たず、受け取ったバイト列から返すバイト列を作る。

use crate::alert::{Alert, AlertDescription, ShieldError};
use crate::cipher_suite::{CipherSuite, SERVER_PREFERENCE_ORDER};
use crate::client_hello::{
    extension_type, named_group, parse_client_hello, ClientHello, ServerName,
};
use crate::crypto::{
    ct_eq, ecdsa_p256_public_key, ecdsa_p256_sign, hmac_sha256, hmac_sha384, scalar_in_range,
    sha256, sha384, signature_to_der, wipe, x25519, x25519_public_key,
};
use crate::key_schedule::KeySchedule;
use crate::limits::{MAX_CERT_CHAIN_COUNT, MAX_HANDSHAKE_READ_TOTAL, MAX_PLAIN_RECORD_PAYLOAD};
use crate::record::{parse_record_header, ContentType, HandshakeReassembler};
use crate::record_crypto::{RecordDirection, RecordProtection};

/// `ecdsa_secp256r1_sha256`（RFC 8446 §4.2.3）
pub const SIGNATURE_ECDSA_SECP256R1_SHA256: u16 = 0x0403;

/// 選ぶ ALPN の値
pub const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// HelloRetryRequest の `random`（SHA-256("HelloRetryRequest")、RFC 8446 §4.1.3）
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_MESSAGE_HASH: u8 = 254;

/// 乱数の供給元。呼び出し側が OS の乱数などを差し込む。
pub trait RandomSource {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), ShieldError>;
}

/// 鍵交換の結果
pub struct KeyAgreementOutput {
    /// ServerHello の `key_share` に載せるサーバーの公開値
    pub server_share: Vec<u8>,
    /// 共有秘密（使い終わりに消去される）
    pub shared_secret: Vec<u8>,
}

impl Drop for KeyAgreementOutput {
    fn drop(&mut self) {
        wipe(&mut self.shared_secret);
    }
}

/// 1 つの名前付きグループの鍵交換
pub trait KeyAgreement {
    fn group(&self) -> u16;
    /// クライアントの公開値からサーバーの公開値と共有秘密を作る。
    /// 公開値が不正、または共有秘密が使えない（低位の点など）ときは `illegal_parameter`。
    fn agree(
        &self,
        rng: &mut dyn RandomSource,
        client_share: &[u8],
    ) -> Result<KeyAgreementOutput, ShieldError>;
}

/// `x25519`（RFC 7748）
pub struct X25519Agreement;

impl KeyAgreement for X25519Agreement {
    fn group(&self) -> u16 {
        named_group::X25519
    }

    fn agree(
        &self,
        rng: &mut dyn RandomSource,
        client_share: &[u8],
    ) -> Result<KeyAgreementOutput, ShieldError> {
        let peer: [u8; 32] = client_share
            .try_into()
            .map_err(|_| ShieldError::illegal_parameter())?;
        let mut private = [0u8; 32];
        rng.fill(&mut private)?;
        let public = x25519_public_key(&private);
        let mut shared = x25519(&private, &peer);
        wipe(&mut private);
        // 低位の点との鍵交換は全ゼロになる。RFC 8446 §7.4.2 / RFC 7748 §6.1 により中止する
        let zero = shared.iter().fold(0u8, |acc, b| acc | b) == 0;
        if zero {
            wipe(&mut shared);
            return Err(ShieldError::illegal_parameter());
        }
        let out = KeyAgreementOutput {
            server_share: public.to_vec(),
            shared_secret: shared.to_vec(),
        };
        wipe(&mut shared);
        Ok(out)
    }
}

/// `CertificateVerify` の署名
pub trait Signer {
    /// SignatureScheme の値
    fn scheme(&self) -> u16;
    /// 署名対象（64 個の 0x20 + 文脈文字列 + 0x00 + トランスクリプトのハッシュ）を署名する
    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, ShieldError>;
}

/// `ecdsa_secp256r1_sha256` の署名（SHA-256、RFC 6979 の決定的 nonce）
pub struct EcdsaP256Signer {
    private: [u8; 32],
}

impl EcdsaP256Signer {
    /// 秘密のスカラー（32 バイトのビッグエンディアン、1 <= d < n）から作る
    pub fn new(private: [u8; 32]) -> Option<Self> {
        if scalar_in_range(&private) {
            Some(Self { private })
        } else {
            None
        }
    }

    /// SEC1 の非圧縮点（65 バイト）
    pub fn public_key(&self) -> [u8; 65] {
        ecdsa_p256_public_key(&self.private)
    }
}

impl Drop for EcdsaP256Signer {
    fn drop(&mut self) {
        wipe(&mut self.private);
    }
}

impl Signer for EcdsaP256Signer {
    fn scheme(&self) -> u16 {
        SIGNATURE_ECDSA_SECP256R1_SHA256
    }

    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, ShieldError> {
        let sig =
            ecdsa_p256_sign(&self.private, content).ok_or_else(ShieldError::internal_error)?;
        Ok(signature_to_der(&sig))
    }
}

/// サーバーの設定
pub struct ServerConfig {
    /// スイートの優先順（既定は ADR 0063 決定 1 の順）
    pub cipher_preference: Vec<CipherSuite>,
    /// 鍵交換の優先順（既定は `x25519` だけ）
    pub key_agreements: Vec<Box<dyn KeyAgreement>>,
    /// 証明書（DER）。先頭が末端の証明書。
    pub certificate_chain: Vec<Vec<u8>>,
    pub signer: Box<dyn Signer>,
    /// `EncryptedExtensions` の先頭に追加する拡張（種別, 本体）。ALPN の前に並べる。
    pub extra_encrypted_extensions: Vec<(u16, Vec<u8>)>,
    /// HelloRetryRequest に載せる `cookie`。ADR 0063 は cookie を使わないので既定は `None`。
    /// 載せた場合、2 つ目の ClientHello が同じ値を返すことを検査する。
    pub hrr_cookie: Option<Vec<u8>>,
}

impl ServerConfig {
    pub fn new(certificate_chain: Vec<Vec<u8>>, signer: Box<dyn Signer>) -> Self {
        Self {
            cipher_preference: SERVER_PREFERENCE_ORDER.to_vec(),
            key_agreements: vec![Box::new(X25519Agreement)],
            certificate_chain,
            signer,
            extra_encrypted_extensions: Vec::new(),
            hrr_cookie: None,
        }
    }

    fn validate(&self) -> Result<(), ShieldError> {
        if self.certificate_chain.is_empty()
            || self.certificate_chain.len() > MAX_CERT_CHAIN_COUNT
            || self
                .certificate_chain
                .iter()
                .any(|c| c.is_empty() || c.len() >= 1 << 24)
            || self.cipher_preference.is_empty()
            || self.key_agreements.is_empty()
        {
            return Err(ShieldError::internal_error());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    ExpectClientHello1,
    ExpectClientHello2,
    ExpectClientFinished,
    Complete,
    Failed,
}

/// ハンドシェイクが終わった後の鍵と交渉結果
pub struct HandshakeOutcome {
    pub suite: CipherSuite,
    /// サーバーからクライアントへ送るアプリケーションデータの保護（シーケンス番号 0）
    pub transmit: RecordProtection,
    /// クライアントからサーバーへ届くアプリケーションデータの保護（シーケンス番号 0）
    pub receive: RecordProtection,
    pub server_name: Option<ServerName>,
    /// 選んだ ALPN。ClientHello に ALPN がなければ `http/1.1` として扱う
    pub alpn: &'static [u8],
}

/// サーバー側のハンドシェイク
pub struct ServerHandshake {
    config: ServerConfig,
    rng: Box<dyn RandomSource>,
    phase: Phase,
    inbuf: Vec<u8>,
    reassembler: HandshakeReassembler,
    /// 先に読んだ平文ハンドシェイクの総量（上限は決定 4.5 の 32 KiB）
    plain_read_total: usize,
    ccs_received: bool,
    ccs_sent: bool,
    transcript: Vec<u8>,
    first_hello: Option<ClientHello>,
    suite: Option<CipherSuite>,
    hrr_group: Option<u16>,
    early_data_offered: bool,
    hs_transmit: Option<RecordProtection>,
    hs_receive: Option<RecordProtection>,
    handshake_buffer: Vec<u8>,
    client_finished_key: Vec<u8>,
    /// サーバーの Finished までのトランスクリプトのハッシュ（クライアントの Finished の検証に使う）
    client_finished_transcript_hash: Vec<u8>,
    app_transmit: Option<RecordProtection>,
    app_receive: Option<RecordProtection>,
    server_name: Option<ServerName>,
    alpn: &'static [u8],
}

fn hash(suite: CipherSuite, data: &[u8]) -> Vec<u8> {
    match suite {
        CipherSuite::TlsChacha20Poly1305Sha256 | CipherSuite::TlsAes128GcmSha256 => {
            sha256(data).to_vec()
        }
        CipherSuite::TlsAes256GcmSha384 => sha384(data).to_vec(),
    }
}

fn hmac(suite: CipherSuite, key: &[u8], data: &[u8]) -> Vec<u8> {
    match suite {
        CipherSuite::TlsChacha20Poly1305Sha256 | CipherSuite::TlsAes128GcmSha256 => {
            hmac_sha256(key, data).to_vec()
        }
        CipherSuite::TlsAes256GcmSha384 => hmac_sha384(key, data).to_vec(),
    }
}

fn u24(len: usize) -> [u8; 3] {
    [(len >> 16) as u8, (len >> 8) as u8, len as u8]
}

fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(kind);
    out.extend_from_slice(&u24(body.len()));
    out.extend_from_slice(body);
    out
}

fn plain_record(content_type: ContentType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(content_type as u8);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// 2 つ目の ClientHello が 1 つ目から変えてよい拡張（RFC 8446 §4.1.2）
const MAY_CHANGE_AFTER_HRR: [u16; 5] = [
    extension_type::KEY_SHARE,
    extension_type::COOKIE,
    extension_type::EARLY_DATA,
    extension_type::PRE_SHARED_KEY,
    21, // padding
];

fn consistent_after_retry(first: &ClientHello, second: &ClientHello) -> bool {
    let strip = |list: &[u16]| -> Vec<u16> {
        list.iter()
            .copied()
            .filter(|t| !MAY_CHANGE_AFTER_HRR.contains(t))
            .collect()
    };
    first.legacy_version == second.legacy_version
        && first.random == second.random
        && first.legacy_session_id == second.legacy_session_id
        && first.cipher_suites == second.cipher_suites
        && first.legacy_compression_methods == second.legacy_compression_methods
        && first.server_name == second.server_name
        && first.supported_versions == second.supported_versions
        && first.supported_groups == second.supported_groups
        && first.signature_algorithms == second.signature_algorithms
        && first.alpn_protocols == second.alpn_protocols
        && strip(&first.extensions_present) == strip(&second.extensions_present)
}

impl ServerHandshake {
    pub fn new(config: ServerConfig, rng: Box<dyn RandomSource>) -> Result<Self, ShieldError> {
        config.validate()?;
        Ok(Self {
            config,
            rng,
            phase: Phase::ExpectClientHello1,
            inbuf: Vec::new(),
            reassembler: HandshakeReassembler::new(),
            plain_read_total: 0,
            ccs_received: false,
            ccs_sent: false,
            transcript: Vec::new(),
            first_hello: None,
            suite: None,
            hrr_group: None,
            early_data_offered: false,
            hs_transmit: None,
            hs_receive: None,
            handshake_buffer: Vec::new(),
            client_finished_key: Vec::new(),
            client_finished_transcript_hash: Vec::new(),
            app_transmit: None,
            app_receive: None,
            server_name: None,
            alpn: ALPN_HTTP_1_1,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.phase == Phase::Complete
    }

    /// 早期データ（0-RTT）が提示されたか。受理はしない。
    pub fn early_data_was_offered(&self) -> bool {
        self.early_data_offered
    }

    /// ハンドシェイクが完了していれば、アプリケーションデータの鍵と交渉結果を取り出す
    pub fn into_outcome(mut self) -> Result<HandshakeOutcome, ShieldError> {
        if self.phase != Phase::Complete {
            return Err(ShieldError::internal_error());
        }
        match (
            self.suite,
            self.app_transmit.take(),
            self.app_receive.take(),
        ) {
            (Some(suite), Some(transmit), Some(receive)) => Ok(HandshakeOutcome {
                suite,
                transmit,
                receive,
                server_name: self.server_name.take(),
                alpn: self.alpn,
            }),
            _ => Err(ShieldError::internal_error()),
        }
    }

    /// 致命的アラートを、いまの送信鍵で保護してレコードにする。
    /// サーバーのハンドシェイク鍵がまだなければ平文で送る。
    pub fn fatal_alert_record(&mut self, description: AlertDescription) -> Vec<u8> {
        let alert = Alert::fatal(description);
        if let Some(tx) = self.hs_transmit.as_mut() {
            let body = [alert.level as u8, alert.description as u8];
            if let Ok(record) = tx.seal_record(ContentType::Alert, &body, 0) {
                return record;
            }
        }
        alert.to_record_bytes().to_vec()
    }

    /// 受け取ったバイト列を処理し、送るべきバイト列を返す。
    ///
    /// 入力が空なら前進しないので終了する（決定 4.4）。エラーを返したら接続を終える。
    /// 送るべきアラートは [`ServerHandshake::fatal_alert_record`] で作る。
    pub fn receive(&mut self, data: &[u8]) -> Result<Vec<u8>, ShieldError> {
        if data.is_empty() {
            self.phase = Phase::Failed;
            return Err(ShieldError::TimeoutOrNoProgress);
        }
        match self.phase {
            Phase::Failed | Phase::Complete => return Err(ShieldError::internal_error()),
            _ => {}
        }
        match self.receive_inner(data) {
            Ok(out) => Ok(out),
            Err(e) => {
                self.phase = Phase::Failed;
                Err(e)
            }
        }
    }

    fn receive_inner(&mut self, data: &[u8]) -> Result<Vec<u8>, ShieldError> {
        self.inbuf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.phase == Phase::Complete {
                // クライアントの Finished の後に同じ読み取りで続くバイトは、
                // アプリケーションデータとして扱うには鍵の切り替えが要る。ここでは受け付けない。
                if !self.inbuf.is_empty() {
                    return Err(ShieldError::unexpected_message());
                }
                return Ok(out);
            }
            if self.inbuf.len() < 5 {
                return Ok(out);
            }
            let encrypted_phase = self.phase == Phase::ExpectClientFinished;
            let outer_is_protected =
                encrypted_phase && self.inbuf[0] == ContentType::ApplicationData as u8;
            let header = parse_record_header(&self.inbuf[..5], outer_is_protected)?;
            let total = 5 + header.length as usize;
            if self.inbuf.len() < total {
                return Ok(out);
            }
            let record: Vec<u8> = self.inbuf.drain(..total).collect();
            match header.content_type {
                ContentType::ChangeCipherSpec => self.on_change_cipher_spec(&record[5..])?,
                ContentType::Alert => {
                    // クライアントからのアラートは接続を終える
                    return Err(ShieldError::ConnectionClosed);
                }
                ContentType::Handshake => {
                    if encrypted_phase {
                        // 暗号化の後の平文のハンドシェイクは許さない
                        return Err(ShieldError::unexpected_message());
                    }
                    if let Some(message) = self.feed_plain_handshake(&record)? {
                        self.on_client_hello(&message, &mut out)?;
                    }
                }
                ContentType::ApplicationData => {
                    if !encrypted_phase {
                        // 早期データ（0-RTT）は読み飛ばさず終える（予算 0、決定 1.2）
                        return Err(ShieldError::unexpected_message());
                    }
                    self.on_protected_record(&record)?;
                }
            }
        }
    }

    fn on_change_cipher_spec(&mut self, payload: &[u8]) -> Result<(), ShieldError> {
        // ClientHello の前、または 2 つ目以降、または内容が 0x01 でないものは unexpected_message
        if self.phase == Phase::ExpectClientHello1 || self.ccs_received || payload != [0x01] {
            return Err(ShieldError::unexpected_message());
        }
        self.ccs_received = true;
        Ok(())
    }

    fn feed_plain_handshake(&mut self, record: &[u8]) -> Result<Option<Vec<u8>>, ShieldError> {
        let message = self.reassembler.feed_bytes(record)?;
        if self.plain_read_total + self.reassembler.total_read_bytes() > MAX_HANDSHAKE_READ_TOTAL {
            return Err(ShieldError::decode_error());
        }
        Ok(message)
    }

    fn append_transcript(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
    }

    fn on_client_hello(&mut self, message: &[u8], out: &mut Vec<u8>) -> Result<(), ShieldError> {
        // 次の ClientHello のために再構成器を作り直す（総量は引き継ぐ）
        self.plain_read_total += self.reassembler.total_read_bytes();
        self.reassembler = HandshakeReassembler::new();

        let hello = parse_client_hello(message)?;
        let second = self.phase == Phase::ExpectClientHello2;

        // 規則 1: TLS 1.3 のみ（supported_versions の検査は解析器が行う）
        // 規則 2: スイート
        let suite = if second {
            // 1 つ目と同じスイート（一覧が同じなので同じものが選ばれる）
            self.suite.ok_or_else(ShieldError::internal_error)?
        } else {
            self.select_suite(&hello)?
        };

        // 規則 4: 署名方式
        if !hello
            .signature_algorithms
            .contains(&self.config.signer.scheme())
        {
            return Err(ShieldError::handshake_failure());
        }

        // 規則 3: 鍵交換のグループ
        let agreement_index = self
            .config
            .key_agreements
            .iter()
            .position(|a| hello.supported_groups.contains(&a.group()))
            .ok_or_else(ShieldError::handshake_failure)?;
        let group = self.config.key_agreements[agreement_index].group();

        // 規則 5: ALPN
        if !hello.alpn_protocols.is_empty()
            && !hello
                .alpn_protocols
                .iter()
                .any(|p| p.as_slice() == ALPN_HTTP_1_1)
        {
            return Err(ShieldError::no_application_protocol());
        }

        // cookie は、こちらが送ったものを 2 つ目の ClientHello で返す場合だけ受け付ける
        if second {
            if hello.cookie != self.config.hrr_cookie {
                return Err(ShieldError::illegal_parameter());
            }
        } else if hello.cookie.is_some() {
            return Err(ShieldError::illegal_parameter());
        }

        if second {
            let first = self
                .first_hello
                .as_ref()
                .ok_or_else(ShieldError::internal_error)?;
            if !consistent_after_retry(first, &hello) {
                return Err(ShieldError::illegal_parameter());
            }
            let retry_group = self.hrr_group.ok_or_else(ShieldError::internal_error)?;
            // 2 つ目の ClientHello は HelloRetryRequest で求めたグループの key_share を 1 つだけ持つ
            if hello.key_shares.len() != 1 || hello.key_shares[0].group != retry_group {
                return Err(ShieldError::illegal_parameter());
            }
            self.append_transcript(message);
        } else {
            self.early_data_offered = hello
                .extensions_present
                .contains(&extension_type::EARLY_DATA);
        }

        let share = hello.key_shares.iter().find(|k| k.group == group);
        let share = match share {
            Some(s) => s.key_exchange.clone(),
            None => {
                if second {
                    return Err(ShieldError::illegal_parameter());
                }
                // key_share がなければ、1 接続に 1 回だけ HelloRetryRequest を返す
                self.send_hello_retry_request(&hello, suite, group, message, out);
                return Ok(());
            }
        };

        if !second {
            self.append_transcript(message);
        }
        self.server_name = hello.server_name.clone();
        self.alpn = ALPN_HTTP_1_1;
        self.send_server_flight(&hello, suite, agreement_index, &share, out)
    }

    fn select_suite(&mut self, hello: &ClientHello) -> Result<CipherSuite, ShieldError> {
        for suite in &self.config.cipher_preference {
            if hello.cipher_suites.contains(&suite.as_u16()) {
                self.suite = Some(*suite);
                return Ok(*suite);
            }
        }
        Err(ShieldError::handshake_failure())
    }

    fn send_hello_retry_request(
        &mut self,
        hello: &ClientHello,
        suite: CipherSuite,
        group: u16,
        first_message: &[u8],
        out: &mut Vec<u8>,
    ) {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&extension(extension_type::KEY_SHARE, &group.to_be_bytes()));
        if let Some(cookie) = &self.config.hrr_cookie {
            let mut body = (cookie.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(cookie);
            extensions.extend_from_slice(&extension(extension_type::COOKIE, &body));
        }
        extensions.extend_from_slice(&extension(
            extension_type::SUPPORTED_VERSIONS,
            &[0x03, 0x04],
        ));
        let body = server_hello_body(
            &HELLO_RETRY_REQUEST_RANDOM,
            &hello.legacy_session_id,
            suite,
            &extensions,
        );
        let message = handshake_message(HS_SERVER_HELLO, &body);

        // トランスクリプトは、1 つ目の ClientHello を message_hash に置き換えたものから始める
        let digest = hash(suite, first_message);
        let mut transcript = vec![HS_MESSAGE_HASH, 0, 0, digest.len() as u8];
        transcript.extend_from_slice(&digest);
        transcript.extend_from_slice(&message);
        self.transcript = transcript;

        out.extend_from_slice(&plain_record(ContentType::Handshake, &message));
        self.send_compatibility_change_cipher_spec(out);
        self.first_hello = Some(hello.clone());
        self.hrr_group = Some(group);
        self.phase = Phase::ExpectClientHello2;
        self.suite = Some(suite);
    }

    fn send_compatibility_change_cipher_spec(&mut self, out: &mut Vec<u8>) {
        if !self.ccs_sent {
            out.extend_from_slice(&plain_record(ContentType::ChangeCipherSpec, &[0x01]));
            self.ccs_sent = true;
        }
    }

    fn send_server_flight(
        &mut self,
        hello: &ClientHello,
        suite: CipherSuite,
        agreement_index: usize,
        client_share: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), ShieldError> {
        // サーバーの乱数と鍵交換（乱数は ServerHello の random、次に鍵交換の順に取る）
        let mut random = [0u8; 32];
        self.rng.fill(&mut random)?;
        let agreement =
            self.config.key_agreements[agreement_index].agree(self.rng.as_mut(), client_share)?;
        let group = self.config.key_agreements[agreement_index].group();

        // ServerHello
        let mut key_share = group.to_be_bytes().to_vec();
        key_share.extend_from_slice(&(agreement.server_share.len() as u16).to_be_bytes());
        key_share.extend_from_slice(&agreement.server_share);
        let mut extensions = extension(extension_type::KEY_SHARE, &key_share);
        extensions.extend_from_slice(&extension(
            extension_type::SUPPORTED_VERSIONS,
            &[0x03, 0x04],
        ));
        let body = server_hello_body(&random, &hello.legacy_session_id, suite, &extensions);
        let server_hello = handshake_message(HS_SERVER_HELLO, &body);
        self.append_transcript(&server_hello);
        out.extend_from_slice(&plain_record(ContentType::Handshake, &server_hello));
        self.send_compatibility_change_cipher_spec(out);

        // 鍵スケジュール: ServerHello までのトランスクリプトでハンドシェイク鍵を作る
        let ks = KeySchedule::new(suite);
        let early = ks.early_secret();
        let handshake_secret = ks.handshake_secret(&early, &agreement.shared_secret);
        drop(agreement);
        let hello_hash = hash(suite, &self.transcript);
        let mut c_hs = ks.client_handshake_traffic_secret(&handshake_secret, &hello_hash);
        let mut s_hs = ks.server_handshake_traffic_secret(&handshake_secret, &hello_hash);
        self.hs_transmit = Some(RecordProtection::new(
            RecordDirection::Transmit,
            suite,
            s_hs.clone(),
            &ks,
        ));
        self.hs_receive = Some(RecordProtection::new(
            RecordDirection::Receive,
            suite,
            c_hs.clone(),
            &ks,
        ));

        // EncryptedExtensions
        let mut ee_extensions = Vec::new();
        for (kind, body) in &self.config.extra_encrypted_extensions {
            ee_extensions.extend_from_slice(&extension(*kind, body));
        }
        if !hello.alpn_protocols.is_empty() {
            let mut list = vec![ALPN_HTTP_1_1.len() as u8];
            list.extend_from_slice(ALPN_HTTP_1_1);
            let mut body = (list.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(&list);
            ee_extensions.extend_from_slice(&extension(
                extension_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                &body,
            ));
        }
        let mut ee_body = (ee_extensions.len() as u16).to_be_bytes().to_vec();
        ee_body.extend_from_slice(&ee_extensions);
        let encrypted_extensions = handshake_message(HS_ENCRYPTED_EXTENSIONS, &ee_body);
        self.append_transcript(&encrypted_extensions);

        // Certificate（要求コンテキストは空、証明書ごとの拡張は空）
        let mut list = Vec::new();
        for cert in &self.config.certificate_chain {
            list.extend_from_slice(&u24(cert.len()));
            list.extend_from_slice(cert);
            list.extend_from_slice(&[0x00, 0x00]);
        }
        let mut cert_body = vec![0x00];
        cert_body.extend_from_slice(&u24(list.len()));
        cert_body.extend_from_slice(&list);
        let certificate = handshake_message(HS_CERTIFICATE, &cert_body);
        self.append_transcript(&certificate);

        // CertificateVerify
        let mut content = vec![0x20u8; 64];
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0x00);
        content.extend_from_slice(&hash(suite, &self.transcript));
        let signature = self.config.signer.sign(&content)?;
        if signature.len() > u16::MAX as usize {
            return Err(ShieldError::internal_error());
        }
        let mut cv_body = self.config.signer.scheme().to_be_bytes().to_vec();
        cv_body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        cv_body.extend_from_slice(&signature);
        let certificate_verify = handshake_message(HS_CERTIFICATE_VERIFY, &cv_body);
        self.append_transcript(&certificate_verify);

        // Finished
        let hash_len = suite.hash_len();
        let mut finished_key = ks.hkdf_expand_label(&s_hs, "finished", b"", hash_len);
        let verify_data = hmac(suite, &finished_key, &hash(suite, &self.transcript));
        wipe(&mut finished_key);
        let finished = handshake_message(HS_FINISHED, &verify_data);
        self.append_transcript(&finished);

        // 4 つのメッセージを 1 つ以上の保護レコードに詰める（1 レコードは 2^14 バイト以下）
        let mut flight = Vec::new();
        flight.extend_from_slice(&encrypted_extensions);
        flight.extend_from_slice(&certificate);
        flight.extend_from_slice(&certificate_verify);
        flight.extend_from_slice(&finished);
        let tx = self
            .hs_transmit
            .as_mut()
            .ok_or_else(ShieldError::internal_error)?;
        for chunk in flight.chunks(MAX_PLAIN_RECORD_PAYLOAD) {
            out.extend_from_slice(&tx.seal_record(ContentType::Handshake, chunk, 0)?);
        }

        // サーバーの Finished までのトランスクリプトで、アプリケーション鍵とクライアントの Finished の検証値を作る
        let finished_hash = hash(suite, &self.transcript);
        let master = ks.master_secret(&handshake_secret);
        let mut s_ap = ks.server_application_traffic_secret_0(&master, &finished_hash);
        let mut c_ap = ks.client_application_traffic_secret_0(&master, &finished_hash);
        self.app_transmit = Some(RecordProtection::new(
            RecordDirection::Transmit,
            suite,
            s_ap.clone(),
            &ks,
        ));
        self.app_receive = Some(RecordProtection::new(
            RecordDirection::Receive,
            suite,
            c_ap.clone(),
            &ks,
        ));
        self.client_finished_key = ks.hkdf_expand_label(&c_hs, "finished", b"", hash_len);
        self.client_finished_transcript_hash = finished_hash;

        let mut handshake_secret = handshake_secret;
        let mut master = master;
        wipe(&mut handshake_secret);
        wipe(&mut master);
        wipe(&mut c_hs);
        wipe(&mut s_hs);
        wipe(&mut s_ap);
        wipe(&mut c_ap);

        self.suite = Some(suite);
        self.phase = Phase::ExpectClientFinished;
        Ok(())
    }

    fn on_protected_record(&mut self, record: &[u8]) -> Result<(), ShieldError> {
        let rx = self
            .hs_receive
            .as_mut()
            .ok_or_else(ShieldError::internal_error)?;
        // 認証に失敗すれば bad_record_mac。早期データもここで失敗して終わる
        let (content_type, plaintext, _) = rx.open_record(record)?;
        match content_type {
            ContentType::Handshake => self.handshake_buffer.extend_from_slice(&plaintext),
            ContentType::Alert => return Err(ShieldError::ConnectionClosed),
            _ => return Err(ShieldError::unexpected_message()),
        }
        self.try_client_finished()
    }

    fn try_client_finished(&mut self) -> Result<(), ShieldError> {
        let suite = self.suite.ok_or_else(ShieldError::internal_error)?;
        let hash_len = suite.hash_len();
        if self.handshake_buffer.len() < 4 {
            return Ok(());
        }
        // この段階で受け取ってよいのは、クライアントの Finished だけ
        if self.handshake_buffer[0] != HS_FINISHED {
            return Err(ShieldError::unexpected_message());
        }
        let body_len = ((self.handshake_buffer[1] as usize) << 16)
            | ((self.handshake_buffer[2] as usize) << 8)
            | self.handshake_buffer[3] as usize;
        if body_len != hash_len {
            return Err(ShieldError::decode_error());
        }
        if self.handshake_buffer.len() < 4 + body_len {
            return Ok(());
        }
        if self.handshake_buffer.len() > 4 + body_len {
            // Finished の後に続くバイトは認めない
            return Err(ShieldError::unexpected_message());
        }
        let expected = hmac(
            suite,
            &self.client_finished_key,
            &self.client_finished_transcript_hash,
        );
        let ok = ct_eq(&expected, &self.handshake_buffer[4..]);
        wipe(&mut self.client_finished_key);
        if !ok {
            return Err(ShieldError::decrypt_error());
        }
        self.hs_transmit = None;
        self.hs_receive = None;
        self.handshake_buffer.clear();
        self.phase = Phase::Complete;
        Ok(())
    }
}

fn server_hello_body(
    random: &[u8; 32],
    session_id: &[u8],
    suite: CipherSuite,
    extensions: &[u8],
) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.as_u16().to_be_bytes());
    body.push(0x00);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);
    body
}
