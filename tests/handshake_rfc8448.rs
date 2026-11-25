//! ハンドシェイクの状態機械と RFC 8448 のトレース（サーバー側の値）の照合（ADR 0063 決定 6 段 3）。
//!
//! 照合するのは、ServerHello・HelloRetryRequest・暗号化されたサーバーの飛行（EncryptedExtensions、
//! Certificate、CertificateVerify、Finished）のバイト列、クライアントの Finished の受理、
//! アプリケーション鍵（トレースのアプリケーションデータのレコード）である。
//!
//! RFC 8448 の例は次のとおり本実装の既定と違うので、差し込みで合わせる（既定の挙動は別の試験で確かめる）。
//! - スイートは `TLS_AES_128_GCM_SHA256`（既定の優先順は ChaCha20-Poly1305 が先）。
//! - 署名は RSA-PSS（本実装は ECDSA P-256 のみ）。署名器を差し込み、署名の対象のバイト列が
//!   トレースの値と一致することを確かめたうえで、トレースの署名を返す。
//! - EncryptedExtensions にはトレースの拡張（supported_groups、record_size_limit、server_name）を載せる。
//! - HelloRetryRequest の例は P-256 の鍵交換を使う（本実装は段 6 まで持たない）ので、
//!   `secp256r1` の鍵交換は、トレースの公開値と共有秘密を返す差し込みにする。
//!   共有秘密はトレースの秘密鍵とクライアントの公開値から OpenSSL（Python `cryptography`）で求めた。
//!   HelloRetryRequest の `cookie` はトレースの値を設定で渡す。
//! - ClientHello の `legacy_session_id` が空の例には ChangeCipherSpec がないが、本実装は決定 1.2 により
//!   ServerHello の直後に 1 つ送る。そのため出力は ChangeCipherSpec の前後で分けて照合する。

#[path = "rfc8448/data.rs"]
mod data;

use data::*;
use sigil_shield_tls::alert::{AlertDescription, ShieldError};
use sigil_shield_tls::cipher_suite::CipherSuite;
use sigil_shield_tls::handshake::{
    KeyAgreement, KeyAgreementOutput, RandomSource, ServerConfig, ServerHandshake, Signer,
    X25519Agreement,
};
use sigil_shield_tls::record::ContentType;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// 決まった列を順に返す乱数
struct FixedRandom {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedRandom {
    fn new(hex: &str) -> Box<Self> {
        Box::new(Self {
            bytes: unhex(hex),
            pos: 0,
        })
    }
}

impl RandomSource for FixedRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), ShieldError> {
        let end = self.pos + out.len();
        out.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

/// トレースの署名を返す署名器（署名の対象がトレースと一致することを確かめる）
struct TraceSigner {
    scheme: u16,
    to_sign: Vec<u8>,
    signature: Vec<u8>,
}

impl Signer for TraceSigner {
    fn scheme(&self) -> u16 {
        self.scheme
    }

    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, ShieldError> {
        assert_eq!(
            content,
            self.to_sign.as_slice(),
            "CertificateVerify の署名対象がトレースと一致しない"
        );
        Ok(self.signature.clone())
    }
}

/// トレースの値を返す `secp256r1` の差し込み
struct TraceP256 {
    server_share: Vec<u8>,
    shared_secret: Vec<u8>,
}

impl KeyAgreement for TraceP256 {
    fn group(&self) -> u16 {
        0x0017
    }

    fn agree(
        &self,
        rng: &mut dyn RandomSource,
        _client_share: &[u8],
    ) -> Result<KeyAgreementOutput, ShieldError> {
        let mut private = [0u8; 32];
        rng.fill(&mut private)?;
        Ok(KeyAgreementOutput {
            server_share: self.server_share.clone(),
            shared_secret: self.shared_secret.clone(),
        })
    }
}

/// Certificate メッセージから末端の証明書（DER）を取り出す
fn leaf_certificate(message: &[u8]) -> Vec<u8> {
    // 種別(1) 長さ(3) コンテキスト長(1)=0 一覧の長さ(3) 証明書の長さ(3) 証明書 拡張(2)
    assert_eq!(message[0], 11);
    assert_eq!(message[4], 0);
    let cert_len =
        ((message[8] as usize) << 16) | ((message[9] as usize) << 8) | message[10] as usize;
    message[11..11 + cert_len].to_vec()
}

/// EncryptedExtensions メッセージの拡張を (種別, 本体) の並びにする
fn encrypted_extensions(message: &[u8]) -> Vec<(u16, Vec<u8>)> {
    assert_eq!(message[0], 8);
    let total = ((message[4] as usize) << 8) | message[5] as usize;
    let mut pos = 6;
    let mut out = Vec::new();
    while pos < 6 + total {
        let kind = u16::from_be_bytes([message[pos], message[pos + 1]]);
        let len = u16::from_be_bytes([message[pos + 2], message[pos + 3]]) as usize;
        out.push((kind, message[pos + 4..pos + 4 + len].to_vec()));
        pos += 4 + len;
    }
    assert_eq!(pos, message.len());
    out
}

struct Trace<'a> {
    pool: &'a str,
    to_sign: &'a str,
    signature: &'a str,
    encrypted_extensions: &'a str,
    certificate: &'a str,
}

fn config(trace: &Trace) -> ServerConfig {
    let signer = TraceSigner {
        scheme: 0x0804,
        to_sign: unhex(trace.to_sign),
        signature: unhex(trace.signature),
    };
    let mut config = ServerConfig::new(
        vec![leaf_certificate(&unhex(trace.certificate))],
        Box::new(signer),
    );
    config.cipher_preference = vec![CipherSuite::TlsAes128GcmSha256];
    config.extra_encrypted_extensions = encrypted_extensions(&unhex(trace.encrypted_extensions));
    config
}

#[test]
fn simple_1rtt_matches_rfc8448() {
    let trace = Trace {
        pool: SIMPLE_SERVER_RNG_POOL,
        to_sign: SIMPLE_SERVER_MESSAGETOSIGN,
        signature: SIMPLE_SERVER_MESSAGESIGNATURE,
        encrypted_extensions: SIMPLE_MESSAGE_ENCRYPTEDEXTENSIONS,
        certificate: SIMPLE_MESSAGE_SERVER_CERTIFICATE,
    };
    let mut hs = ServerHandshake::new(config(&trace), FixedRandom::new(trace.pool)).unwrap();
    let out = hs.receive(&unhex(SIMPLE_RECORD_CLIENTHELLO_1)).unwrap();

    let server_hello = unhex(SIMPLE_RECORD_SERVERHELLO);
    let flight = unhex(SIMPLE_RECORD_SERVERHANDSHAKEMESSAGES);
    let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    let mut want = server_hello.clone();
    want.extend_from_slice(&ccs);
    want.extend_from_slice(&flight);
    assert_eq!(out, want);

    let reply = hs.receive(&unhex(SIMPLE_RECORD_CLIENTFINISHED)).unwrap();
    assert!(reply.is_empty());
    assert!(hs.is_complete());

    // アプリケーション鍵: トレースのアプリケーションデータのレコードと一致する
    let mut outcome = hs.into_outcome().unwrap();
    assert_eq!(outcome.suite, CipherSuite::TlsAes128GcmSha256);
    assert_eq!(outcome.alpn, b"http/1.1");
    // トレースではサーバーが先に NewSessionTicket（シーケンス番号 0）を送るので、
    // アプリケーションデータはシーケンス番号 1。本実装はチケットを送らない。
    outcome.transmit.sequence_number = 1;
    let sealed = outcome
        .transmit
        .seal_record(
            ContentType::ApplicationData,
            &unhex(SIMPLE_SERVER_APPDATA),
            0,
        )
        .unwrap();
    assert_eq!(sealed, unhex(SIMPLE_RECORD_SERVER_APPDATA));
    let (kind, plain, used) = outcome
        .receive
        .open_record(&unhex(SIMPLE_RECORD_CLIENT_APPDATA))
        .unwrap();
    assert_eq!(kind, ContentType::ApplicationData);
    assert_eq!(plain, unhex(SIMPLE_SERVER_APPDATA));
    assert_eq!(used, unhex(SIMPLE_RECORD_CLIENT_APPDATA).len());
}

#[test]
fn simple_1rtt_server_hello_message_matches_rfc8448() {
    // ServerHello のメッセージそのもの（レコードの本体）
    let server_hello = unhex(SIMPLE_RECORD_SERVERHELLO);
    assert_eq!(
        &server_hello[5..],
        unhex(SIMPLE_MESSAGE_SERVERHELLO).as_slice()
    );
}

#[test]
fn middlebox_compatibility_matches_rfc8448() {
    // legacy_session_id が空でない例。トレースの出力は ServerHello、ChangeCipherSpec、保護レコードの順で、
    // クライアントは ChangeCipherSpec の後に Finished を送る。
    let trace = Trace {
        pool: COMPAT_SERVER_RNG_POOL,
        to_sign: COMPAT_SERVER_MESSAGETOSIGN,
        signature: COMPAT_SERVER_MESSAGESIGNATURE,
        encrypted_extensions: COMPAT_MESSAGE_ENCRYPTEDEXTENSIONS,
        certificate: COMPAT_MESSAGE_SERVER_CERTIFICATE,
    };
    let mut hs = ServerHandshake::new(config(&trace), FixedRandom::new(trace.pool)).unwrap();
    let out = hs.receive(&unhex(COMPAT_RECORD_CLIENTHELLO_1)).unwrap();
    let mut want = unhex(COMPAT_RECORD_SERVERHELLO);
    want.extend_from_slice(&unhex(COMPAT_RECORD_SERVERHANDSHAKEMESSAGES));
    assert_eq!(out, want);
    hs.receive(&unhex(COMPAT_RECORD_CLIENTFINISHED)).unwrap();
    assert!(hs.is_complete());
}

#[test]
fn hello_retry_request_matches_rfc8448() {
    let trace = Trace {
        pool: HRR_SERVER_RNG_POOL,
        to_sign: HRR_SERVER_MESSAGETOSIGN,
        signature: HRR_SERVER_MESSAGESIGNATURE,
        encrypted_extensions: HRR_MESSAGE_ENCRYPTEDEXTENSIONS,
        certificate: HRR_MESSAGE_SERVER_CERTIFICATE,
    };
    let mut cfg = config(&trace);
    // サーバーは P-256 を優先する。クライアントの最初の key_share は x25519 だけなので、
    // HelloRetryRequest で secp256r1 を求める。
    let server_hello = unhex(HRR_RECORD_SERVERHELLO);
    let server_share = unhex(
        &HRR_MESSAGE_SERVERHELLO[HRR_MESSAGE_SERVERHELLO.find("0017004104").unwrap() + 8..][..130],
    );
    cfg.key_agreements = vec![
        Box::new(TraceP256 {
            server_share,
            // 共有秘密: トレースのサーバーの秘密鍵 8c510601… とクライアントの 2 つ目の ClientHello の
            // 公開値から、OpenSSL（Python cryptography の ECDH）で求めた値
            shared_secret: unhex(
                "c142ce13ca11b5c2233652e63ad3d97844f1621fbfb9de69d547dc8fedeabeb4",
            ),
        }),
        Box::new(X25519Agreement),
    ];
    cfg.hrr_cookie = Some(unhex(HRR_HELLORETRYREQUEST_COOKIE));
    let mut hs = ServerHandshake::new(cfg, FixedRandom::new(trace.pool)).unwrap();

    // 1 つ目の ClientHello → HelloRetryRequest（のあとに互換の ChangeCipherSpec）
    let out = hs.receive(&unhex(HRR_RECORD_CLIENTHELLO_1)).unwrap();
    let hrr = unhex(HRR_RECORD_HELLORETRYREQUEST);
    let mut want = hrr.clone();
    want.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    assert_eq!(out, want);
    assert!(!hs.is_complete());

    // 2 つ目の ClientHello → ServerHello と保護された飛行（ChangeCipherSpec は 2 つ目を送らない）
    let out = hs.receive(&unhex(HRR_RECORD_CLIENTHELLO_2)).unwrap();
    let mut want = server_hello;
    want.extend_from_slice(&unhex(HRR_RECORD_SERVERHANDSHAKEMESSAGES));
    assert_eq!(out, want);

    hs.receive(&unhex(HRR_RECORD_CLIENTFINISHED)).unwrap();
    assert!(hs.is_complete());
}

#[test]
fn hello_retry_request_cookie_must_be_echoed() {
    let trace = Trace {
        pool: HRR_SERVER_RNG_POOL,
        to_sign: HRR_SERVER_MESSAGETOSIGN,
        signature: HRR_SERVER_MESSAGESIGNATURE,
        encrypted_extensions: HRR_MESSAGE_ENCRYPTEDEXTENSIONS,
        certificate: HRR_MESSAGE_SERVER_CERTIFICATE,
    };
    let mut cfg = config(&trace);
    cfg.key_agreements = vec![
        Box::new(TraceP256 {
            server_share: vec![0; 65],
            shared_secret: vec![1; 32],
        }),
        Box::new(X25519Agreement),
    ];
    // トレースの cookie と違う値を設定すると、2 つ目の ClientHello が返す cookie と食い違う
    cfg.hrr_cookie = Some(vec![0xaa; 8]);
    let mut hs = ServerHandshake::new(cfg, FixedRandom::new(trace.pool)).unwrap();
    hs.receive(&unhex(HRR_RECORD_CLIENTHELLO_1)).unwrap();
    let err = hs.receive(&unhex(HRR_RECORD_CLIENTHELLO_2)).unwrap_err();
    assert_eq!(err, ShieldError::Fatal(AlertDescription::IllegalParameter));
}
