//! ハンドシェイクの規則（ADR 0063 決定 1.2）の試験。
//!
//! 本物の署名（ECDSA P-256）と本物の鍵交換（X25519）を使い、試験用のクライアントが
//! サーバーの飛行を復号し、CertificateVerify の署名と Finished を検証して、自分の Finished を返す。

use sigil_shield_tls::alert::{AlertDescription, ShieldError};
use sigil_shield_tls::cipher_suite::CipherSuite;
use sigil_shield_tls::crypto::{
    ecdsa_p256_verify, hmac_sha256, hmac_sha384, sha256, sha384, x25519, x25519_public_key,
    RawSignature,
};
use sigil_shield_tls::handshake::{
    EcdsaP256Signer, RandomSource, ServerConfig, ServerHandshake, SIGNATURE_ECDSA_SECP256R1_SHA256,
};
use sigil_shield_tls::key_schedule::KeySchedule;
use sigil_shield_tls::record::ContentType;
use sigil_shield_tls::record_crypto::{RecordDirection, RecordProtection};

const SERVER_KEY: [u8; 32] = [
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
];
const P256_GENERATOR: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// 呼ぶたびに別の値を返す、再現できる乱数
struct CountingRandom(u8);

impl RandomSource for CountingRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), ShieldError> {
        for b in out.iter_mut() {
            self.0 = self.0.wrapping_mul(31).wrapping_add(7);
            *b = self.0;
        }
        Ok(())
    }
}

fn server() -> ServerHandshake {
    let signer = EcdsaP256Signer::new(SERVER_KEY).unwrap();
    let config = ServerConfig::new(vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]], Box::new(signer));
    ServerHandshake::new(config, Box::new(CountingRandom(1))).unwrap()
}

fn server_public() -> [u8; 65] {
    EcdsaP256Signer::new(SERVER_KEY).unwrap().public_key()
}

// ---- ClientHello の組み立て ----

#[derive(Clone)]
struct Hello {
    session_id: Vec<u8>,
    suites: Vec<u16>,
    versions: Vec<u16>,
    groups: Vec<u16>,
    sigalgs: Vec<u16>,
    shares: Vec<(u16, Vec<u8>)>,
    alpn: Option<Vec<Vec<u8>>>,
    psk_modes: bool,
    psk: bool,
    early_data: bool,
    cookie: Option<Vec<u8>>,
}

impl Hello {
    fn x25519(private: &[u8; 32]) -> Hello {
        Hello {
            session_id: vec![0x55; 32],
            suites: vec![0x1301, 0x1302, 0x1303],
            versions: vec![0x0304],
            groups: vec![0x001d, 0x0017],
            sigalgs: vec![0x0804, SIGNATURE_ECDSA_SECP256R1_SHA256],
            shares: vec![(0x001d, x25519_public_key(private).to_vec())],
            alpn: None,
            psk_modes: false,
            psk: false,
            early_data: false,
            cookie: None,
        }
    }

    fn message(&self) -> Vec<u8> {
        fn ext(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
            out.extend_from_slice(&kind.to_be_bytes());
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
            out.extend_from_slice(body);
        }
        let mut exts = Vec::new();
        let mut v = vec![(self.versions.len() * 2) as u8];
        for x in &self.versions {
            v.extend_from_slice(&x.to_be_bytes());
        }
        ext(&mut exts, 0x002b, &v);
        let mut g = ((self.groups.len() * 2) as u16).to_be_bytes().to_vec();
        for x in &self.groups {
            g.extend_from_slice(&x.to_be_bytes());
        }
        ext(&mut exts, 0x000a, &g);
        let mut s = ((self.sigalgs.len() * 2) as u16).to_be_bytes().to_vec();
        for x in &self.sigalgs {
            s.extend_from_slice(&x.to_be_bytes());
        }
        ext(&mut exts, 0x000d, &s);
        let mut ks = Vec::new();
        for (group, share) in &self.shares {
            ks.extend_from_slice(&group.to_be_bytes());
            ks.extend_from_slice(&(share.len() as u16).to_be_bytes());
            ks.extend_from_slice(share);
        }
        let mut body = (ks.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&ks);
        ext(&mut exts, 0x0033, &body);
        if let Some(list) = &self.alpn {
            let mut l = Vec::new();
            for p in list {
                l.push(p.len() as u8);
                l.extend_from_slice(p);
            }
            let mut body = (l.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(&l);
            ext(&mut exts, 0x0010, &body);
        }
        if self.psk_modes {
            ext(&mut exts, 0x002d, &[0x01, 0x01]);
        }
        if self.early_data {
            ext(&mut exts, 0x002a, &[]);
        }
        if let Some(c) = &self.cookie {
            let mut body = (c.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(c);
            ext(&mut exts, 0x002c, &body);
        }
        if self.psk {
            // 識別子 1 つ（4 バイト）と binder 1 つ（32 バイト）
            let mut body = Vec::new();
            body.extend_from_slice(&(2u16 + 4 + 4).to_be_bytes());
            body.extend_from_slice(&4u16.to_be_bytes());
            body.extend_from_slice(b"tick");
            body.extend_from_slice(&[0, 0, 0, 0]);
            body.extend_from_slice(&33u16.to_be_bytes());
            body.push(32);
            body.extend_from_slice(&[0xbb; 32]);
            ext(&mut exts, 0x0029, &body);
        }
        let mut b = vec![0x03, 0x03];
        b.extend_from_slice(&[0x42; 32]);
        b.push(self.session_id.len() as u8);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&((self.suites.len() * 2) as u16).to_be_bytes());
        for x in &self.suites {
            b.extend_from_slice(&x.to_be_bytes());
        }
        b.extend_from_slice(&[0x01, 0x00]);
        b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        b.extend_from_slice(&exts);
        let mut m = vec![
            0x01,
            (b.len() >> 16) as u8,
            (b.len() >> 8) as u8,
            b.len() as u8,
        ];
        m.extend_from_slice(&b);
        m
    }
}

fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut r = vec![kind, 0x03, 0x03];
    r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    r.extend_from_slice(payload);
    r
}

fn hello_record(h: &Hello) -> Vec<u8> {
    record(0x16, &h.message())
}

// ---- 試験用のクライアント ----

fn hash(suite: CipherSuite, data: &[u8]) -> Vec<u8> {
    match suite {
        CipherSuite::TlsAes256GcmSha384 => sha384(data).to_vec(),
        _ => sha256(data).to_vec(),
    }
}

fn hmac(suite: CipherSuite, key: &[u8], data: &[u8]) -> Vec<u8> {
    match suite {
        CipherSuite::TlsAes256GcmSha384 => hmac_sha384(key, data).to_vec(),
        _ => hmac_sha256(key, data).to_vec(),
    }
}

/// サーバーの出力を読み、検証して、クライアントの Finished を返す試験用クライアント
struct Client {
    private: [u8; 32],
    transcript: Vec<u8>,
    suite: Option<CipherSuite>,
    s_ap: Vec<u8>,
    server_hello_extensions: Vec<u16>,
    encrypted_extension_types: Vec<u16>,
    session_id_echo: Vec<u8>,
}

fn split_records(mut data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let len = u16::from_be_bytes([data[3], data[4]]) as usize;
        out.push((data[0], data[5..5 + len].to_vec()));
        data = &data[5 + len..];
    }
    out
}

fn parse_der_signature(der: &[u8]) -> RawSignature {
    assert_eq!(der[0], 0x30);
    assert_eq!(der[1] as usize, der.len() - 2);
    let mut pos = 2;
    let mut ints = Vec::new();
    for _ in 0..2 {
        assert_eq!(der[pos], 0x02);
        let len = der[pos + 1] as usize;
        let mut v = der[pos + 2..pos + 2 + len].to_vec();
        pos += 2 + len;
        while v.len() > 32 {
            assert_eq!(v.remove(0), 0);
        }
        let mut padded = vec![0u8; 32 - v.len()];
        padded.extend_from_slice(&v);
        ints.push(<[u8; 32]>::try_from(padded).unwrap());
    }
    assert_eq!(pos, der.len());
    RawSignature {
        r: ints[0],
        s: ints[1],
    }
}

impl Client {
    fn new(private: [u8; 32]) -> Client {
        Client {
            private,
            transcript: Vec::new(),
            suite: None,
            s_ap: Vec::new(),
            server_hello_extensions: Vec::new(),
            encrypted_extension_types: Vec::new(),
            session_id_echo: Vec::new(),
        }
    }

    /// ClientHello を送った直後のサーバーの出力（HelloRetryRequest を除く）を処理し、
    /// クライアントの Finished のレコード（ChangeCipherSpec 付き）を返す。
    fn finish(
        &mut self,
        server_output: &[u8],
        hello_messages: &[u8],
        server_public_key: &[u8; 65],
    ) -> (Vec<u8>, KeyScheduleSecrets) {
        self.transcript.extend_from_slice(hello_messages);
        let records = split_records(server_output);
        let (kind, sh) = &records[0];
        assert_eq!(*kind, 0x16);
        assert_eq!(sh[0], 2);
        self.transcript.extend_from_slice(sh);
        // ServerHello: 2 + 32 + 1 + sid + 2 + 1 + 2 + exts
        let sid_len = sh[4 + 2 + 32] as usize;
        self.session_id_echo = sh[4 + 2 + 32 + 1..4 + 2 + 32 + 1 + sid_len].to_vec();
        let mut pos = 4 + 2 + 32 + 1 + sid_len;
        let suite = CipherSuite::from_u16(u16::from_be_bytes([sh[pos], sh[pos + 1]])).unwrap();
        self.suite = Some(suite);
        pos += 3;
        let ext_len = u16::from_be_bytes([sh[pos], sh[pos + 1]]) as usize;
        pos += 2;
        let end = pos + ext_len;
        let mut server_share = None;
        while pos < end {
            let kind = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
            let len = u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]) as usize;
            self.server_hello_extensions.push(kind);
            if kind == 0x0033 {
                assert_eq!(u16::from_be_bytes([sh[pos + 4], sh[pos + 5]]), 0x001d);
                let l = u16::from_be_bytes([sh[pos + 6], sh[pos + 7]]) as usize;
                server_share = Some(sh[pos + 8..pos + 8 + l].to_vec());
            }
            pos += 4 + len;
        }
        let server_share: [u8; 32] = server_share.unwrap().try_into().unwrap();
        let shared = x25519(&self.private, &server_share);

        let ks = KeySchedule::new(suite);
        let early = ks.early_secret();
        let hs = ks.handshake_secret(&early, &shared);
        let h_sh = hash(suite, &self.transcript);
        let c_hs = ks.client_handshake_traffic_secret(&hs, &h_sh);
        let s_hs = ks.server_handshake_traffic_secret(&hs, &h_sh);
        let mut rx = RecordProtection::new(RecordDirection::Receive, suite, s_hs.clone(), &ks);

        // ChangeCipherSpec は、サーバーの最初のメッセージの直後に 1 つだけ送られる。
        // HelloRetryRequest があれば、そちらの後に送られているので、ここにはない。
        let mut idx = 1;
        if records[idx].0 == 0x14 {
            assert_eq!(records[idx], (0x14, vec![0x01]));
            idx += 1;
        }
        // 残りは保護レコード
        let mut buf = Vec::new();
        for (kind, payload) in &records[idx..] {
            assert_eq!(*kind, 0x17);
            let rec = record(0x17, payload);
            let (inner, plain, _) = rx.open_record(&rec).unwrap();
            assert_eq!(inner, ContentType::Handshake);
            buf.extend_from_slice(&plain);
        }
        // EncryptedExtensions, Certificate, CertificateVerify, Finished の順
        let mut messages = Vec::new();
        let mut p = 0;
        while p < buf.len() {
            let len =
                ((buf[p + 1] as usize) << 16) | ((buf[p + 2] as usize) << 8) | buf[p + 3] as usize;
            messages.push(buf[p..p + 4 + len].to_vec());
            p += 4 + len;
        }
        let types: Vec<u8> = messages.iter().map(|m| m[0]).collect();
        assert_eq!(types, vec![8, 11, 15, 20]);

        // EncryptedExtensions の拡張の種別
        let ee = &messages[0];
        let total = u16::from_be_bytes([ee[4], ee[5]]) as usize;
        let mut q = 6;
        while q < 6 + total {
            self.encrypted_extension_types
                .push(u16::from_be_bytes([ee[q], ee[q + 1]]));
            q += 4 + u16::from_be_bytes([ee[q + 2], ee[q + 3]]) as usize;
        }

        self.transcript.extend_from_slice(&messages[0]);
        self.transcript.extend_from_slice(&messages[1]);
        // CertificateVerify: 署名方式は ecdsa_secp256r1_sha256、署名は検証が通る
        let cv = &messages[2];
        assert_eq!(
            u16::from_be_bytes([cv[4], cv[5]]),
            SIGNATURE_ECDSA_SECP256R1_SHA256
        );
        let sig_len = u16::from_be_bytes([cv[6], cv[7]]) as usize;
        assert_eq!(cv.len(), 8 + sig_len);
        let signature = parse_der_signature(&cv[8..]);
        let mut content = vec![0x20u8; 64];
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0);
        content.extend_from_slice(&hash(suite, &self.transcript));
        assert!(
            ecdsa_p256_verify(server_public_key, &content, &signature),
            "CertificateVerify の署名が検証できない"
        );
        self.transcript.extend_from_slice(cv);

        // サーバーの Finished
        let fin = &messages[3];
        let hl = suite.hash_len();
        let s_key = ks.hkdf_expand_label(&s_hs, "finished", b"", hl);
        assert_eq!(
            &fin[4..],
            hmac(suite, &s_key, &hash(suite, &self.transcript)).as_slice()
        );
        self.transcript.extend_from_slice(fin);
        let h_fin = hash(suite, &self.transcript);

        // アプリケーション鍵
        let master = ks.master_secret(&hs);
        self.s_ap = ks.server_application_traffic_secret_0(&master, &h_fin);
        let c_ap = ks.client_application_traffic_secret_0(&master, &h_fin);

        // クライアントの Finished
        let c_key = ks.hkdf_expand_label(&c_hs, "finished", b"", hl);
        let verify = hmac(suite, &c_key, &h_fin);
        let mut finished = vec![20, 0, 0, hl as u8];
        finished.extend_from_slice(&verify);
        let mut tx = RecordProtection::new(RecordDirection::Transmit, suite, c_hs.clone(), &ks);
        let mut out = record(0x14, &[0x01]);
        out.extend_from_slice(
            &tx.seal_record(ContentType::Handshake, &finished, 0)
                .unwrap(),
        );
        (
            out,
            KeyScheduleSecrets {
                suite,
                ks,
                s_ap: self.s_ap.clone(),
                c_ap,
                c_hs,
                s_hs,
            },
        )
    }
}

struct KeyScheduleSecrets {
    suite: CipherSuite,
    ks: KeySchedule,
    s_ap: Vec<u8>,
    c_ap: Vec<u8>,
    c_hs: Vec<u8>,
    s_hs: Vec<u8>,
}

/// 完全なハンドシェイクを行い、アプリケーションデータが両方向で通ることを確かめる
fn complete_handshake(hello: &Hello, private: [u8; 32]) -> Client {
    let mut server = server();
    let msg = hello.message();
    let out = server.receive(&record(0x16, &msg)).unwrap();
    let mut client = Client::new(private);
    let (finished, secrets) = client.finish(&out, &msg, &server_public());
    assert!(server.receive(&finished).unwrap().is_empty());
    assert!(server.is_complete());
    let mut outcome = server.into_outcome().unwrap();
    let mut client_rx = RecordProtection::new(
        RecordDirection::Receive,
        secrets.suite,
        secrets.s_ap.clone(),
        &secrets.ks,
    );
    let mut client_tx = RecordProtection::new(
        RecordDirection::Transmit,
        secrets.suite,
        secrets.c_ap.clone(),
        &secrets.ks,
    );
    let sealed = outcome
        .transmit
        .seal_record(ContentType::ApplicationData, b"from server", 0)
        .unwrap();
    assert_eq!(client_rx.open_record(&sealed).unwrap().1, b"from server");
    let sealed = client_tx
        .seal_record(ContentType::ApplicationData, b"from client", 0)
        .unwrap();
    assert_eq!(
        outcome.receive.open_record(&sealed).unwrap().1,
        b"from client"
    );
    client
}

const KEY_A: [u8; 32] = [0x11; 32];

// ---- 試験 ----

#[test]
fn full_handshake_round_trip_with_default_preference() {
    let hello = Hello::x25519(&KEY_A);
    let client = complete_handshake(&hello, KEY_A);
    // 既定の優先順は ChaCha20-Poly1305 が先
    assert_eq!(client.suite, Some(CipherSuite::TlsChacha20Poly1305Sha256));
    // ServerHello の拡張は key_share と supported_versions だけ（pre_shared_key などは載せない）
    assert_eq!(client.server_hello_extensions, vec![0x0033, 0x002b]);
    // legacy_session_id はそのまま返す
    assert_eq!(client.session_id_echo, vec![0x55; 32]);
    // ALPN の提示がなければ EncryptedExtensions に ALPN は載せない
    assert!(client.encrypted_extension_types.is_empty());
}

#[test]
fn suite_follows_server_preference_not_client_order() {
    for (offered, want) in [
        (vec![0x1302, 0x1301], CipherSuite::TlsAes128GcmSha256),
        (vec![0x1302], CipherSuite::TlsAes256GcmSha384),
        (
            vec![0x1302, 0x1303, 0x1301],
            CipherSuite::TlsChacha20Poly1305Sha256,
        ),
    ] {
        let mut hello = Hello::x25519(&KEY_A);
        hello.suites = offered;
        let client = complete_handshake(&hello, KEY_A);
        assert_eq!(client.suite, Some(want));
    }
}

fn first_error(hello: &Hello) -> ShieldError {
    server().receive(&hello_record(hello)).unwrap_err()
}

#[test]
fn no_common_suite_is_handshake_failure() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.suites = vec![0x009c, 0xc02f];
    assert_eq!(
        first_error(&hello),
        ShieldError::Fatal(AlertDescription::HandshakeFailure)
    );
}

#[test]
fn missing_tls13_is_protocol_version() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.versions = vec![0x0303, 0x0302];
    assert_eq!(
        first_error(&hello),
        ShieldError::Fatal(AlertDescription::ProtocolVersion)
    );
}

#[test]
fn missing_ecdsa_p256_signature_algorithm_is_handshake_failure() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.sigalgs = vec![0x0804, 0x0805, 0x0806, 0x0807];
    assert_eq!(
        first_error(&hello),
        ShieldError::Fatal(AlertDescription::HandshakeFailure)
    );
}

#[test]
fn no_common_group_is_handshake_failure() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.groups = vec![0x0017, 0x0018];
    hello.shares = vec![(0x0017, unhex(P256_GENERATOR))];
    assert_eq!(
        first_error(&hello),
        ShieldError::Fatal(AlertDescription::HandshakeFailure)
    );
}

#[test]
fn unknown_groups_suites_extensions_and_signature_algorithms_are_ignored() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.suites = vec![0x0a0a, 0x1301, 0xfafa];
    hello.groups = vec![0x2a2a, 0x6399, 0x001d];
    hello.sigalgs = vec![0x0a0a, SIGNATURE_ECDSA_SECP256R1_SHA256, 0x0909];
    hello.shares.insert(0, (0x2a2a, vec![0]));
    let client = complete_handshake(&hello, KEY_A);
    assert_eq!(client.suite, Some(CipherSuite::TlsAes128GcmSha256));
}

#[test]
fn low_order_x25519_share_is_illegal_parameter() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.shares = vec![(0x001d, vec![0u8; 32])];
    assert_eq!(
        first_error(&hello),
        ShieldError::Fatal(AlertDescription::IllegalParameter)
    );
}

// ---- ALPN ----

#[test]
fn alpn_selects_http_1_1_when_offered() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.alpn = Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    let client = complete_handshake(&hello, KEY_A);
    assert_eq!(client.encrypted_extension_types, vec![0x0010]);
}

#[test]
fn alpn_without_http_1_1_is_no_application_protocol() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.alpn = Some(vec![b"h2".to_vec(), b"spdy/3".to_vec()]);
    assert_eq!(
        first_error(&hello),
        ShieldError::Fatal(AlertDescription::NoApplicationProtocol)
    );
}

#[test]
fn alpn_result_is_reported_as_http_1_1() {
    let mut server = server();
    let hello = Hello::x25519(&KEY_A);
    let msg = hello.message();
    let out = server.receive(&record(0x16, &msg)).unwrap();
    let mut client = Client::new(KEY_A);
    let (finished, _) = client.finish(&out, &msg, &server_public());
    server.receive(&finished).unwrap();
    assert_eq!(server.into_outcome().unwrap().alpn, b"http/1.1");
}

// ---- HelloRetryRequest ----

fn p256_only_hello() -> Hello {
    let mut hello = Hello::x25519(&KEY_A);
    hello.shares = vec![(0x0017, unhex(P256_GENERATOR))];
    hello
}

#[test]
fn hello_retry_request_is_sent_once_when_key_share_is_missing() {
    let mut server = server();
    let hello1 = p256_only_hello();
    let out = server.receive(&hello_record(&hello1)).unwrap();
    let records = split_records(&out);
    // HelloRetryRequest、ChangeCipherSpec の順
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].0, 0x16);
    assert_eq!(records[1], (0x14, vec![0x01]));
    let hrr = &records[0].1;
    assert_eq!(hrr[0], 2);
    assert_eq!(
        &hrr[6..38],
        unhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c").as_slice()
    );
    // 選ぶグループは x25519（key_share 拡張は 2 バイトのグループだけ）
    let tail = hrr.len();
    assert_eq!(&hrr[tail - 6..], &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    assert_eq!(
        &hrr[tail - 12..tail - 6],
        &[0x00, 0x33, 0x00, 0x02, 0x00, 0x1d]
    );

    // 2 つ目の ClientHello は x25519 の key_share だけを持つ。それ以外は 1 つ目と同じ。
    let mut hello2 = hello1.clone();
    hello2.shares = vec![(0x001d, x25519_public_key(&KEY_A).to_vec())];
    let msg2 = hello2.message();
    let out2 = server.receive(&record(0x16, &msg2)).unwrap();

    // クライアント側: message_hash を使ったトランスクリプトで続ける
    let suite = CipherSuite::TlsChacha20Poly1305Sha256;
    let mut prefix = vec![254, 0, 0, 32];
    prefix.extend_from_slice(&hash(suite, &hello1.message()));
    prefix.extend_from_slice(hrr);
    prefix.extend_from_slice(&msg2);
    let mut client = Client::new(KEY_A);
    let (finished, _) = client.finish(&out2, &prefix, &server_public());
    // 2 つ目の出力に ChangeCipherSpec は 2 回目を載せない
    assert_eq!(
        split_records(&out2).iter().filter(|r| r.0 == 0x14).count(),
        0
    );
    server.receive(&finished).unwrap();
    assert!(server.is_complete());
}

#[test]
fn second_client_hello_differing_outside_key_share_is_illegal_parameter() {
    type Change = Box<dyn Fn(&mut Hello)>;
    let changes: Vec<(&str, Change)> = vec![
        ("suites", Box::new(|h| h.suites = vec![0x1303])),
        ("groups", Box::new(|h| h.groups = vec![0x001d])),
        (
            "sigalgs",
            Box::new(|h| h.sigalgs = vec![SIGNATURE_ECDSA_SECP256R1_SHA256]),
        ),
        ("session_id", Box::new(|h| h.session_id = vec![1; 32])),
        (
            "alpn",
            Box::new(|h| h.alpn = Some(vec![b"http/1.1".to_vec()])),
        ),
        ("psk_modes", Box::new(|h| h.psk_modes = true)),
    ];
    for (name, change) in changes {
        let mut server = server();
        let hello1 = p256_only_hello();
        server.receive(&hello_record(&hello1)).unwrap();
        let mut hello2 = hello1.clone();
        hello2.shares = vec![(0x001d, x25519_public_key(&KEY_A).to_vec())];
        change(&mut hello2);
        assert_eq!(
            server.receive(&hello_record(&hello2)).unwrap_err(),
            ShieldError::Fatal(AlertDescription::IllegalParameter),
            "{name}"
        );
    }
}

#[test]
fn second_client_hello_must_carry_exactly_the_requested_key_share() {
    // key_share が元のまま（P-256 だけ）
    let mut server_a = server();
    let hello1 = p256_only_hello();
    server_a.receive(&hello_record(&hello1)).unwrap();
    assert_eq!(
        server_a.receive(&hello_record(&hello1)).unwrap_err(),
        ShieldError::Fatal(AlertDescription::IllegalParameter)
    );
    // 要求したグループに加えて別の key_share を持つ
    let mut server_b = server();
    server_b.receive(&hello_record(&hello1)).unwrap();
    let mut hello2 = hello1.clone();
    hello2.shares = vec![
        (0x001d, x25519_public_key(&KEY_A).to_vec()),
        (0x0017, unhex(P256_GENERATOR)),
    ];
    assert_eq!(
        server_b.receive(&hello_record(&hello2)).unwrap_err(),
        ShieldError::Fatal(AlertDescription::IllegalParameter)
    );
}

#[test]
fn unsolicited_cookie_is_illegal_parameter() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.cookie = Some(vec![1, 2, 3]);
    assert_eq!(
        first_error(&hello),
        ShieldError::Fatal(AlertDescription::IllegalParameter)
    );
    let mut server = server();
    let hello1 = p256_only_hello();
    server.receive(&hello_record(&hello1)).unwrap();
    let mut hello2 = hello1.clone();
    hello2.shares = vec![(0x001d, x25519_public_key(&KEY_A).to_vec())];
    hello2.cookie = Some(vec![9]);
    assert_eq!(
        server.receive(&hello_record(&hello2)).unwrap_err(),
        ShieldError::Fatal(AlertDescription::IllegalParameter)
    );
}

// ---- ChangeCipherSpec ----

#[test]
fn change_cipher_spec_rules() {
    // ClientHello の前
    assert_eq!(
        server().receive(&record(0x14, &[1])).unwrap_err(),
        ShieldError::Fatal(AlertDescription::UnexpectedMessage)
    );
    // 内容が 0x01 でない・長さが違う
    for body in [&[0u8][..], &[2][..], &[1, 1][..]] {
        let mut s = server();
        s.receive(&p256_only_record()).unwrap();
        assert_eq!(
            s.receive(&record(0x14, body)).unwrap_err(),
            ShieldError::Fatal(AlertDescription::UnexpectedMessage),
            "{body:?}"
        );
    }
    // 1 つだけ受理し、2 つ目は拒否する
    let mut s = server();
    s.receive(&p256_only_record()).unwrap();
    s.receive(&record(0x14, &[1])).unwrap();
    assert_eq!(
        s.receive(&record(0x14, &[1])).unwrap_err(),
        ShieldError::Fatal(AlertDescription::UnexpectedMessage)
    );
}

fn p256_only_record() -> Vec<u8> {
    hello_record(&p256_only_hello())
}

#[test]
fn client_change_cipher_spec_between_hello_and_finished_is_accepted_once() {
    // ClientHello の後、Finished の前に 1 つ（finish() が送る形）。complete_handshake が通ることで確認済み。
    // ここでは Finished の前に 2 つ送ると拒否されることを確かめる。
    let mut s = server();
    let hello = Hello::x25519(&KEY_A);
    let msg = hello.message();
    let out = s.receive(&record(0x16, &msg)).unwrap();
    let mut client = Client::new(KEY_A);
    let (finished, _) = client.finish(&out, &msg, &server_public());
    let mut doubled = record(0x14, &[1]);
    doubled.extend_from_slice(&finished);
    assert_eq!(
        s.receive(&doubled).unwrap_err(),
        ShieldError::Fatal(AlertDescription::UnexpectedMessage)
    );
}

// ---- PSK と 0-RTT ----

#[test]
fn pre_shared_key_is_not_accepted_and_a_full_handshake_is_done() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.psk_modes = true;
    hello.psk = true;
    let client = complete_handshake(&hello, KEY_A);
    // ServerHello に pre_shared_key（0x0029）は載らない
    assert_eq!(client.server_hello_extensions, vec![0x0033, 0x002b]);
    // 証明書の認証（CertificateVerify の署名の検証）も行われている（finish() が確認する）
}

#[test]
fn pre_shared_key_structure_is_checked_but_never_accepted() {
    // psk_key_exchange_modes なしの pre_shared_key は拒否
    let mut hello = Hello::x25519(&KEY_A);
    hello.psk = true;
    assert_eq!(
        first_error(&hello),
        ShieldError::Fatal(AlertDescription::IllegalParameter)
    );
    // 構造が壊れた early_data（空でない）
    let mut msg = {
        let mut h = Hello::x25519(&KEY_A);
        h.early_data = true;
        h.message()
    };
    // early_data 拡張（種別 0x002a、長さ 0）の長さを 1 にして 1 バイト足す
    let pos = msg
        .windows(4)
        .position(|w| w == [0x00, 0x2a, 0x00, 0x00])
        .unwrap();
    msg[pos + 3] = 1;
    msg.insert(pos + 4, 0);
    let ext_len_pos = 4 + 2 + 32 + 1 + 32 + 2 + 6 + 2;
    let new_ext = u16::from_be_bytes([msg[ext_len_pos], msg[ext_len_pos + 1]]) + 1;
    msg[ext_len_pos..ext_len_pos + 2].copy_from_slice(&new_ext.to_be_bytes());
    let new_len = msg.len() - 4;
    msg[1] = (new_len >> 16) as u8;
    msg[2] = (new_len >> 8) as u8;
    msg[3] = new_len as u8;
    assert_eq!(
        server().receive(&record(0x16, &msg)).unwrap_err(),
        ShieldError::Fatal(AlertDescription::DecodeError)
    );
}

#[test]
fn psk_only_offer_without_a_common_group_is_handshake_failure() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.groups = vec![0x0017];
    hello.shares = vec![];
    hello.psk_modes = true;
    hello.psk = true;
    assert_eq!(
        first_error(&hello),
        ShieldError::Fatal(AlertDescription::HandshakeFailure)
    );
}

#[test]
fn early_data_is_not_accepted_and_early_records_end_the_connection() {
    let mut hello = Hello::x25519(&KEY_A);
    hello.early_data = true;
    hello.psk_modes = true;
    hello.psk = true;
    let msg = hello.message();

    // ClientHello の直後に、早期データのつもりの保護レコードが続く
    let mut s = server();
    let mut input = record(0x16, &msg);
    input.extend_from_slice(&record(0x17, &[0x99; 40]));
    let err = s.receive(&input).unwrap_err();
    assert_eq!(err, ShieldError::Fatal(AlertDescription::BadRecordMac));
    assert!(s.early_data_was_offered());

    // サーバーの出力に early_data は載らない
    let mut s = server();
    let out = s.receive(&record(0x16, &msg)).unwrap();
    let mut client = Client::new(KEY_A);
    let (finished, _) = client.finish(&out, &msg, &server_public());
    assert!(!client.encrypted_extension_types.contains(&0x002a));
    assert!(!client.server_hello_extensions.contains(&0x002a));
    s.receive(&finished).unwrap();
    assert!(s.is_complete());

    // HelloRetryRequest の後、2 つ目の ClientHello の前の早期データのレコードも終える
    let mut s = server();
    let mut h1 = p256_only_hello();
    h1.early_data = true;
    s.receive(&hello_record(&h1)).unwrap();
    assert_eq!(
        s.receive(&record(0x17, &[0x99; 40])).unwrap_err(),
        ShieldError::Fatal(AlertDescription::UnexpectedMessage)
    );
}

// ---- クライアントの Finished ----

fn server_waiting_for_finished() -> (ServerHandshake, Client, Vec<u8>, KeyScheduleSecrets) {
    let mut s = server();
    let hello = Hello::x25519(&KEY_A);
    let msg = hello.message();
    let out = s.receive(&record(0x16, &msg)).unwrap();
    let mut client = Client::new(KEY_A);
    let (finished, secrets) = client.finish(&out, &msg, &server_public());
    (s, client, finished, secrets)
}

fn client_record(secrets: &KeyScheduleSecrets, kind: ContentType, body: &[u8]) -> Vec<u8> {
    let mut tx = RecordProtection::new(
        RecordDirection::Transmit,
        secrets.suite,
        secrets.c_hs.clone(),
        &secrets.ks,
    );
    tx.seal_record(kind, body, 0).unwrap()
}

#[test]
fn wrong_client_finished_is_decrypt_error() {
    let (mut s, _, _, secrets) = server_waiting_for_finished();
    let mut bad = vec![20, 0, 0, 32];
    bad.extend_from_slice(&[0u8; 32]);
    let rec = client_record(&secrets, ContentType::Handshake, &bad);
    assert_eq!(
        s.receive(&rec).unwrap_err(),
        ShieldError::Fatal(AlertDescription::DecryptError)
    );
}

#[test]
fn client_finished_with_wrong_length_or_trailing_bytes_is_rejected() {
    let (mut s, _, _, secrets) = server_waiting_for_finished();
    let rec = client_record(
        &secrets,
        ContentType::Handshake,
        &[20, 0, 0, 5, 1, 2, 3, 4, 5],
    );
    assert_eq!(
        s.receive(&rec).unwrap_err(),
        ShieldError::Fatal(AlertDescription::DecodeError)
    );

    let (mut s, _, _, secrets) = server_waiting_for_finished();
    let mut long = vec![20, 0, 0, 32];
    long.extend_from_slice(&[0u8; 33]);
    let rec = client_record(&secrets, ContentType::Handshake, &long);
    assert_eq!(
        s.receive(&rec).unwrap_err(),
        ShieldError::Fatal(AlertDescription::UnexpectedMessage)
    );
}

#[test]
fn unexpected_handshake_messages_before_client_finished_are_rejected() {
    // NewSessionTicket(4)・CertificateRequest(13)・ClientHello(1)・KeyUpdate(24) など
    for kind in [1u8, 4, 13, 24, 11, 15] {
        let (mut s, _, _, secrets) = server_waiting_for_finished();
        let rec = client_record(&secrets, ContentType::Handshake, &[kind, 0, 0, 1, 0]);
        assert_eq!(
            s.receive(&rec).unwrap_err(),
            ShieldError::Fatal(AlertDescription::UnexpectedMessage),
            "type {kind}"
        );
    }
}

#[test]
fn application_data_before_client_finished_is_unexpected_message() {
    let (mut s, _, _, secrets) = server_waiting_for_finished();
    let rec = client_record(&secrets, ContentType::ApplicationData, b"GET / HTTP/1.1");
    assert_eq!(
        s.receive(&rec).unwrap_err(),
        ShieldError::Fatal(AlertDescription::UnexpectedMessage)
    );
}

#[test]
fn tampered_protected_record_is_bad_record_mac() {
    let (mut s, _, finished, _) = server_waiting_for_finished();
    let mut tampered = finished.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        s.receive(&tampered).unwrap_err(),
        ShieldError::Fatal(AlertDescription::BadRecordMac)
    );
}

#[test]
fn client_finished_split_across_records_is_accepted() {
    let mut s = server();
    let hello = Hello::x25519(&KEY_A);
    let msg = hello.message();
    let out = s.receive(&record(0x16, &msg)).unwrap();
    let mut client = Client::new(KEY_A);
    let (finished, secrets) = client.finish(&out, &msg, &server_public());
    // finished は ChangeCipherSpec（6 バイト）と保護レコード 1 つ。平文を取り出して 2 つに分けて送り直す
    let mut rx = RecordProtection::new(
        RecordDirection::Receive,
        secrets.suite,
        secrets.c_hs.clone(),
        &secrets.ks,
    );
    let (_, plain, _) = rx.open_record(&finished[6..]).unwrap();
    let mut tx = RecordProtection::new(
        RecordDirection::Transmit,
        secrets.suite,
        secrets.c_hs.clone(),
        &secrets.ks,
    );
    let mut wire = record(0x14, &[1]);
    wire.extend_from_slice(
        &tx.seal_record(ContentType::Handshake, &plain[..10], 0)
            .unwrap(),
    );
    wire.extend_from_slice(
        &tx.seal_record(ContentType::Handshake, &plain[10..], 0)
            .unwrap(),
    );
    s.receive(&wire).unwrap();
    assert!(s.is_complete());
}

// ---- 入出力の規則 ----

#[test]
fn empty_input_does_not_make_progress() {
    assert_eq!(
        server().receive(&[]).unwrap_err(),
        ShieldError::TimeoutOrNoProgress
    );
}

#[test]
fn client_hello_may_arrive_one_byte_at_a_time() {
    let mut s = server();
    let hello = Hello::x25519(&KEY_A);
    let wire = hello_record(&hello);
    let mut out = Vec::new();
    for byte in &wire {
        out.extend(s.receive(&[*byte]).unwrap());
    }
    assert!(!out.is_empty());
    let mut client = Client::new(KEY_A);
    let (finished, _) = client.finish(&out, &hello.message(), &server_public());
    // Finished も 1 バイトずつ
    for byte in &finished {
        s.receive(&[*byte]).unwrap();
    }
    assert!(s.is_complete());
}

#[test]
fn input_after_failure_or_completion_is_rejected() {
    let mut s = server();
    assert!(s.receive(&[0x99, 3, 3, 0, 1, 0]).is_err());
    assert!(s.receive(&[0x16]).is_err());

    let (mut s, _, finished, _) = server_waiting_for_finished();
    s.receive(&finished).unwrap();
    assert!(s.receive(&[0x17, 3, 3, 0, 1, 0]).is_err());
}

#[test]
fn bytes_after_client_finished_in_the_same_read_are_rejected() {
    let (mut s, _, finished, secrets) = server_waiting_for_finished();
    let mut input = finished;
    let mut tx = RecordProtection::new(
        RecordDirection::Transmit,
        secrets.suite,
        secrets.c_ap.clone(),
        &secrets.ks,
    );
    input.extend_from_slice(
        &tx.seal_record(ContentType::ApplicationData, b"x", 0)
            .unwrap(),
    );
    assert!(s.receive(&input).is_err());
}

#[test]
fn fatal_alert_is_plain_before_server_hello_and_protected_after() {
    let mut s = server();
    assert_eq!(
        s.fatal_alert_record(AlertDescription::HandshakeFailure),
        vec![0x15, 3, 3, 0, 2, 2, 40]
    );

    let mut s = server();
    let hello = Hello::x25519(&KEY_A);
    let msg = hello.message();
    let out = s.receive(&record(0x16, &msg)).unwrap();
    let mut client = Client::new(KEY_A);
    let (_, secrets) = client.finish(&out, &msg, &server_public());
    let alert = s.fatal_alert_record(AlertDescription::DecryptError);
    assert_eq!(alert[0], 0x17);
    // サーバーのハンドシェイク鍵で復号できる（飛行が 1 レコードなので、次のシーケンス番号は 1）
    let mut rx = RecordProtection::new(
        RecordDirection::Receive,
        secrets.suite,
        secrets.s_hs.clone(),
        &secrets.ks,
    );
    rx.sequence_number = 1;
    let (kind, plain, _) = rx.open_record(&alert).unwrap();
    assert_eq!(kind, ContentType::Alert);
    assert_eq!(plain, vec![2, 51]);
}
