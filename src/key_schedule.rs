//! TLS 1.3 鍵スケジュール (ADR 0063 決定 1, RFC 8446 §7.1)
//!
//! - ハンドシェイク秘密からアプリケーション秘密までの導出
//! - 方向別の key と iv の導出 (HKDF-Expand-Label)
//! - 鍵更新時の次世代 Traffic Secret 導出 ("traffic upd")

use crate::cipher_suite::CipherSuite;
use crate::crypto::{
    hkdf_expand_label_sha256, hkdf_expand_label_sha384, hkdf_extract_sha256, hkdf_extract_sha384,
    sha256, sha384,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySchedule {
    pub suite: CipherSuite,
}

impl KeySchedule {
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }

    /// 空文字列に対するハッシュ値 Transcript-Hash("")
    pub fn empty_hash(&self) -> Vec<u8> {
        match self.suite {
            CipherSuite::TlsChacha20Poly1305Sha256 | CipherSuite::TlsAes128GcmSha256 => {
                sha256(b"").to_vec()
            }
            CipherSuite::TlsAes256GcmSha384 => sha384(b"").to_vec(),
        }
    }

    /// HKDF-Extract の実行
    pub fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self.suite {
            CipherSuite::TlsChacha20Poly1305Sha256 | CipherSuite::TlsAes128GcmSha256 => {
                hkdf_extract_sha256(salt, ikm).to_vec()
            }
            CipherSuite::TlsAes256GcmSha384 => hkdf_extract_sha384(salt, ikm).to_vec(),
        }
    }

    /// HKDF-Expand-Label の実行 ("tls13 " プレフィックスを内部で付与)
    pub fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        out_len: usize,
    ) -> Vec<u8> {
        match self.suite {
            CipherSuite::TlsChacha20Poly1305Sha256 | CipherSuite::TlsAes128GcmSha256 => {
                hkdf_expand_label_sha256(secret, label, context, out_len)
            }
            CipherSuite::TlsAes256GcmSha384 => {
                hkdf_expand_label_sha384(secret, label, context, out_len)
            }
        }
    }

    /// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
    pub fn derive_secret(&self, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
        let hash_len = self.suite.hash_len();
        self.hkdf_expand_label(secret, label, transcript_hash, hash_len)
    }

    /// Early Secret の導出 (PSK なし: salt=0, IKM=0)
    pub fn early_secret(&self) -> Vec<u8> {
        let hash_len = self.suite.hash_len();
        let zeros = vec![0u8; hash_len];
        self.hkdf_extract(&zeros, &zeros)
    }

    /// Handshake Secret の導出:
    /// derived_secret = Derive-Secret(Early Secret, "derived", "")
    /// Handshake Secret = HKDF-Extract(salt = derived_secret, IKM = shared_secret)
    pub fn handshake_secret(&self, early_secret: &[u8], shared_secret: &[u8]) -> Vec<u8> {
        let empty_h = self.empty_hash();
        let derived = self.derive_secret(early_secret, "derived", &empty_h);
        self.hkdf_extract(&derived, shared_secret)
    }

    /// Master Secret の導出:
    /// derived_secret = Derive-Secret(Handshake Secret, "derived", "")
    /// Master Secret = HKDF-Extract(salt = derived_secret, IKM = 0)
    pub fn master_secret(&self, handshake_secret: &[u8]) -> Vec<u8> {
        let empty_h = self.empty_hash();
        let derived = self.derive_secret(handshake_secret, "derived", &empty_h);
        let zeros = vec![0u8; self.suite.hash_len()];
        self.hkdf_extract(&derived, &zeros)
    }

    /// クライアントハンドシェイクトラフィック秘密 (c hs traffic)
    pub fn client_handshake_traffic_secret(
        &self,
        handshake_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Vec<u8> {
        self.derive_secret(handshake_secret, "c hs traffic", transcript_hash)
    }

    /// サーバーハンドシェイクトラフィック秘密 (s hs traffic)
    pub fn server_handshake_traffic_secret(
        &self,
        handshake_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Vec<u8> {
        self.derive_secret(handshake_secret, "s hs traffic", transcript_hash)
    }

    /// クライアントアプリケーショントラフィック秘密 0 (c ap traffic)
    pub fn client_application_traffic_secret_0(
        &self,
        master_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Vec<u8> {
        self.derive_secret(master_secret, "c ap traffic", transcript_hash)
    }

    /// サーバーアプリケーショントラフィック秘密 0 (s ap traffic)
    pub fn server_application_traffic_secret_0(
        &self,
        master_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Vec<u8> {
        self.derive_secret(master_secret, "s ap traffic", transcript_hash)
    }

    /// トラフィック鍵の導出: HKDF-Expand-Label(Secret, "key", "", key_length)
    pub fn derive_traffic_key(&self, traffic_secret: &[u8]) -> Vec<u8> {
        self.hkdf_expand_label(traffic_secret, "key", b"", self.suite.key_len())
    }

    /// トラフィック IV の導出: HKDF-Expand-Label(Secret, "iv", "", 12)
    pub fn derive_traffic_iv(&self, traffic_secret: &[u8]) -> [u8; 12] {
        let bytes = self.hkdf_expand_label(traffic_secret, "iv", b"", 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&bytes);
        iv
    }

    /// トラフィック鍵と IV を同時に導出
    pub fn derive_traffic_key_iv(&self, traffic_secret: &[u8]) -> (Vec<u8>, [u8; 12]) {
        (
            self.derive_traffic_key(traffic_secret),
            self.derive_traffic_iv(traffic_secret),
        )
    }

    /// 鍵更新時の次世代 Traffic Secret 導出:
    /// next_secret = HKDF-Expand-Label(current_secret, "traffic upd", "", Hash.length)
    pub fn next_traffic_secret(&self, current_traffic_secret: &[u8]) -> Vec<u8> {
        self.hkdf_expand_label(
            current_traffic_secret,
            "traffic upd",
            b"",
            self.suite.hash_len(),
        )
    }
}
