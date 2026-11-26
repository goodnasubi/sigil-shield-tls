# sigil-shield-tls

TLS 終端部品（平文 HTTP で待ち受ける Sigil 製サービスの前段に配置する TLS 終端）。

設計方針と仕様は [ADR 0063](https://github.com/goodnasubi/sigil/blob/main/docs/decisions/0063-shield-tls.md) に基づく。

- [nginx の脆弱性から得た設計教訓](docs/nginx2root-lessons.md)

## 適合の限界（ADR 0063 決定 1.1）

本コンポーネントは **RFC 8446（TLS 1.3）の完全準拠を主張しない**。
RSA 署名に対応せず（ECDSA P-256 のみ）、鍵交換は X25519 と secp256r1（P-256、段 6）に対応する。また、0-RTT・セッション再開・チケット・クライアント証明書は持たない。

## 段 1: 入口の解析（決定 4.2〜4.5）

- レコード層の読み取りと先頭 5 バイトの厳密検査
- ハンドシェイクメッセージの再構成（最大 16 KiB・最大 8 レコード）
- ClientHello の解析（決定 4.3 の全行の規則）
- 致命的アラートと接続終了（fail-closed）
- 読み取りの前進と期限（決定 4.4: 1 バイト以上消費するか終了、消費せず繰り返さない）
- 資源の上限とメモリ予算の検査（決定 4.5）
- ファジング対象（ClientHello 解析、レコード層再構成）

## 段 2: 鍵スケジュールと保護レコード（決定 1、決定 1.3）

- 暗号スイート 3 種の実装（ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM）
  - サーバー優先順: ChaCha20-Poly1305 > AES-128-GCM > AES-256-GCM（定数時間 S-box に対する実測検証済み）
- 暗号基本部品（SHA-256/384, HMAC, HKDF-SHA-256/384, 定数時間 S-box AES, GHASH, ChaCha20, Poly1305）
- TLS 1.3 鍵スケジュール（HKDF-Expand-Label によるハンドシェイク秘密・トラフィック鍵・更新鍵の導出）
- 保護レコード処理（方向別 64 ビットシーケンス番号、12 バイト IV XOR Nonce、平文長 2^14 以下、暗号文長 2^14 + 256 以下、認証失敗時 `bad_record_mac` で即座に終了）
- 鍵更新（KeyUpdate メッセージ送受信、送信 2^23 回到達前の更新および超過時終了、受信 16 回制限）

