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

## 段 3: ハンドシェイク状態機械（決定 1.1、決定 1.4）

- TLS 1.3 1-RTT ハンドシェイク状態機械（`Start` -> `WaitClientHello` -> `SentServerFlight` -> `Connected`）
- サーバーフライト生成（ServerHello, ChangeCipherSpec, EncryptedExtensions, Certificate, CertificateVerify, Finished）
- 決定的 ECDSA P-256 署名（RFC 6979）と証明書検証
- RFC 8448 テストベクタに基づくハンドシェイク検証

## 段 4: 証明書管理と SNI 照合（決定 2）

- PEM / PKCS#8 / X.509 DER 証明書・秘密鍵の構文解析
- ファイル権限検査（秘密鍵ファイル権限 `0o077` の厳格排除）
- SNI（Server Name Indication）の小文字正規化と照合（完全一致および先頭ワイルドカード `*.domain`）
- 未登録 SNI に対する致命的アラート `unrecognized_name` による即座の切断（暗黙の既定証明書排除）
- アトミックな証明書ストアの再読み込み

## 段 5: 中継・PROXY プロトコル v2・安全なログ（決定 3、決定 5）

- 単一の上流 IPv4/IPv6 アドレス・ポートへの 1:1 中継（接続共有・再利用の禁止）
- PROXY protocol v2 ヘッダー生成（接続元 IP・ポート、暗号化情報、SNI authority TLV）
- エラー処理（上流到達不能時の固定 `502 Bad Gateway` 送出、上流異常時のアラート送出）
- 安全なログ出力（SNI の英数字サニタイズ、平文・暗号鍵・生 ClientHello の出力禁止）

## 段 6: P-256 鍵交換と HelloRetryRequest（決定 1.2）

- P-256（`secp256r1`）ECDH 鍵交換の実装
- `key_share` 不足時の HelloRetryRequest（HRR）生成と再試行（1 接続あたり 1 回のみ）
- 不正な公開鍵（無限遠点、曲線上外）の拒絶（`illegal_parameter`）

## 段 7: 相互運用試験・負荷実測・公開前記録（決定 6、Issue #22）

- 外部プロセス（`openssl s_client`、`curl`）を用いた TLS 1.3 相互運用試験
  - OpenSSL 3.x による TLS 1.3 接続（X25519 および P-256）
  - curl による HTTPS GET リクエストおよび `HTTP/1.1 200 OK` 応答検証
  - 未登録 SNI に対するサーバー拒絶動作の検証
- 1 コアあたりのハンドシェイク処理性能の実測と負荷記録
- [公開前検証記録（docs/pre-publish-record.md）](docs/pre-publish-record.md) の作成
  - G2 記録（各設計決定への適合確認）
  - G3 においてリポジトリ所有者へ提示する確認項目（適合限界、CPU 費用、証明書運用、平文区間、長時間ファジング等）
  - **G2 は外部公開を承認しない**（外部公開の承認は G3 で所有者が決定）


