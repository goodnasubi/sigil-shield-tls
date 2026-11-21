# nginx の脆弱性（NGINX2Root）から得た TLS 終端の設計教訓

## 概要

2026-11-18、nginx に深刻な脆弱性5件（総称 NGINX2Root、いずれも CVSS v4.0 スコア 9.2）が公開され、nginx 1.30.7 および 1.31.9 で修正された。中心は HTTP/2 フロー制御の整数アンダーフロー（CVE-2026-123007、nginx 1.9.5 = 2015年から潜伏していた）をはじめとするメモリ安全性の欠陥であり、TLS プロトコル自体の欠陥ではない。

sigil-shield-tls は未実装であり、nginx のコードを使わないため、これらの脆弱性の直接の影響はない。本書は、NGINX2Root と同時修正分を含む TLS 周辺の欠陥から、sigil-shield-tls の設計要件を引き出すための記録である。

## TLS 周辺の欠陥と教訓

- **CVE-2026-118899**: TLS 1.3 接続でリクエストボディを読み取る際の無限ループ（サービス不能 / DoS）。
  - 教訓: 読み取り処理は、必ず前進するか、タイムアウトで終了することを仕様で保証する。進展のない読み取りを無期限に繰り返す状態を作らない。
- **CVE-2026-120967**: クライアント証明書検証における SNI バイパス。
  - 教訓: SNI による振り分け先と、証明書を検証する名前（ホスト名）を必ず一致させる。振り分けと検証で名前の解釈がずれる経路を作らない。
- **CVE-2026-123640**: `ssl_preread` モジュールにおける検証不足。
  - 教訓: 終端前の ClientHello パースでは、長さと境界を厳密に検証する。これは sigil-shield-tls の玄関（最初に外部入力を受け取る場所）に当たるため、特に優先度が高い。
- **CVE-2026-120993**: PROXY protocol v2 の処理における NULL ポインタ参照。
  - 教訓: PROXY protocol のパースも攻撃面として扱い、不正な入力でプロセスが落ちないことを保証する。

## 設計要件のまとめ

上記の教訓から得られる次の4要件を、sigil-shield-tls の ADR 起草時に必ず取り込む。

1. 読み取りは必ず前進するかタイムアウトで終了することを仕様で保証する。
2. SNI の振り分け先と、証明書を検証する名前を一致させる。
3. ClientHello のパースでは長さ・境界を厳密に検証する。
4. PROXY protocol のパースも攻撃面として扱い、不正な入力で落ちないことを保証する。

## 出典

- nginx security advisories: https://nginx.org/en/security_advisories.html
- Cloudflare Blog, "nginx2root: five new nginx vulnerabilities, and how Cloudflare protects origins from the worst of them": https://blog.cloudflare.com/nginx2root/
