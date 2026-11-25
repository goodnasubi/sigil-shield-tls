//! 資源上限の境界試験（ADR 0063 決定 4.5）
//!
//! 各項目について、直下・一致（下限/上限）・超過の境界を確かめる。
//! 範囲外・無制限の値は受け付けず、検証で拒否されることを確認する。

#![allow(clippy::field_reassign_with_default)]

use sigil_shield_tls::limits::{LimitError, ShieldLimits};

#[test]
fn test_default_limits_are_valid() {
    let limits = ShieldLimits::default();
    assert!(limits.validate().is_ok());
}

#[test]
fn test_max_connections_boundary() {
    // 範囲: 1〜65536 (ただしメモリ上限 256 MiB / 64 KiB = 4096 接続)
    // 直下 (0) -> エラー
    let mut limits = ShieldLimits::default();
    limits.max_connections = 0;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_connections",
            value: 0,
            min: 1,
            max: 65536
        })
    ));

    // 一致下限 (1) -> OK
    limits.max_connections = 1;
    assert!(limits.validate().is_ok());

    // メモリ上限境界: 4096 接続 × 64 KiB = 256 MiB (一致上限) -> OK
    limits.max_connections = 4096;
    assert!(limits.validate().is_ok());

    // メモリ上限境界: 4097 接続 × 64 KiB = 256.0625 MiB (メモリ超過) -> エラー
    limits.max_connections = 4097;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::MemoryBudgetExceeded { .. })
    ));

    // 数値範囲超過: 65537 -> エラー
    limits.max_connections = 65537;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_connections",
            value: 65537,
            ..
        })
    ));
}

#[test]
fn test_max_handshaking_connections_boundary() {
    // 範囲: 1〜1024
    let mut limits = ShieldLimits::default();

    // 直下 (0)
    limits.max_handshaking_connections = 0;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_handshaking_connections",
            value: 0,
            min: 1,
            max: 1024
        })
    ));

    // 一致下限 (1)
    limits.max_handshaking_connections = 1;
    assert!(limits.validate().is_ok());

    // 一致上限 (1024)
    limits.max_handshaking_connections = 1024;
    assert!(limits.validate().is_ok());

    // 超過 (1025)
    limits.max_handshaking_connections = 1025;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_handshaking_connections",
            value: 1025,
            min: 1,
            max: 1024
        })
    ));
}

#[test]
fn test_max_connections_per_source_boundary() {
    // 範囲: 1〜1024
    let mut limits = ShieldLimits::default();

    // 直下 (0)
    limits.max_connections_per_source = 0;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_connections_per_source",
            value: 0,
            min: 1,
            max: 1024
        })
    ));

    // 一致下限 (1)
    limits.max_connections_per_source = 1;
    assert!(limits.validate().is_ok());

    // 一致上限 (1024)
    limits.max_connections_per_source = 1024;
    assert!(limits.validate().is_ok());

    // 超過 (1025)
    limits.max_connections_per_source = 1025;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_connections_per_source",
            value: 1025,
            min: 1,
            max: 1024
        })
    ));
}

#[test]
fn test_max_handshaking_per_source_boundary() {
    // 範囲: 1〜64
    let mut limits = ShieldLimits::default();

    // 直下 (0)
    limits.max_handshaking_per_source = 0;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_handshaking_per_source",
            value: 0,
            min: 1,
            max: 64
        })
    ));

    // 一致下限 (1)
    limits.max_handshaking_per_source = 1;
    assert!(limits.validate().is_ok());

    // 一致上限 (64)
    limits.max_handshaking_per_source = 64;
    assert!(limits.validate().is_ok());

    // 超過 (65)
    limits.max_handshaking_per_source = 65;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_handshaking_per_source",
            value: 65,
            min: 1,
            max: 64
        })
    ));
}

#[test]
fn test_max_concurrent_crypto_tasks_boundary() {
    // 範囲: 1〜64
    let mut limits = ShieldLimits::default();

    // 直下 (0)
    limits.max_concurrent_crypto_tasks = 0;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_concurrent_crypto_tasks",
            value: 0,
            min: 1,
            max: 64
        })
    ));

    // 一致下限 (1)
    limits.max_concurrent_crypto_tasks = 1;
    assert!(limits.validate().is_ok());

    // 一致上限 (64)
    limits.max_concurrent_crypto_tasks = 64;
    assert!(limits.validate().is_ok());

    // 超過 (65)
    limits.max_concurrent_crypto_tasks = 65;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "max_concurrent_crypto_tasks",
            value: 65,
            min: 1,
            max: 64
        })
    ));
}

#[test]
fn test_handshake_timeout_boundary() {
    // 範囲: 1〜60 秒
    let mut limits = ShieldLimits::default();

    limits.handshake_timeout_secs = 0;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "handshake_timeout_secs",
            value: 0,
            min: 1,
            max: 60
        })
    ));

    limits.handshake_timeout_secs = 1;
    assert!(limits.validate().is_ok());

    limits.handshake_timeout_secs = 60;
    assert!(limits.validate().is_ok());

    limits.handshake_timeout_secs = 61;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "handshake_timeout_secs",
            value: 61,
            min: 1,
            max: 60
        })
    ));
}

#[test]
fn test_idle_timeout_boundary() {
    // 範囲: 5〜3600 秒
    let mut limits = ShieldLimits::default();

    limits.idle_timeout_secs = 4;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "idle_timeout_secs",
            value: 4,
            min: 5,
            max: 3600
        })
    ));

    limits.idle_timeout_secs = 5;
    assert!(limits.validate().is_ok());

    limits.idle_timeout_secs = 3600;
    assert!(limits.validate().is_ok());

    limits.idle_timeout_secs = 3601;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "idle_timeout_secs",
            value: 3601,
            min: 5,
            max: 3600
        })
    ));
}

#[test]
fn test_write_timeout_boundary() {
    // 範囲: 1〜300 秒
    let mut limits = ShieldLimits::default();

    limits.write_timeout_secs = 0;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "write_timeout_secs",
            value: 0,
            min: 1,
            max: 300
        })
    ));

    limits.write_timeout_secs = 1;
    assert!(limits.validate().is_ok());

    limits.write_timeout_secs = 300;
    assert!(limits.validate().is_ok());

    limits.write_timeout_secs = 301;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "write_timeout_secs",
            value: 301,
            min: 1,
            max: 300
        })
    ));
}

#[test]
fn test_upstream_connect_timeout_boundary() {
    // 範囲: 1〜30 秒
    let mut limits = ShieldLimits::default();

    limits.upstream_connect_timeout_secs = 0;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "upstream_connect_timeout_secs",
            value: 0,
            min: 1,
            max: 30
        })
    ));

    limits.upstream_connect_timeout_secs = 1;
    assert!(limits.validate().is_ok());

    limits.upstream_connect_timeout_secs = 30;
    assert!(limits.validate().is_ok());

    limits.upstream_connect_timeout_secs = 31;
    assert!(matches!(
        limits.validate(),
        Err(LimitError::OutOfRange {
            parameter: "upstream_connect_timeout_secs",
            value: 31,
            min: 1,
            max: 30
        })
    ));
}
