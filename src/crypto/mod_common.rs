//! 暗号モジュール共通定義

/// 定数時間バイト列比較
#[inline(always)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 秘密を持つバッファを消去する。コンパイラに書き込みを取り除かれないよう volatile で書く。
/// コンパイラが作る一時値やレジスタの内容は消せない（best effort）。
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` は有効な可変参照。
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
