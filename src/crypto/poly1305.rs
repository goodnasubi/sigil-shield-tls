//! Poly1305 一元 MAC (RFC 8439)

fn read_le32(b: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let len = std::cmp::min(4, b.len());
    buf[..len].copy_from_slice(&b[..len]);
    u32::from_le_bytes(buf)
}

pub fn poly1305_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let r0 = (read_le32(&key[0..4]) & 0x3ffffff) as u64;
    let r1 = ((read_le32(&key[3..7]) >> 2) & 0x3ffff03) as u64;
    let r2 = ((read_le32(&key[6..10]) >> 4) & 0x3ffc0ff) as u64;
    let r3 = ((read_le32(&key[9..13]) >> 6) & 0x3f03fff) as u64;
    let r4 = ((read_le32(&key[12..16]) >> 8) & 0x00fffff) as u64;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    let mut offset = 0;
    while offset < message.len() {
        let chunk_len = std::cmp::min(16, message.len() - offset);
        let chunk = &message[offset..offset + chunk_len];

        let mut block = [0u8; 16];
        block[..chunk_len].copy_from_slice(chunk);
        let hibit = if chunk_len == 16 {
            1u64 << 24
        } else {
            block[chunk_len] = 1;
            0u64
        };

        let b0 = (read_le32(&block[0..4]) & 0x3ffffff) as u64;
        let b1 = ((read_le32(&block[3..7]) >> 2) & 0x3ffffff) as u64;
        let b2 = ((read_le32(&block[6..10]) >> 4) & 0x3ffffff) as u64;
        let b3 = ((read_le32(&block[9..13]) >> 6) & 0x3ffffff) as u64;
        let b4 = ((read_le32(&block[12..16]) >> 8) as u64) | hibit;

        h0 += b0;
        h1 += b1;
        h2 += b2;
        h3 += b3;
        h4 += b4;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h0 = d0 & 0x3ffffff;
        let d1_carry = d1 + c;
        c = d1_carry >> 26;
        h1 = d1_carry & 0x3ffffff;
        let d2_carry = d2 + c;
        c = d2_carry >> 26;
        h2 = d2_carry & 0x3ffffff;
        let d3_carry = d3 + c;
        c = d3_carry >> 26;
        h3 = d3_carry & 0x3ffffff;
        let d4_carry = d4 + c;
        c = d4_carry >> 26;
        h4 = d4_carry & 0x3ffffff;

        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        offset += 16;
    }

    let mut c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    // 完全な mod (2^130 - 5) のリダクション
    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    let g4 = h4 + c;

    let mask = (g4 >> 26).wrapping_neg() & 1;
    let not_mask = 1 ^ mask;
    h0 = (h0 & not_mask) | (g0 & mask);
    h1 = (h1 & not_mask) | (g1 & mask);
    h2 = (h2 & not_mask) | (g2 & mask);
    h3 = (h3 & not_mask) | (g3 & mask);
    h4 = (h4 & not_mask) | ((g4 & 0x3ffffff) & mask);

    let w0 = ((h0 | (h1 << 26)) & 0xffffffff) as u32;
    let w1 = (((h1 >> 6) | (h2 << 20)) & 0xffffffff) as u32;
    let w2 = (((h2 >> 12) | (h3 << 14)) & 0xffffffff) as u32;
    let w3 = (((h3 >> 18) | (h4 << 8)) & 0xffffffff) as u32;

    let s0 = read_le32(&key[16..20]);
    let s1 = read_le32(&key[20..24]);
    let s2 = read_le32(&key[24..28]);
    let s3 = read_le32(&key[28..32]);

    let f0 = (w0 as u64) + (s0 as u64);
    let f1 = (w1 as u64) + (s1 as u64) + (f0 >> 32);
    let f2 = (w2 as u64) + (s2 as u64) + (f1 >> 32);
    let f3 = (w3 as u64) + (s3 as u64) + (f2 >> 32);

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
    out[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
    out[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
    out
}
