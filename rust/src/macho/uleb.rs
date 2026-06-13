//! ULEB128 / SLEB128 decoding, mirroring ULEB128.{h,m}.

/// Read an unsigned LEB128 starting at `*pos` in `data`, advancing `*pos`.
pub fn read_uleb128(data: &[u8], pos: &mut usize) -> u64 {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    while *pos < data.len() {
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    result
}

/// Read a signed LEB128 starting at `*pos` in `data`, advancing `*pos`.
pub fn read_sleb128(data: &[u8], pos: &mut usize) -> i64 {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut byte = 0u8;
    while *pos < data.len() {
        byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    // sign extend
    if shift < 64 && (byte & 0x40) != 0 {
        result |= -1i64 << shift;
    }
    result
}
