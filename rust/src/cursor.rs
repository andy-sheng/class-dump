//! Byte cursor over a Mach-O file's data, mirroring CDDataCursor / CDMachOFileDataCursor.
//!
//! The cursor reads using a configurable byte order and pointer size, so the same code
//! handles 32/64-bit and big/little-endian Mach-O files.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ByteOrder {
    Little,
    Big,
}

/// A cursor positioned at a byte offset within a shared data buffer.
pub struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
    byte_order: ByteOrder,
    ptr_size: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8], byte_order: ByteOrder, ptr_size: usize) -> Self {
        Cursor { data, offset: 0, byte_order, ptr_size }
    }

    pub fn at(data: &'a [u8], byte_order: ByteOrder, ptr_size: usize, offset: usize) -> Self {
        Cursor { data, offset, byte_order, ptr_size }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    pub fn advance(&mut self, n: usize) {
        self.offset += n;
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    pub fn is_at_end(&self) -> bool {
        self.offset >= self.data.len()
    }

    pub fn read_u8(&mut self) -> u8 {
        let v = self.data.get(self.offset).copied().unwrap_or(0);
        self.offset += 1;
        v
    }

    pub fn read_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.read_into(&mut b);
        match self.byte_order {
            ByteOrder::Little => u16::from_le_bytes(b),
            ByteOrder::Big => u16::from_be_bytes(b),
        }
    }

    pub fn read_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.read_into(&mut b);
        match self.byte_order {
            ByteOrder::Little => u32::from_le_bytes(b),
            ByteOrder::Big => u32::from_be_bytes(b),
        }
    }

    pub fn read_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.read_into(&mut b);
        match self.byte_order {
            ByteOrder::Little => u64::from_le_bytes(b),
            ByteOrder::Big => u64::from_be_bytes(b),
        }
    }

    /// Read a pointer-sized value (4 or 8 bytes) using the cursor's pointer size.
    pub fn read_ptr(&mut self) -> u64 {
        match self.ptr_size {
            4 => self.read_u32() as u64,
            _ => self.read_u64(),
        }
    }

    /// Read big-endian u32 regardless of configured byte order (used for the magic number).
    pub fn read_be_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.read_into(&mut b);
        u32::from_be_bytes(b)
    }

    pub fn read_bytes(&mut self, n: usize) -> &'a [u8] {
        let start = self.offset.min(self.data.len());
        let end = (self.offset + n).min(self.data.len());
        self.offset += n;
        &self.data[start..end]
    }

    fn read_into(&mut self, buf: &mut [u8]) {
        let n = buf.len();
        let start = self.offset.min(self.data.len());
        let end = (start + n).min(self.data.len());
        let got = end - start;
        buf[..got].copy_from_slice(&self.data[start..end]);
        self.offset += n;
    }

    /// Read a fixed-length string field, trimming at the first NUL (e.g. segment/section names).
    pub fn read_fixed_string(&mut self, n: usize) -> String {
        let bytes = self.read_bytes(n);
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }
}

/// Read a NUL-terminated ASCII/UTF-8 string starting at `offset` in `data`.
pub fn cstring_at(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let rest = &data[offset..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}
