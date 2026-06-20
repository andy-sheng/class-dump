//! Mach-O file parsing, mirroring CDMachOFile / CDLCSegment / CDSection / CDLCDyldInfo
//! / CDLCDyldChainedFixups / CDSymbol.

pub mod consts;
pub mod uleb;

use crate::cursor::{cstring_at, ByteOrder, Cursor};
use consts::*;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Section {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub flags: u32,
}

impl Section {
    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.addr && addr < self.addr + self.size
    }
    pub fn section_type(&self) -> u32 {
        self.flags & SECTION_TYPE
    }
}

#[derive(Clone)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub sections: Vec<Section>,
}

impl Segment {
    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.vmaddr && addr < self.vmaddr + self.vmsize
    }

    /// File data offset for a vm address within this segment (CDLCSegment fileOffsetForAddress:).
    pub fn file_offset_for_address(&self, addr: u64) -> u64 {
        // Prefer the containing section's mapping (matches CDSection behaviour); fall back to segment.
        for sect in &self.sections {
            if sect.contains_address(addr) {
                if sect.section_type() == S_ZEROFILL {
                    return 0;
                }
                return sect.offset as u64 + (addr - sect.addr);
            }
        }
        self.fileoff + (addr - self.vmaddr)
    }
}

#[derive(Clone)]
pub struct Symbol {
    pub name: String,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub value: u64,
}

impl Symbol {
    pub fn is_external(&self) -> bool {
        self.n_type & N_EXT != 0
    }
    pub fn is_in_section(&self) -> bool {
        (self.n_type & N_TYPE) == N_SECT
    }
}

#[derive(Clone)]
pub struct BuildVersion {
    pub platform: u32,
    pub minos: u32,
    pub sdk: u32,
    pub tools: Vec<(u32, u32)>, // (tool, version)
}

#[derive(Clone)]
pub struct DylibInfo {
    pub name: String,
    pub current_version: u32,
    pub compatibility_version: u32,
}

pub struct MachOFile {
    pub data: Vec<u8>,
    pub filename: String,
    pub byte_order: ByteOrder,
    pub magic: u32,
    pub cputype: i32,
    pub cpusubtype: i32,
    pub filetype: u32,
    pub ncmds: u32,
    pub flags: u32,
    pub uses64: bool,

    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub symbol_base_address: u64,

    pub uuid: Option<[u8; 16]>,
    pub source_version: Option<u64>,
    pub build_version: Option<BuildVersion>,
    pub min_version_macosx: Option<u32>,
    pub min_version_ios: Option<u32>,
    pub dylib_id: Option<DylibInfo>,
    pub dylibs: Vec<DylibInfo>,
    pub run_paths: Vec<String>,
    pub has_encryption: bool,

    // address -> external symbol name (from dyld_info binds and/or chained fixups binds)
    symbol_names_by_address: HashMap<u64, String>,
    // class name -> symbol (for isExported and superclass symbol lookup)
    class_symbols: HashMap<String, Symbol>,
}

impl MachOFile {
    pub fn ptr_size(&self) -> usize {
        if self.uses64 {
            8
        } else {
            4
        }
    }

    pub fn masked_cpu_type(&self) -> i32 {
        self.cputype & !(CPU_ARCH_MASK as i32)
    }

    /// Parse a thin Mach-O image from owned bytes.
    pub fn parse(data: Vec<u8>, filename: String) -> Option<MachOFile> {
        if data.len() < 4 {
            return None;
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let (byte_order, uses64) = match magic {
            MH_MAGIC => (ByteOrder::Big, false),
            MH_MAGIC_64 => (ByteOrder::Big, true),
            MH_CIGAM => (ByteOrder::Little, false),
            MH_CIGAM_64 => (ByteOrder::Little, true),
            _ => return None,
        };

        let ptr_size = if uses64 { 8 } else { 4 };
        let mut file = MachOFile {
            data,
            filename,
            byte_order,
            magic,
            cputype: 0,
            cpusubtype: 0,
            filetype: 0,
            ncmds: 0,
            flags: 0,
            uses64,
            segments: Vec::new(),
            symbols: Vec::new(),
            symbol_base_address: 0,
            uuid: None,
            source_version: None,
            build_version: None,
            min_version_macosx: None,
            min_version_ios: None,
            dylib_id: None,
            dylibs: Vec::new(),
            run_paths: Vec::new(),
            has_encryption: false,
            symbol_names_by_address: HashMap::new(),
            class_symbols: HashMap::new(),
        };

        {
            let data = std::mem::take(&mut file.data);
            let mut cur = Cursor::new(&data, byte_order, ptr_size);
            cur.read_be_u32(); // magic (already known)
            file.cputype = cur.read_u32() as i32;
            file.cpusubtype = cur.read_u32() as i32;
            file.filetype = cur.read_u32();
            file.ncmds = cur.read_u32();
            let _sizeofcmds = cur.read_u32();
            file.flags = cur.read_u32();
            if uses64 {
                let _reserved = cur.read_u32();
            }
            let header_size = if uses64 { 32 } else { 28 };
            file.read_load_commands(&data, header_size);
            file.data = data;
        }

        // Build per-class symbol map and locate any dyld_info / chained fixups.
        file.index_class_symbols();
        file.process_dyld_info();
        file.process_chained_fixups();

        Some(file)
    }

    fn read_load_commands(&mut self, data: &[u8], header_size: usize) {
        let mut cur = Cursor::at(data, self.byte_order, self.ptr_size(), header_size);
        // Deferred parsing for symtab/dyld_info needs full data; capture offsets here.
        for _ in 0..self.ncmds {
            let cmd_start = cur.offset();
            let cmd = cur.read_u32();
            let cmdsize = cur.read_u32() as usize;
            match cmd {
                LC_SEGMENT | LC_SEGMENT_64 => {
                    self.parse_segment(data, cmd_start, cmd == LC_SEGMENT_64);
                }
                LC_SYMTAB => {
                    let symoff = cur.read_u32();
                    let nsyms = cur.read_u32();
                    let stroff = cur.read_u32();
                    let _strsize = cur.read_u32();
                    self.parse_symtab(data, symoff, nsyms, stroff);
                }
                LC_UUID => {
                    let bytes = cur.read_bytes(16);
                    let mut u = [0u8; 16];
                    u.copy_from_slice(&bytes[..16.min(bytes.len())]);
                    self.uuid = Some(u);
                }
                LC_SOURCE_VERSION => {
                    self.source_version = Some(cur.read_u64());
                }
                LC_BUILD_VERSION => {
                    let platform = cur.read_u32();
                    let minos = cur.read_u32();
                    let sdk = cur.read_u32();
                    let ntools = cur.read_u32();
                    let mut tools = Vec::new();
                    for _ in 0..ntools {
                        let tool = cur.read_u32();
                        let version = cur.read_u32();
                        tools.push((tool, version));
                    }
                    self.build_version = Some(BuildVersion { platform, minos, sdk, tools });
                }
                LC_VERSION_MIN_MACOSX => {
                    self.min_version_macosx = Some(cur.read_u32());
                }
                LC_VERSION_MIN_IPHONEOS => {
                    self.min_version_ios = Some(cur.read_u32());
                }
                LC_ID_DYLIB | LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
                | LC_LOAD_UPWARD_DYLIB => {
                    let name_off = cur.read_u32() as usize;
                    let _timestamp = cur.read_u32();
                    let current_version = cur.read_u32();
                    let compatibility_version = cur.read_u32();
                    let name = cstring_at(&data[cmd_start..cmd_start + cmdsize], name_off)
                        .unwrap_or_default();
                    let info = DylibInfo { name, current_version, compatibility_version };
                    if cmd == LC_ID_DYLIB {
                        self.dylib_id = Some(info);
                    } else {
                        self.dylibs.push(info);
                    }
                }
                LC_RPATH => {
                    let path_off = cur.read_u32() as usize;
                    if let Some(p) = cstring_at(&data[cmd_start..cmd_start + cmdsize], path_off) {
                        self.run_paths.push(p);
                    }
                }
                LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                    let _cryptoff = cur.read_u32();
                    let _cryptsize = cur.read_u32();
                    let cryptid = cur.read_u32();
                    if cryptid != 0 {
                        self.has_encryption = true;
                    }
                }
                _ => {}
            }
            cur.set_offset(cmd_start + cmdsize);
        }
    }

    fn parse_segment(&mut self, data: &[u8], cmd_start: usize, is64: bool) {
        let mut cur = Cursor::at(data, self.byte_order, self.ptr_size(), cmd_start);
        let _cmd = cur.read_u32();
        let _cmdsize = cur.read_u32();
        let name = cur.read_fixed_string(16);
        let (vmaddr, vmsize, fileoff, filesize);
        if is64 {
            vmaddr = cur.read_u64();
            vmsize = cur.read_u64();
            fileoff = cur.read_u64();
            filesize = cur.read_u64();
        } else {
            vmaddr = cur.read_u32() as u64;
            vmsize = cur.read_u32() as u64;
            fileoff = cur.read_u32() as u64;
            filesize = cur.read_u32() as u64;
        }
        let _maxprot = cur.read_u32();
        let _initprot = cur.read_u32();
        let nsects = cur.read_u32();
        let _flags = cur.read_u32();

        let mut sections = Vec::new();
        for _ in 0..nsects {
            let sectname = cur.read_fixed_string(16);
            let segname = cur.read_fixed_string(16);
            let (addr, size);
            if is64 {
                addr = cur.read_u64();
                size = cur.read_u64();
            } else {
                addr = cur.read_u32() as u64;
                size = cur.read_u32() as u64;
            }
            let offset = cur.read_u32();
            let _align = cur.read_u32();
            let _reloff = cur.read_u32();
            let _nreloc = cur.read_u32();
            let flags = cur.read_u32();
            let _reserved1 = cur.read_u32();
            let _reserved2 = cur.read_u32();
            if is64 {
                let _reserved3 = cur.read_u32();
            }
            sections.push(Section { sectname, segname, addr, size, offset, flags });
        }

        self.segments.push(Segment { name, vmaddr, vmsize, fileoff, filesize, sections });
    }

    fn parse_symtab(&mut self, data: &[u8], symoff: u32, nsyms: u32, stroff: u32) {
        let strtab = &data[stroff as usize..];
        let mut cur = Cursor::at(data, self.byte_order, self.ptr_size(), symoff as usize);
        for _ in 0..nsyms {
            let n_strx = cur.read_u32();
            let n_type = cur.read_u8();
            let n_sect = cur.read_u8();
            let n_desc = cur.read_u16();
            let value = if self.uses64 {
                cur.read_u64()
            } else {
                cur.read_u32() as u64
            };
            let name = cstring_at(strtab, n_strx as usize).unwrap_or_default();
            self.symbols.push(Symbol { name, n_type, n_sect, n_desc, value });
        }
        // CDLCSymbolTable baseAddress: vmaddr of first non-__PAGEZERO segment (the __TEXT).
        if let Some(seg) = self.segments.iter().find(|s| s.name != "__PAGEZERO") {
            self.symbol_base_address = seg.vmaddr;
        }
    }

    fn index_class_symbols(&mut self) {
        let prefix = "_OBJC_CLASS_$_";
        for sym in &self.symbols {
            if let Some(stripped) = sym.name.strip_prefix(prefix) {
                self.class_symbols
                    .entry(stripped.to_string())
                    .or_insert_with(|| sym.clone());
            }
        }
    }

    pub fn image_base(&self) -> u64 {
        self.segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .map(|s| s.vmaddr)
            .unwrap_or(0)
    }

    pub fn segment_containing_address(&self, addr: u64) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains_address(addr))
    }

    pub fn data_offset_for_address(&self, addr: u64) -> Option<u64> {
        if addr == 0 {
            return None;
        }
        let seg = self.segment_containing_address(addr)?;
        Some(seg.file_offset_for_address(addr))
    }

    pub fn string_at_address(&self, addr: u64) -> Option<String> {
        if addr == 0 {
            return None;
        }
        let off = self.data_offset_for_address(addr)? as usize;
        cstring_at(&self.data, off)
    }

    pub fn section_with_name(&self, segname: &str, sectname: &str) -> Option<&Section> {
        for seg in &self.segments {
            for sect in &seg.sections {
                if sect.segname == segname && sect.sectname == sectname {
                    return Some(sect);
                }
            }
        }
        None
    }

    pub fn segment_with_name(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == name)
    }

    pub fn has_objc2_data(&self) -> bool {
        // New ABI has a __DATA,__objc_imageinfo (or in __DATA_CONST).
        self.section_with_name("__DATA", "__objc_imageinfo").is_some()
            || self.section_with_name("__DATA_CONST", "__objc_imageinfo").is_some()
            || self.section_with_name("__DATA_DIRTY", "__objc_imageinfo").is_some()
    }

    pub fn has_objc1_data(&self) -> bool {
        self.segment_with_name("__OBJC").is_some()
    }

    /// The second word of __objc_imageinfo (flags), used for the GC status line.
    pub fn objc_image_info_flags(&self) -> Option<u32> {
        let sect = self
            .segments
            .iter()
            .flat_map(|s| s.sections.iter())
            .find(|s| s.sectname == "__objc_imageinfo")?;
        if sect.size < 8 {
            return None;
        }
        let off = sect.offset as usize;
        if off + 8 > self.data.len() {
            return None;
        }
        Some(u32::from_le_bytes([
            self.data[off + 4],
            self.data[off + 5],
            self.data[off + 6],
            self.data[off + 7],
        ]))
    }

    /// External class name for an address where a superclass pointer was bound (CDMachOFile).
    pub fn external_class_name_for_address(&self, addr: u64) -> Option<String> {
        let name = self.symbol_names_by_address.get(&addr)?;
        let prefix = "_OBJC_CLASS_$_";
        if let Some(stripped) = name.strip_prefix(prefix) {
            Some(stripped.to_string())
        } else {
            Some(name.clone())
        }
    }

    pub fn has_relocation_entry_for_address(&self, addr: u64) -> bool {
        self.symbol_names_by_address.contains_key(&addr)
    }

    pub fn class_symbol(&self, name: &str) -> Option<&Symbol> {
        self.class_symbols.get(name)
    }

    // ----- dyld_info bind parsing (LC_DYLD_INFO) -----

    fn process_dyld_info(&mut self) {
        // Find LC_DYLD_INFO(_ONLY) by re-scanning the load commands for its offsets.
        let data = std::mem::take(&mut self.data);
        let mut cur = Cursor::at(&data, self.byte_order, self.ptr_size(), if self.uses64 { 32 } else { 28 });
        let mut bind_ranges: Vec<(u32, u32)> = Vec::new();
        for _ in 0..self.ncmds {
            let cmd_start = cur.offset();
            let cmd = cur.read_u32();
            let cmdsize = cur.read_u32() as usize;
            if cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY {
                let _rebase_off = cur.read_u32();
                let _rebase_size = cur.read_u32();
                let bind_off = cur.read_u32();
                let bind_size = cur.read_u32();
                let weak_bind_off = cur.read_u32();
                let weak_bind_size = cur.read_u32();
                bind_ranges.push((bind_off, bind_size));
                bind_ranges.push((weak_bind_off, weak_bind_size));
            }
            cur.set_offset(cmd_start + cmdsize);
        }
        for (off, size) in bind_ranges {
            if size > 0 {
                self.parse_bind_ops(&data, off as usize, size as usize);
            }
        }
        self.data = data;
    }

    fn parse_bind_ops(&mut self, data: &[u8], start: usize, size: usize) {
        const BIND_OPCODE_MASK: u8 = 0xF0;
        const BIND_IMMEDIATE_MASK: u8 = 0x0F;
        const BIND_OPCODE_DONE: u8 = 0x00;
        const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
        const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
        const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
        const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
        const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
        const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
        const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
        const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
        const BIND_OPCODE_DO_BIND: u8 = 0x90;
        const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
        const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
        const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;

        let ptr_size = self.ptr_size() as u64;
        let seg0_vmaddr = self.segments.get(0).map(|s| s.vmaddr).unwrap_or(0);
        let seg_vmaddrs: Vec<u64> = self.segments.iter().map(|s| s.vmaddr).collect();

        let end = (start + size).min(data.len());
        let mut pos = start;
        let mut address = seg0_vmaddr;
        let mut symbol_name = String::new();

        let mut binds: Vec<(u64, String)> = Vec::new();
        while pos < end {
            let byte = data[pos];
            pos += 1;
            let immediate = byte & BIND_IMMEDIATE_MASK;
            let opcode = byte & BIND_OPCODE_MASK;
            match opcode {
                BIND_OPCODE_DONE => break,
                BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {}
                BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                    uleb::read_uleb128(data, &mut pos);
                }
                BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {}
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                    symbol_name = cstring_at(data, pos).unwrap_or_default();
                    pos += symbol_name.len() + 1;
                }
                BIND_OPCODE_SET_TYPE_IMM => {}
                BIND_OPCODE_SET_ADDEND_SLEB => {
                    uleb::read_sleb128(data, &mut pos);
                }
                BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    let val = uleb::read_uleb128(data, &mut pos);
                    let base = *seg_vmaddrs.get(immediate as usize).unwrap_or(&0);
                    address = base.wrapping_add(val);
                }
                BIND_OPCODE_ADD_ADDR_ULEB => {
                    let val = uleb::read_uleb128(data, &mut pos);
                    address = address.wrapping_add(val);
                }
                BIND_OPCODE_DO_BIND => {
                    binds.push((address, symbol_name.clone()));
                    address = address.wrapping_add(ptr_size);
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                    let val = uleb::read_uleb128(data, &mut pos);
                    binds.push((address, symbol_name.clone()));
                    address = address.wrapping_add(ptr_size).wrapping_add(val);
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                    binds.push((address, symbol_name.clone()));
                    address = address
                        .wrapping_add(ptr_size)
                        .wrapping_add(immediate as u64 * ptr_size);
                }
                BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                    let count = uleb::read_uleb128(data, &mut pos);
                    let skip = uleb::read_uleb128(data, &mut pos);
                    for _ in 0..count {
                        binds.push((address, symbol_name.clone()));
                        address = address.wrapping_add(ptr_size).wrapping_add(skip);
                    }
                }
                _ => break,
            }
        }
        for (addr, name) in binds {
            self.symbol_names_by_address.insert(addr, name);
        }
    }

    // ----- dyld chained fixups (LC_DYLD_CHAINED_FIXUPS) -----

    fn process_chained_fixups(&mut self) {
        // Locate the chained fixups linkedit blob.
        let data = std::mem::take(&mut self.data);
        let mut fixup_off = 0u32;
        let mut fixup_size = 0u32;
        {
            let mut cur = Cursor::at(&data, self.byte_order, self.ptr_size(), if self.uses64 { 32 } else { 28 });
            for _ in 0..self.ncmds {
                let cmd_start = cur.offset();
                let cmd = cur.read_u32();
                let cmdsize = cur.read_u32() as usize;
                if cmd == LC_DYLD_CHAINED_FIXUPS {
                    fixup_off = cur.read_u32();
                    fixup_size = cur.read_u32();
                }
                cur.set_offset(cmd_start + cmdsize);
            }
        }
        if fixup_size == 0 {
            self.data = data;
            return;
        }

        let mut data = data; // take ownership, patch below
        self.walk_chained_fixups(&mut data, fixup_off as usize);
        self.data = data;
    }

    fn walk_chained_fixups(&mut self, file_bytes: &mut Vec<u8>, header_off: usize) {
        // The chain_data blob is at header_off. All offsets in the blob are relative to header_off.
        let blob_base = header_off;
        let rd_u32 = |bytes: &[u8], off: usize| -> u32 {
            u32::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ])
        };

        if blob_base + 28 > file_bytes.len() {
            return;
        }
        let starts_offset = rd_u32(file_bytes, blob_base + 4);
        let imports_offset = rd_u32(file_bytes, blob_base + 8);
        let symbols_offset = rd_u32(file_bytes, blob_base + 12);
        let imports_count = rd_u32(file_bytes, blob_base + 16);
        let imports_format = rd_u32(file_bytes, blob_base + 20);

        let image_base = self.image_base();

        // Build import symbol-name table.
        let mut import_names: Vec<String> = Vec::with_capacity(imports_count as usize);
        {
            let symbol_pool = blob_base + symbols_offset as usize;
            let imports = blob_base + imports_offset as usize;
            for i in 0..imports_count as usize {
                let name_offset = match imports_format {
                    DYLD_CHAINED_IMPORT => {
                        let e = rd_u32(file_bytes, imports + i * 4);
                        e >> 9
                    }
                    DYLD_CHAINED_IMPORT_ADDEND => {
                        let e = rd_u32(file_bytes, imports + i * 8);
                        e >> 9
                    }
                    DYLD_CHAINED_IMPORT_ADDEND64 => {
                        // 64-bit: lib_ordinal:16, weak:1, reserved:15, name_offset:32
                        let lo = rd_u32(file_bytes, imports + i * 16);
                        let _ = lo;
                        rd_u32(file_bytes, imports + i * 16 + 4)
                    }
                    _ => 0,
                };
                let name = cstring_at(file_bytes, symbol_pool + name_offset as usize)
                    .unwrap_or_default();
                import_names.push(name);
            }
        }

        // Walk starts_in_image.
        let sii = blob_base + starts_offset as usize;
        if sii + 4 > file_bytes.len() {
            return;
        }
        let seg_count = rd_u32(file_bytes, sii);
        let mut symbol_binds: Vec<(u64, String)> = Vec::new();

        for seg_index in 0..seg_count as usize {
            let seg_info_offset = rd_u32(file_bytes, sii + 4 + seg_index * 4);
            if seg_info_offset == 0 {
                continue;
            }
            let seg_info = sii + seg_info_offset as usize;
            // dyld_chained_starts_in_segment
            let page_size = u16::from_le_bytes([file_bytes[seg_info + 4], file_bytes[seg_info + 5]]);
            let pointer_format =
                u16::from_le_bytes([file_bytes[seg_info + 6], file_bytes[seg_info + 7]]);
            let segment_offset = u64::from_le_bytes([
                file_bytes[seg_info + 8],
                file_bytes[seg_info + 9],
                file_bytes[seg_info + 10],
                file_bytes[seg_info + 11],
                file_bytes[seg_info + 12],
                file_bytes[seg_info + 13],
                file_bytes[seg_info + 14],
                file_bytes[seg_info + 15],
            ]);
            let page_count =
                u16::from_le_bytes([file_bytes[seg_info + 20], file_bytes[seg_info + 21]]);

            let is_arm64e = matches!(
                pointer_format,
                DYLD_CHAINED_PTR_ARM64E
                    | DYLD_CHAINED_PTR_ARM64E_KERNEL
                    | DYLD_CHAINED_PTR_ARM64E_USERLAND
                    | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
                    | DYLD_CHAINED_PTR_ARM64E_USERLAND24
            );
            let stride: u64 = match pointer_format {
                DYLD_CHAINED_PTR_ARM64E
                | DYLD_CHAINED_PTR_ARM64E_USERLAND
                | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => 8,
                _ => 4,
            };
            if pointer_format != DYLD_CHAINED_PTR_64
                && pointer_format != DYLD_CHAINED_PTR_64_OFFSET
                && !is_arm64e
            {
                eprintln!(
                    "Warning: Unsupported dyld chained pointer format {}; skipping segment.",
                    pointer_format
                );
                continue;
            }

            for page_index in 0..page_count as usize {
                let ps_off = seg_info + 22 + page_index * 2;
                let start_offset =
                    u16::from_le_bytes([file_bytes[ps_off], file_bytes[ps_off + 1]]);
                if start_offset == DYLD_CHAINED_PTR_START_NONE {
                    continue;
                }
                if start_offset & DYLD_CHAINED_PTR_START_MULTI != 0 {
                    continue;
                }
                let mut chain_addr = image_base
                    + segment_offset
                    + (page_index as u64) * (page_size as u64)
                    + start_offset as u64;
                loop {
                    let file_off = match self.data_offset_for_address(chain_addr) {
                        Some(o) => o as usize,
                        None => break,
                    };
                    if file_off + 8 > file_bytes.len() {
                        break;
                    }
                    let raw = u64::from_le_bytes([
                        file_bytes[file_off],
                        file_bytes[file_off + 1],
                        file_bytes[file_off + 2],
                        file_bytes[file_off + 3],
                        file_bytes[file_off + 4],
                        file_bytes[file_off + 5],
                        file_bytes[file_off + 6],
                        file_bytes[file_off + 7],
                    ]);

                    let next;
                    let mut new_value = 0u64;
                    if is_arm64e {
                        let is_bind = (raw >> 62) & 0x1 != 0;
                        let is_auth = (raw >> 63) & 0x1 != 0;
                        next = (raw >> 51) & 0x7ff;
                        if is_bind {
                            let ordinal = if pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24 {
                                raw & 0xffffff
                            } else {
                                raw & 0xffff
                            };
                            if let Some(n) = import_names.get(ordinal as usize) {
                                symbol_binds.push((chain_addr, n.clone()));
                            }
                            new_value = 0;
                        } else if is_auth {
                            let target = raw & 0xffffffff;
                            new_value = image_base + target;
                        } else {
                            let target = raw & 0x7ffffffffff;
                            new_value = if pointer_format == DYLD_CHAINED_PTR_ARM64E {
                                target
                            } else {
                                image_base + target
                            };
                        }
                    } else {
                        let is_bind = (raw >> 63) & 0x1 != 0;
                        next = (raw >> 51) & 0xfff;
                        if is_bind {
                            let ordinal = raw & 0xffffff;
                            if let Some(n) = import_names.get(ordinal as usize) {
                                symbol_binds.push((chain_addr, n.clone()));
                            }
                            new_value = 0;
                        } else {
                            let target = raw & 0xfffffffff;
                            new_value = if pointer_format == DYLD_CHAINED_PTR_64 {
                                target
                            } else {
                                image_base + target
                            };
                        }
                    }

                    file_bytes[file_off..file_off + 8].copy_from_slice(&new_value.to_le_bytes());

                    if next == 0 {
                        break;
                    }
                    chain_addr += next * stride;
                }
            }
        }

        for (addr, name) in symbol_binds {
            self.symbol_names_by_address.insert(addr, name);
        }
    }
}
