//! Mach-O constants, vendored so the parser builds on any host OS.
//! Values from <mach-o/loader.h>, <mach-o/fat.h>, <mach/machine.h>.

pub const MH_MAGIC: u32 = 0xfeed_face;
pub const MH_CIGAM: u32 = 0xcefa_edfe;
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;

pub const FAT_MAGIC: u32 = 0xcafe_babe;
pub const FAT_CIGAM: u32 = 0xbeba_feca;
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;
pub const FAT_CIGAM_64: u32 = 0xbfba_feca;

// File types
pub const MH_OBJECT: u32 = 0x1;
pub const MH_EXECUTE: u32 = 0x2;
pub const MH_DYLIB: u32 = 0x6;
pub const MH_DYLINKER: u32 = 0x7;
pub const MH_BUNDLE: u32 = 0x8;

// Header flags
pub const MH_NOUNDEFS: u32 = 0x1;

// Load commands
pub const LC_REQ_DYLD: u32 = 0x8000_0000;
pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1b;
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2a;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;

// CPU types
pub const CPU_ARCH_ABI64: i32 = 0x0100_0000;
pub const CPU_TYPE_X86: i32 = 7;
pub const CPU_TYPE_X86_64: i32 = 7 | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM: i32 = 12;
pub const CPU_TYPE_ARM64: i32 = 12 | CPU_ARCH_ABI64;
pub const CPU_TYPE_POWERPC: i32 = 18;
pub const CPU_TYPE_POWERPC64: i32 = 18 | CPU_ARCH_ABI64;

pub const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
pub const CPU_ARCH_MASK: u32 = 0xff00_0000;

// arm64 subtypes
pub const CPU_SUBTYPE_ARM64_ALL: i32 = 0;
pub const CPU_SUBTYPE_ARM64E: i32 = 2;

// Section flags / types
pub const SECTION_TYPE: u32 = 0x0000_00ff;
pub const S_ZEROFILL: u32 = 0x1;

// build_version platforms
pub const PLATFORM_MACOS: u32 = 1;
pub const PLATFORM_IOS: u32 = 2;
pub const PLATFORM_TVOS: u32 = 3;
pub const PLATFORM_WATCHOS: u32 = 4;
pub const PLATFORM_BRIDGEOS: u32 = 5;
pub const PLATFORM_MACCATALYST: u32 = 6;
pub const PLATFORM_IOSSIMULATOR: u32 = 7;
pub const PLATFORM_TVOSSIMULATOR: u32 = 8;
pub const PLATFORM_WATCHOSSIMULATOR: u32 = 9;

// build tools
pub const TOOL_CLANG: u32 = 1;
pub const TOOL_SWIFT: u32 = 2;
pub const TOOL_LD: u32 = 3;

// nlist (symbol table)
pub const N_STAB: u8 = 0xe0;
pub const N_TYPE: u8 = 0x0e;
pub const N_EXT: u8 = 0x01;
pub const N_SECT: u8 = 0xe;

// dyld chained fixups
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
pub const DYLD_CHAINED_PTR_64: u16 = 2;
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;

pub const DYLD_CHAINED_IMPORT: u32 = 1;
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;
