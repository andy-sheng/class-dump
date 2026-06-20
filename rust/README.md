# class-dump (Rust port)

A from-scratch, cross-platform Rust reimplementation of class-dump, translated
faithfully from the Objective-C source so its output matches byte-for-byte.

Unlike the original (which links Foundation and the Objective-C runtime and only
builds on macOS), this port has no platform dependencies — it just parses Mach-O
bytes — so it builds and runs on macOS, Linux and Windows.

## Fidelity

Validated against the original class-dump 3.5.1 on real apps:

- **WeChat.app** (arm64, chained fixups, ~1.26M lines of output): every one of
  46,866 `@interface`/`@protocol` blocks is byte-for-byte identical; the entire
  dump matches except 2 lines.
- **Grace.app** (arm64, LC_DYLD_INFO): 15,467 / 15,472 blocks identical.

The handful of residual differences are all caused by the *original* tool's
hash-order-dependent structure merging (the canonical member names / kept
protocol qualifier for a structure shared by multiple definitions depend on
`NSDictionary` enumeration order, which is not reproducible). This port instead
produces deterministic output.

## What's implemented

- Mach-O container: header, load commands, segments/sections, symbol table.
- Pointer resolution: `LC_DYLD_INFO` bind opcodes + `LC_DYLD_CHAINED_FIXUPS`.
- ObjC2 metadata: classes, categories, protocols (`__objc_protolist` + uniquing
  with method/property merge), methods (incl. relative method lists and shared
  extended method types), ivars, properties.
- Full CDType type system: parser/lexer (incl. C++ template tag names, blocks
  with signatures, char→BOOL, MISSING_TYPE, parse-failure replication), the
  4-phase CDTypeController/CDStructureTable structure pipeline with
  CDStruct_/CDUnion_ typedef naming (SHA1-based), expand-vs-reference decisions,
  and the named/typedef/exception structure sections.
- Output: header + per-file comment block (UUID, versions, GC, run paths),
  declarations with property/accessor folding, and the structure sections.

## Not yet implemented

- Fat (universal) binaries and 32-bit / ObjC1 (`__OBJC`) images.
- CLI options: `-H`/`-o` (headers to files), `--arch`, `-s`/`-S` sorting, etc.
  (Currently dumps a single thin image to stdout, like `class-dump <file>`.)

## Build & run

```
cargo build --release
./target/release/class-dump <mach-o-file>
```
