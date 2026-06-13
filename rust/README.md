# class-dump (Rust port)

A from-scratch, cross-platform Rust reimplementation of class-dump, translated
faithfully from the Objective-C source so its output matches byte-for-byte.

Unlike the original (which links Foundation and the Objective-C runtime and only
builds on macOS), this port has no platform dependencies — it just parses Mach-O
bytes — so it builds and runs on macOS, Linux and Windows.

## Status

Validated against the original class-dump 3.5.1 on real apps (Grace, WeChat):

- **Mach-O container**: header, load commands, segments/sections, symbol table,
  fat detection — done.
- **Pointer resolution**: classic `LC_DYLD_INFO` binds + `LC_DYLD_CHAINED_FIXUPS`
  (rebases patched in place, binds recorded) — done.
- **ObjC2 metadata**: classes, categories, protocols (incl. `__objc_protolist`),
  methods (incl. relative/small method lists and shared extended method types),
  ivars, properties — done. Class/protocol counts match exactly
  (WeChat: 39958 classes, 6913 protocols).
- **Output**: `@interface`/`@protocol`/`@interface(Category)` bodies, property
  synthesis/accessor folding, `@optional`, "Remaining properties",
  hidden-visibility attribute — common cases are byte-for-byte identical
  (e.g. `MMUIViewController` matches exactly).

## Remaining work (well-scoped)

- Struct/union **typedef table** (`CDStruct_<hash>` naming + the "Named/Typedef'd
  Structures/Unions" sections); currently anonymous structs are expanded inline.
- Block signature decoding (`void (^)(_Bool)`).
- Header + per-file comment block (UUID, versions, GC line).
- CLI options: `-H`/`-o`, `--arch`, `-s`/`-S` sorting, fat binaries, ObjC1 (32-bit).

## Build & run

```
cargo build --release
./target/release/class-dump <mach-o-file>
```
