//! Text output, mirroring CDClassDumpVisitor + CDTextClassDumpVisitor and the
//! CDOCClass/Protocol/Category visiting order, using the type controller for all
//! type formatting (struct typedefs, sections, etc.).

use crate::macho::{consts::*, MachOFile};
use crate::objc::{Category, Class, Method, ObjcImage, Property, Protocol};
use crate::typ::{self, CDType, FormatterCfg};
use crate::typecontroller::TypeController;
use std::collections::HashMap;

pub struct Options {
    pub sort_methods: bool,
}

fn ivar_cfg() -> FormatterCfg {
    FormatterCfg { should_expand: false, should_auto_expand: true, base_level: 1, is_struct_decl: false }
}
fn plain_cfg() -> FormatterCfg {
    FormatterCfg { should_expand: false, should_auto_expand: false, base_level: 0, is_struct_decl: false }
}

fn parse_one(s: &str) -> CDType {
    typ::Parser::new(s).parse_type()
}

// ----- property attribute parsing -----

struct PropInfo {
    type_encoding: String,
    alist: Vec<String>,
    unknown_attrs: Vec<String>,
    attr_string_after_type: String,
    readonly: bool,
    dynamic: bool,
    weak: bool,
    getter: String,
    setter: String,
    backing_var: Option<String>,
}

fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn split_type_and_rest(s: &str) -> (String, String) {
    // s is the attribute string after the leading 'T'
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_quote = false;
    let mut end = bytes.len();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b'{' | b'(' | b'[' if !in_quote => depth += 1,
            b'}' | b')' | b']' if !in_quote => depth -= 1,
            b',' if !in_quote && depth == 0 => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    let ty = s[..end].to_string();
    let rest = if end < s.len() { s[end + 1..].to_string() } else { String::new() };
    (ty, rest)
}

fn parse_property(p: &Property) -> PropInfo {
    let mut info = PropInfo {
        type_encoding: String::new(),
        alist: Vec::new(),
        unknown_attrs: Vec::new(),
        attr_string_after_type: String::new(),
        readonly: false,
        dynamic: false,
        weak: false,
        getter: p.name.clone(),
        setter: format!("set{}:", capitalize_first(&p.name)),
        backing_var: None,
    };
    let rest;
    if let Some(stripped) = p.attributes.strip_prefix('T') {
        let (ty, r) = split_type_and_rest(stripped);
        info.type_encoding = ty;
        info.attr_string_after_type = r.clone();
        rest = r;
    } else {
        rest = String::new();
    }
    if !rest.is_empty() {
        for attr in rest.split(',') {
            let first = attr.chars().next().unwrap_or(' ');
            let tail = &attr[attr.char_indices().nth(1).map(|(i, _)| i).unwrap_or(attr.len())..];
            match first {
                'R' => {
                    info.readonly = true;
                    info.alist.push("readonly".to_string());
                }
                'C' => info.alist.push("copy".to_string()),
                '&' => info.alist.push("retain".to_string()),
                'G' => {
                    info.getter = tail.to_string();
                    info.alist.push(format!("getter={}", tail));
                }
                'S' => {
                    info.setter = tail.to_string();
                    info.alist.push(format!("setter={}", tail));
                }
                'V' => info.backing_var = Some(tail.to_string()),
                'N' => info.alist.push("nonatomic".to_string()),
                'W' => info.weak = true,
                'P' => info.weak = false,
                'D' => info.dynamic = true,
                _ => info.unknown_attrs.push(attr.to_string()),
            }
        }
    }
    info
}

fn format_property(tc: &TypeController, p: &Property) -> String {
    let info = parse_property(p);
    let mut s = String::new();
    if !info.alist.is_empty() {
        s.push_str(&format!("@property({}) ", info.alist.join(", ")));
    } else {
        s.push_str("@property ");
    }
    if info.weak {
        s.push_str("__weak ");
    }
    let ty = parse_one(&info.type_encoding);
    s.push_str(&tc.format_variable(Some(&p.name), &ty, &plain_cfg()));
    s.push(';');
    if info.dynamic {
        s.push_str(&format!(" // @dynamic {};", p.name));
    } else if let Some(bv) = &info.backing_var {
        if *bv == p.name {
            s.push_str(&format!(" // @synthesize {};", p.name));
        } else {
            s.push_str(&format!(" // @synthesize {}={};", p.name, bv));
        }
    }
    s.push('\n');
    if !info.unknown_attrs.is_empty() {
        s.push_str(&format!(
            "// Preceding property had unknown attributes: {}\n",
            info.unknown_attrs.join(",")
        ));
        if p.attributes.len() > 80 {
            s.push_str(&format!(
                "// Original attribute string (following type): {}\n\n",
                info.attr_string_after_type
            ));
        } else {
            s.push_str(&format!("// Original attribute string: {}\n\n", p.attributes));
        }
    }
    s
}

// ----- method formatting (port of formatMethodName) -----

fn format_method(tc: &TypeController, selector: &str, type_string: &str) -> Option<String> {
    let types = typ::parse_method_types(type_string)?;
    if types.is_empty() {
        return Some(format!("({})", selector));
    }
    let cfg = plain_cfg();
    let ret = tc.format_type_no_merge(&types[0], &cfg);
    let mut result = format!("({})", ret);

    let count = types.len();
    let mut index = 3usize;
    let bytes = selector.as_bytes();
    let mut i = 0usize;
    let mut no_more = false;
    while i < bytes.len() {
        // scan up to ':'
        let start = i;
        while i < bytes.len() && bytes[i] != b':' {
            i += 1;
        }
        result.push_str(&selector[start..i]);
        if i < bytes.len() && bytes[i] == b':' {
            result.push(':');
            i += 1;
            if index >= count {
                no_more = true;
            } else {
                let argtype = tc.format_type_no_merge(&types[index], &cfg);
                result.push_str(&format!("({})arg{}", argtype, index - 2));
                if i < bytes.len() && bytes[i] != b':' {
                    result.push(' ');
                }
                index += 1;
            }
        }
    }
    if no_more {
        result.push_str(" /* Error: Ran out of types for this method. */");
    }
    Some(result)
}

/// Emit one method line with the given prefix ('+' or '-'), or the parse-error comment.
fn emit_method(tc: &TypeController, out: &mut String, prefix: char, m: &Method) {
    out.push(prefix);
    out.push(' ');
    match format_method(tc, &m.name, &m.type_string) {
        Some(body) => {
            out.push_str(&body);
            out.push_str(";\n");
        }
        None => {
            out.push_str(&format!(
                "    // Error parsing type: {}, name: {}\n",
                m.type_string, m.name
            ));
        }
    }
}

// ----- property state (uniqued by name) -----

struct PropertyState {
    by_name: HashMap<String, Property>,
    by_accessor: HashMap<String, String>,
}

impl PropertyState {
    fn new(properties: &[Property]) -> Self {
        let mut by_name = HashMap::new();
        let mut by_accessor = HashMap::new();
        for p in properties {
            let info = parse_property(p);
            by_name.insert(p.name.clone(), p.clone());
            by_accessor.insert(info.getter.clone(), p.name.clone());
            if !info.readonly {
                by_accessor.insert(info.setter.clone(), p.name.clone());
            }
        }
        PropertyState { by_name, by_accessor }
    }
    fn take_for_accessor(&mut self, selector: &str) -> Option<Property> {
        let name = self.by_accessor.get(selector).cloned()?;
        self.by_name.remove(&name)
    }
    fn is_accessor(&self, selector: &str) -> bool {
        self.by_accessor.contains_key(selector)
    }
    fn remaining_sorted(&self) -> Vec<Property> {
        let mut v: Vec<Property> = self.by_name.values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }
}

fn visit_methods(
    tc: &TypeController,
    out: &mut String,
    class_methods: &[Method],
    instance_methods: &[Method],
    optional_class: &[Method],
    optional_instance: &[Method],
    properties: &[Property],
    opts: &Options,
) {
    let mut state = PropertyState::new(properties);
    let sorted = |ms: &[Method]| -> Vec<Method> {
        let mut v: Vec<Method> = ms.to_vec();
        if opts.sort_methods {
            v.sort_by(|a, b| a.name.cmp(&b.name));
        }
        v
    };
    let emit_instance = |out: &mut String, state: &mut PropertyState, m: &Method| {
        if state.is_accessor(&m.name) {
            if let Some(p) = state.take_for_accessor(&m.name) {
                out.push_str(&format_property(tc, &p));
            }
        } else {
            emit_method(tc, out, '-', m);
        }
    };

    for m in sorted(class_methods) {
        emit_method(tc, out, '+', &m);
    }
    for m in sorted(instance_methods) {
        emit_instance(out, &mut state, &m);
    }
    if !optional_class.is_empty() || !optional_instance.is_empty() {
        out.push_str("\n@optional\n");
        for m in sorted(optional_class) {
            emit_method(tc, out, '+', &m);
        }
        for m in sorted(optional_instance) {
            emit_instance(out, &mut state, &m);
        }
    }
    let remaining = state.remaining_sorted();
    if !remaining.is_empty() {
        out.push('\n');
        out.push_str("// Remaining properties\n");
        for p in remaining {
            out.push_str(&format_property(tc, &p));
        }
    }
}

fn has_methods(c: &Class) -> bool {
    !c.class_methods.is_empty() || !c.instance_methods.is_empty()
}

fn visit_class(tc: &TypeController, out: &mut String, c: &Class, opts: &Options) {
    if !c.is_exported {
        out.push_str("__attribute__((visibility(\"hidden\")))\n");
    }
    out.push_str(&format!("@interface {}", c.name));
    if let Some(sc) = &c.superclass_name {
        out.push_str(&format!(" : {}", sc));
    }
    if !c.protocols.is_empty() {
        out.push_str(&format!(" <{}>", c.protocols.join(", ")));
    }
    out.push('\n');

    out.push_str("{\n");
    for iv in &c.ivars {
        let ty = parse_one(&iv.type_string);
        out.push_str(&tc.format_variable(Some(&iv.name), &ty, &ivar_cfg()));
        out.push_str(";\n");
    }
    out.push_str("}\n\n");

    visit_methods(tc, out, &c.class_methods, &c.instance_methods, &[], &[], &c.properties, opts);

    if has_methods(c) {
        out.push('\n');
    }
    out.push_str("@end\n\n");
}

fn visit_protocol(tc: &TypeController, out: &mut String, p: &Protocol, opts: &Options) {
    out.push_str(&format!("@protocol {}", p.name));
    if !p.adopted_protocols.is_empty() {
        out.push_str(&format!(" <{}>", p.adopted_protocols.join(", ")));
    }
    out.push('\n');
    visit_methods(
        tc,
        out,
        &p.class_methods,
        &p.instance_methods,
        &p.optional_class_methods,
        &p.optional_instance_methods,
        &p.properties,
        opts,
    );
    out.push_str("@end\n\n");
}

fn visit_category(tc: &TypeController, out: &mut String, c: &Category, opts: &Options) {
    out.push_str(&format!("@interface {} ({})", c.class_name, c.name));
    if !c.protocols.is_empty() {
        out.push_str(&format!(" <{}>", c.protocols.join(", ")));
    }
    out.push('\n');
    visit_methods(tc, out, &c.class_methods, &c.instance_methods, &[], &[], &c.properties, opts);
    out.push_str("@end\n\n");
}

// ----- type registration (phase 0) -----

fn register_methods(tc: &mut TypeController, methods: &[Method]) {
    for m in methods {
        if let Some(types) = typ::parse_method_types(&m.type_string) {
            for t in types {
                tc.register_type(&t, true);
            }
        }
    }
}

fn register_all_types(tc: &mut TypeController, image: &ObjcImage) {
    for c in &image.classes {
        for iv in &c.ivars {
            tc.register_type(&parse_one(&iv.type_string), false);
        }
        register_methods(tc, &c.class_methods);
        register_methods(tc, &c.instance_methods);
    }
    for cat in &image.categories {
        register_methods(tc, &cat.class_methods);
        register_methods(tc, &cat.instance_methods);
    }
    for p in &image.protocols {
        register_methods(tc, &p.class_methods);
        register_methods(tc, &p.instance_methods);
        register_methods(tc, &p.optional_class_methods);
        register_methods(tc, &p.optional_instance_methods);
    }
}

// ----- header / file comment block -----

fn nibble_version(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

fn source_version_string(v: u64) -> String {
    let a = v >> 40;
    let b = (v >> 30) & 0x3ff;
    let c = (v >> 20) & 0x3ff;
    let d = (v >> 10) & 0x3ff;
    let e = v & 0x3ff;
    format!("{}.{}.{}.{}.{}", a, b, c, d, e)
}

fn platform_name(platform: u32) -> String {
    match platform {
        PLATFORM_MACOS => "macOS".to_string(),
        PLATFORM_IOS => "iOS".to_string(),
        PLATFORM_TVOS => "tvOS".to_string(),
        PLATFORM_WATCHOS => "watchOS".to_string(),
        PLATFORM_BRIDGEOS => "bridgeOS".to_string(),
        PLATFORM_MACCATALYST => "Mac Catalyst".to_string(),
        PLATFORM_IOSSIMULATOR => "iOS Simulator".to_string(),
        PLATFORM_TVOSSIMULATOR => "tvOS Simulator".to_string(),
        PLATFORM_WATCHOSSIMULATOR => "watchOS Simulator".to_string(),
        _ => format!("Unknown platform {:x}", platform),
    }
}

fn tool_name(tool: u32) -> String {
    match tool {
        TOOL_CLANG => "clang".to_string(),
        TOOL_SWIFT => "swift".to_string(),
        TOOL_LD => "ld".to_string(),
        _ => format!("Unknown tool {:x}", tool),
    }
}

fn cpu_name(cputype: i32, cpusubtype: i32) -> String {
    let masked = cpusubtype & !(CPU_SUBTYPE_MASK as i32);
    match cputype {
        CPU_TYPE_X86_64 => "x86_64".to_string(),
        CPU_TYPE_X86 => "i386".to_string(),
        CPU_TYPE_ARM64 => {
            if masked == CPU_SUBTYPE_ARM64E {
                "arm64e".to_string()
            } else {
                "arm64".to_string()
            }
        }
        CPU_TYPE_ARM => "arm".to_string(),
        CPU_TYPE_POWERPC64 => "ppc64".to_string(),
        CPU_TYPE_POWERPC => "ppc".to_string(),
        _ => format!("0x{:x}:0x{:x}", cputype, cpusubtype),
    }
}

fn uuid_string(u: &[u8; 16]) -> String {
    let h: Vec<String> = u.iter().map(|b| format!("{:02X}", b)).collect();
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13],
        h[14], h[15]
    )
}

fn resolve_run_path(path: &str, filename: &str) -> String {
    let dir = match filename.rfind('/') {
        Some(i) => &filename[..i],
        None => ".",
    };
    if let Some(rest) = path.strip_prefix("@executable_path") {
        format!("{}{}", dir, rest)
    } else if let Some(rest) = path.strip_prefix("@loader_path") {
        format!("{}{}", dir, rest)
    } else {
        path.to_string()
    }
}

fn file_comment_block(macho: &MachOFile) -> String {
    let mut s = String::new();
    s.push_str("#pragma mark -\n\n");
    s.push_str("//\n");
    s.push_str(&format!("// File: {}\n", macho.filename));
    if let Some(u) = &macho.uuid {
        s.push_str(&format!("// UUID: {}\n", uuid_string(u)));
    }
    s.push_str("//\n");
    s.push_str(&format!(
        "//                           Arch: {}\n",
        cpu_name(macho.cputype, macho.cpusubtype)
    ));
    if macho.filetype == MH_DYLIB {
        if let Some(id) = &macho.dylib_id {
            s.push_str(&format!(
                "//                Current version: {}\n",
                nibble_version(id.current_version)
            ));
            s.push_str(&format!(
                "//          Compatibility version: {}\n",
                nibble_version(id.compatibility_version)
            ));
        }
    }
    if let Some(sv) = macho.source_version {
        s.push_str(&format!("//                 Source version: {}\n", source_version_string(sv)));
    }
    if let Some(bv) = &macho.build_version {
        s.push_str(&format!(
            "//                  Build version: Platform: {} {}, SDK: {}\n",
            platform_name(bv.platform),
            nibble_version(bv.minos),
            nibble_version(bv.sdk)
        ));
        let tools: Vec<String> = bv
            .tools
            .iter()
            .map(|(t, v)| format!("{} {}", tool_name(*t), nibble_version(*v)))
            .collect();
        s.push_str(&format!(
            "//                          Tools: {}\n",
            tools.join("\n                                   ")
        ));
    }
    // GC status
    if macho.has_objc2_data() || macho.has_objc1_data() {
        let gc = match macho.objc_image_info_flags() {
            None => Some("Unknown".to_string()),
            Some(v) => match v & 0x06 {
                0 => Some("Unsupported".to_string()),
                2 => Some("Supported".to_string()),
                6 => Some("Required".to_string()),
                other => Some(format!("Unknown (0x{:08x})", other)),
            },
        };
        if let Some(gc) = gc {
            s.push_str("//\n");
            s.push_str(&format!("// Objective-C Garbage Collection: {}\n", gc));
        }
    }
    if !macho.run_paths.is_empty() {
        s.push_str("//\n");
        for rp in &macho.run_paths {
            s.push_str(&format!("//                       Run path: {}\n", rp));
            s.push_str(&format!(
                "//                               = {}\n",
                resolve_run_path(rp, &macho.filename)
            ));
        }
    }
    if macho.has_encryption {
        s.push_str("//         This file is encrypted:\n");
    }
    s.push_str("//\n");
    s
}

pub fn dump(macho: &MachOFile, image: &ObjcImage, opts: &Options) -> String {
    let mut tc = TypeController::new();
    register_all_types(&mut tc, image);
    tc.work_some_magic();

    let mut out = String::new();
    out.push_str("//\n");
    out.push_str("//     Generated by class-dump 3.5.1 (64 bit).\n");
    out.push_str("//\n");
    out.push_str("//  Copyright (C) 1997-2019 Steve Nygard.\n");
    out.push_str("//\n\n");

    if macho.has_objc2_data() || macho.has_objc1_data() {
        tc.append_structures(&mut out);
    }

    out.push_str(&file_comment_block(macho));
    out.push('\n');

    // Protocols (uniqued by name, sorted).
    let mut protocols: Vec<&Protocol> = image.protocols.iter().collect();
    protocols.sort_by(|a, b| a.name.cmp(&b.name));
    let mut seen = std::collections::HashSet::new();
    protocols.retain(|p| seen.insert(p.name.clone()));
    for p in protocols {
        visit_protocol(&tc, &mut out, p, opts);
    }

    // Classes, sorted by name.
    let mut classes: Vec<&Class> = image.classes.iter().collect();
    classes.sort_by(|a, b| a.name.cmp(&b.name));
    for c in classes {
        visit_class(&tc, &mut out, c, opts);
    }

    // Categories, sorted by class name.
    let mut categories: Vec<&Category> = image.categories.iter().collect();
    categories.sort_by(|a, b| a.class_name.cmp(&b.class_name));
    for c in categories {
        visit_category(&tc, &mut out, c, opts);
    }

    out
}
