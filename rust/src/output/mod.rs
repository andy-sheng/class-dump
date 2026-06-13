//! Text output, mirroring CDTextClassDumpVisitor + CDOCClass/Protocol/Category visiting order.

use crate::macho::MachOFile;
use crate::objc::{Category, Class, Method, ObjcImage, Property, Protocol};
use crate::typ;
use std::collections::HashMap;

pub struct Options {
    pub sort_by_name: bool,
    pub sort_methods: bool,
}

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

fn parse_property(p: &Property) -> PropInfo {
    // Attribute string: T<type>,attr,attr,...
    let s = &p.attributes;
    let mut type_encoding = String::new();
    let mut rest: Vec<String> = Vec::new();
    if let Some(stripped) = s.strip_prefix('T') {
        // The type runs until the first top-level comma. Type encodings can contain commas only
        // inside quotes/braces; for property type encodings a simple scan to the first comma that
        // is not inside {}/()/"" suffices.
        let bytes = stripped.as_bytes();
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
        type_encoding = stripped[..end].to_string();
        if end < stripped.len() {
            let after = &stripped[end + 1..];
            if !after.is_empty() {
                rest = after.split(',').map(|x| x.to_string()).collect();
            }
        }
    }
    let after_type = if let Some(stripped) = s.strip_prefix('T') {
        let bytes = stripped.as_bytes();
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
        if end < stripped.len() {
            stripped[end + 1..].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let mut info = PropInfo {
        type_encoding,
        alist: Vec::new(),
        unknown_attrs: Vec::new(),
        attr_string_after_type: after_type,
        readonly: false,
        dynamic: false,
        weak: false,
        getter: p.name.clone(),
        setter: format!("set{}:", capitalize_first(&p.name)),
        backing_var: None,
    };

    for attr in &rest {
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
            _ => info.unknown_attrs.push(attr.clone()),
        }
    }
    info
}

fn format_property(p: &Property) -> String {
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
    let mut parser = typ::Parser::new(&info.type_encoding);
    let ty = parser.parse_type();
    let formatted = typ::format(&ty, &p.name);
    s.push_str(&formatted);
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

fn format_method(prefix: char, m: &Method) -> String {
    typ::format_method(prefix, &m.name, &m.type_string)
}

fn protocols_string(protocols: &[String]) -> String {
    protocols.join(", ")
}

/// Mirror of CDVisitorPropertyState: properties uniqued by name, plus an accessor->name map.
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

    /// If `selector` is an accessor for a not-yet-emitted property, return and consume it.
    fn take_for_accessor(&mut self, selector: &str) -> Option<Property> {
        if let Some(name) = self.by_accessor.get(selector).cloned() {
            return self.by_name.remove(&name);
        }
        None
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
                out.push_str(&format_property(&p));
            }
        } else {
            out.push_str(&format_method('-', m));
            out.push_str(";\n");
        }
    };

    for m in sorted(class_methods) {
        out.push_str(&format_method('+', &m));
        out.push_str(";\n");
    }
    for m in sorted(instance_methods) {
        emit_instance(out, &mut state, &m);
    }

    if !optional_class.is_empty() || !optional_instance.is_empty() {
        out.push_str("\n@optional\n");
        for m in sorted(optional_class) {
            out.push_str(&format_method('+', &m));
            out.push_str(";\n");
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
            out.push_str(&format_property(&p));
        }
    }
}

fn has_methods(c: &Class) -> bool {
    !c.class_methods.is_empty() || !c.instance_methods.is_empty()
}

fn visit_class(out: &mut String, c: &Class, opts: &Options) {
    if !c.is_exported {
        out.push_str("__attribute__((visibility(\"hidden\")))\n");
    }
    out.push_str(&format!("@interface {}", c.name));
    if let Some(sc) = &c.superclass_name {
        out.push_str(&format!(" : {}", sc));
    }
    if !c.protocols.is_empty() {
        out.push_str(&format!(" <{}>", protocols_string(&c.protocols)));
    }
    out.push('\n');

    // ivars (always emit braces)
    out.push_str("{\n");
    for iv in &c.ivars {
        let mut parser = typ::Parser::new(&iv.type_string);
        let ty = parser.parse_type();
        out.push_str("    ");
        out.push_str(&typ::format(&ty, &iv.name));
        out.push_str(";\n");
    }
    out.push_str("}\n\n");

    visit_methods(
        out,
        &c.class_methods,
        &c.instance_methods,
        &[],
        &[],
        &c.properties,
        opts,
    );

    if has_methods(c) {
        out.push('\n');
    }
    out.push_str("@end\n\n");
}

fn visit_protocol(out: &mut String, p: &Protocol, opts: &Options) {
    out.push_str(&format!("@protocol {}", p.name));
    if !p.adopted_protocols.is_empty() {
        out.push_str(&format!(" <{}>", protocols_string(&p.adopted_protocols)));
    }
    out.push('\n');
    visit_methods(
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

fn visit_category(out: &mut String, c: &Category, opts: &Options) {
    out.push_str(&format!("@interface {} ({})", c.class_name, c.name));
    if !c.protocols.is_empty() {
        out.push_str(&format!(" <{}>", protocols_string(&c.protocols)));
    }
    out.push('\n');
    visit_methods(
        out,
        &c.class_methods,
        &c.instance_methods,
        &[],
        &[],
        &c.properties,
        opts,
    );
    out.push_str("@end\n\n");
}

pub fn dump(macho: &MachOFile, image: &ObjcImage, opts: &Options) -> String {
    let mut out = String::new();
    // Header comment.
    out.push_str("//\n");
    out.push_str("//     Generated by class-dump 3.5.1 (64 bit).\n");
    out.push_str("//\n");
    out.push_str("//  Copyright (C) 1997-2019 Steve Nygard.\n");
    out.push_str("//\n\n");
    out.push_str("#pragma mark -\n\n");

    let _ = macho; // file comment block: TODO

    // Protocols, uniqued by name and sorted by name (default behaviour).
    let mut protocols: Vec<&Protocol> = image.protocols.iter().collect();
    protocols.sort_by(|a, b| a.name.cmp(&b.name));
    let mut seen = std::collections::HashSet::new();
    protocols.retain(|p| seen.insert(p.name.clone()));
    for p in protocols {
        visit_protocol(&mut out, p, opts);
    }

    // Classes, sorted by name.
    let mut classes: Vec<&Class> = image.classes.iter().collect();
    if opts.sort_by_name || true {
        classes.sort_by(|a, b| a.name.cmp(&b.name));
    }
    for c in classes {
        visit_class(&mut out, c, opts);
    }

    // Categories.
    let mut categories: Vec<&Category> = image.categories.iter().collect();
    categories.sort_by(|a, b| a.class_name.cmp(&b.class_name));
    for c in categories {
        visit_category(&mut out, c, opts);
    }

    out
}
