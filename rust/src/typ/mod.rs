//! Objective-C @encode type parsing and formatting, mirroring the CDType* family.
//!
//! This is a first cut that handles primitives, objects, pointers, arrays, bitfields,
//! structs and unions, plus method-signature formatting.  Struct expansion into a
//! "Named Structures" section is handled separately by the output stage.

#[derive(Clone, Debug)]
pub enum Type {
    Primitive(char),
    Id,
    NamedObject(String),
    Block,
    Class,
    Sel,
    CharStar,
    Pointer(Box<Type>),
    Array(u64, Box<Type>),
    Struct(String, Vec<(Option<String>, Type)>),
    Union(String, Vec<(Option<String>, Type)>),
    Bitfield(u32),
    FunctionPointer,
    Unknown,
    Modifier(char, Box<Type>),
}

pub struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(s: &'a str) -> Self {
        Parser { bytes: s.as_bytes(), pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_digits(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn read_number(&mut self) -> u64 {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        std::str::from_utf8(&self.bytes[start..self.pos])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Parse a single type.
    pub fn parse_type(&mut self) -> Type {
        let c = match self.peek() {
            Some(c) => c,
            None => return Type::Unknown,
        };
        match c {
            b'r' | b'n' | b'N' | b'o' | b'O' | b'R' | b'V' | b'A' | b'j' => {
                self.pos += 1;
                let inner = self.parse_type();
                Type::Modifier(c as char, Box::new(inner))
            }
            b'@' => {
                self.pos += 1;
                match self.peek() {
                    Some(b'"') => {
                        self.pos += 1;
                        let start = self.pos;
                        while let Some(ch) = self.peek() {
                            if ch == b'"' {
                                break;
                            }
                            self.pos += 1;
                        }
                        let name =
                            String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned();
                        if self.peek() == Some(b'"') {
                            self.pos += 1;
                        }
                        // @"<NSCopying>" style protocol-only is still an object; keep name.
                        Type::NamedObject(name)
                    }
                    Some(b'?') => {
                        self.pos += 1;
                        Type::Block
                    }
                    _ => Type::Id,
                }
            }
            b'#' => {
                self.pos += 1;
                Type::Class
            }
            b':' => {
                self.pos += 1;
                Type::Sel
            }
            b'*' => {
                self.pos += 1;
                Type::CharStar
            }
            b'^' => {
                self.pos += 1;
                if self.peek() == Some(b'?') {
                    self.pos += 1;
                    Type::FunctionPointer
                } else {
                    Type::Pointer(Box::new(self.parse_type()))
                }
            }
            b'[' => {
                self.pos += 1;
                let count = self.read_number();
                let inner = self.parse_type();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                }
                Type::Array(count, Box::new(inner))
            }
            b'{' => self.parse_struct_or_union(b'{', b'}'),
            b'(' => self.parse_struct_or_union(b'(', b')'),
            b'b' => {
                self.pos += 1;
                let n = self.read_number();
                Type::Bitfield(n as u32)
            }
            b'?' => {
                self.pos += 1;
                Type::Unknown
            }
            _ => {
                // primitive
                self.pos += 1;
                Type::Primitive(c as char)
            }
        }
    }

    fn parse_struct_or_union(&mut self, open: u8, close: u8) -> Type {
        self.pos += 1; // consume open
        // read name up to '=' or close
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == b'=' || ch == close {
                break;
            }
            self.pos += 1;
        }
        let name = String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned();
        let mut fields = Vec::new();
        if self.peek() == Some(b'=') {
            self.pos += 1;
            while let Some(ch) = self.peek() {
                if ch == close {
                    break;
                }
                // optional field name in quotes
                let mut field_name = None;
                if ch == b'"' {
                    self.pos += 1;
                    let s = self.pos;
                    while let Some(c2) = self.peek() {
                        if c2 == b'"' {
                            break;
                        }
                        self.pos += 1;
                    }
                    field_name =
                        Some(String::from_utf8_lossy(&self.bytes[s..self.pos]).into_owned());
                    if self.peek() == Some(b'"') {
                        self.pos += 1;
                    }
                    if self.peek() == Some(close) {
                        fields.push((field_name, Type::Unknown));
                        break;
                    }
                }
                let ty = self.parse_type();
                fields.push((field_name, ty));
            }
        }
        if self.peek() == Some(close) {
            self.pos += 1;
        }
        if open == b'{' {
            Type::Struct(name, fields)
        } else {
            Type::Union(name, fields)
        }
    }
}

/// Parse the full method type string into a vector of types (return + self + _cmd + args),
/// skipping the frame-offset digits between them.
pub fn parse_method_types(s: &str) -> Vec<Type> {
    let mut p = Parser::new(s);
    let mut out = Vec::new();
    while p.peek().is_some() {
        // A leading digit with no type would be malformed; guard.
        if p.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            p.skip_digits();
            continue;
        }
        let ty = p.parse_type();
        p.skip_digits();
        out.push(ty);
    }
    out
}

fn primitive_name(c: char) -> &'static str {
    match c {
        'c' => "char",
        'i' => "int",
        's' => "short",
        'l' => "long",
        'q' => "long long",
        'C' => "unsigned char",
        'I' => "unsigned int",
        'S' => "unsigned short",
        'L' => "unsigned long",
        'Q' => "unsigned long long",
        'f' => "float",
        'd' => "double",
        'D' => "long double",
        'B' => "_Bool",
        'v' => "void",
        _ => "void",
    }
}

/// Format `ty` as a C declaration embedding `name` (which may be empty).
pub fn format(ty: &Type, name: &str) -> String {
    match ty {
        Type::Modifier(_, inner) => format(inner, name),
        Type::Primitive(c) => join(primitive_name(*c), name),
        Type::Id => join("id", name),
        Type::Class => join("Class", name),
        Type::Sel => join("SEL", name),
        Type::Block => join("CDUnknownBlockType", name),
        Type::Unknown => join("void", name), // bare '?' rarely standalone
        Type::FunctionPointer => join("CDUnknownFunctionPointerType", name),
        Type::NamedObject(cls) => {
            if cls.starts_with('<') {
                // protocol-only object: id <Proto>
                if name.is_empty() {
                    format!("id {}", cls)
                } else {
                    format!("id {} {}", cls, name)
                }
            } else if name.is_empty() {
                format!("{} *", cls)
            } else {
                format!("{} *{}", cls, name)
            }
        }
        Type::CharStar => {
            if name.is_empty() {
                "char *".to_string()
            } else {
                format!("char *{}", name)
            }
        }
        Type::Pointer(inner) => {
            // pointer: attach '*' to the name
            let inner_name = format!("*{}", name);
            format(inner, &inner_name)
        }
        Type::Array(count, inner) => {
            let arr_name = format!("{}[{}]", name, count);
            format(inner, &arr_name)
        }
        Type::Bitfield(n) => {
            if name.is_empty() {
                format!("int : {}", n)
            } else {
                format!("int {} : {}", name, n)
            }
        }
        Type::Struct(sname, fields) => format_record("struct", sname, fields, name),
        Type::Union(sname, fields) => format_record("union", sname, fields, name),
    }
}

fn format_record(
    kw: &str,
    sname: &str,
    fields: &[(Option<String>, Type)],
    name: &str,
) -> String {
    // Anonymous (name is "?" or empty) -> expand inline; named -> "struct Name".
    let anonymous = sname.is_empty() || sname == "?";
    let head = if anonymous {
        if fields.is_empty() {
            format!("{} {{ }}", kw)
        } else {
            let mut s = format!("{} {{\n", kw);
            for (i, (fname, fty)) in fields.iter().enumerate() {
                let fn_name = fname.clone().unwrap_or_else(|| format!("_field{}", i + 1));
                s.push_str("    ");
                s.push_str(&format(fty, &fn_name));
                s.push_str(";\n");
            }
            s.push('}');
            s
        }
    } else {
        format!("{} {}", kw, sname)
    };
    join(&head, name)
}

fn join(base: &str, name: &str) -> String {
    if name.is_empty() {
        base.to_string()
    } else {
        format!("{} {}", base, name)
    }
}

/// Format a full method declaration: `- (ret)sel:(a)arg1 ...` (prefix is "-" or "+").
pub fn format_method(prefix: char, selector: &str, type_string: &str) -> String {
    let types = parse_method_types(type_string);
    let ret = types.get(0).cloned().unwrap_or(Type::Id);
    let ret_str = format(&ret, "");
    // args after self(@) and _cmd(:)
    let args: Vec<&Type> = types.iter().skip(3).collect();

    let parts: Vec<&str> = selector.split(':').collect();
    // A selector with no colon: split yields [selector]; no args.
    if selector.contains(':') {
        // parts has trailing "" because selector ends with ':'
        let keywords: Vec<&str> = parts.iter().filter(|s| !s.is_empty()).cloned().collect();
        let n = keywords.len();
        let mut s = format!("{} ({}){}", prefix, ret_str.trim(), "");
        // Build "kw:(type)argN " for each keyword.
        let mut decl = String::new();
        for i in 0..n {
            let argty = args.get(i).cloned().cloned().unwrap_or(Type::Id);
            let aname = format!("arg{}", i + 1);
            // selector keyword includes the colon
            decl.push_str(&format!("{}:({}){}", keywords[i], format(&argty, "").trim(), aname));
            if i + 1 < n {
                decl.push(' ');
            }
        }
        s = format!("{} ({}){}", prefix, ret_str.trim(), decl);
        s
    } else {
        format!("{} ({}){}", prefix, ret_str.trim(), selector)
    }
}
