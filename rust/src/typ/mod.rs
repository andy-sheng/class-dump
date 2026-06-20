//! Faithful port of CDType / CDTypeParser / CDTypeLexer: the Objective-C @encode
//! type AST, its canonical string forms, structure depth, merging, member-name
//! generation, and formatting.

pub const T_NAMED_OBJECT: u8 = 1;
pub const T_FUNCTION_POINTER: u8 = 2;
pub const T_BLOCK: u8 = 3;

#[derive(Clone, Default)]
pub struct CDType {
    pub prim: u8,
    pub subtype: Option<Box<CDType>>,
    pub members: Vec<CDType>,
    pub type_name: Option<String>,
    pub variable_name: Option<String>,
    pub bitfield_size: String,
    pub array_size: String,
    pub protocols: Vec<String>,
    pub block_types: Option<Vec<CDType>>,
}

/// Formatter configuration, mirroring CDTypeFormatter's flags.
pub struct FormatterCfg {
    pub should_expand: bool,
    pub should_auto_expand: bool,
    pub base_level: usize,
    pub is_struct_decl: bool,
}

/// Implemented by the type controller; supplies typedef names and expand decisions.
pub trait TypeNamer {
    fn typedef_name_for_structure(&self, ty: &CDType, cfg: &FormatterCfg, level: usize) -> Option<String>;
    fn should_expand_type(&self, ty: &CDType) -> bool;
}

/// A namer with no type controller (used for block signatures): no typedefs, no expansion.
pub struct NullNamer;
impl TypeNamer for NullNamer {
    fn typedef_name_for_structure(&self, _ty: &CDType, _cfg: &FormatterCfg, _level: usize) -> Option<String> {
        None
    }
    fn should_expand_type(&self, _ty: &CDType) -> bool {
        false
    }
}

impl CDType {
    fn simple(prim: u8) -> CDType {
        CDType { prim, ..Default::default() }
    }

    pub fn is_id_type(&self) -> bool {
        self.prim == b'@'
    }
    pub fn is_named_object(&self) -> bool {
        self.prim == T_NAMED_OBJECT
    }
    pub fn is_struct(&self) -> bool {
        self.prim == b'{'
    }
    pub fn is_union(&self) -> bool {
        self.prim == b'('
    }

    /// The struct/union tag description used as a dictionary key: "?" for anonymous.
    pub fn type_name_description(&self) -> String {
        self.type_name.clone().unwrap_or_default()
    }

    pub fn is_template_type(&self) -> bool {
        self.type_name.as_deref().map(|n| n.contains('<')).unwrap_or(false)
    }

    // ----- canonical type strings -----

    pub fn type_string(&self) -> String {
        self._type_string(1_000_000, true)
    }
    pub fn bare_type_string(&self) -> String {
        self._type_string(0, true)
    }
    pub fn really_bare_type_string(&self) -> String {
        self._type_string(0, false)
    }

    fn _type_string(&self, level: i64, show_objects: bool) -> String {
        match self.prim {
            T_NAMED_OBJECT => {
                if show_objects {
                    format!("@\"{}\"", self.type_name.clone().unwrap_or_default())
                } else {
                    "@".to_string()
                }
            }
            b'@' => "@".to_string(),
            b'b' => format!("b{}", self.bitfield_size),
            b'[' => format!(
                "[{}{}]",
                self.array_size,
                self.subtype_string(level, show_objects)
            ),
            b'(' => self.record_string('(', ')', level, show_objects),
            b'{' => self.record_string('{', '}', level, show_objects),
            b'^' => format!("^{}", self.subtype_string(level, show_objects)),
            b'j' | b'r' | b'n' | b'N' | b'o' | b'O' | b'R' | b'V' | b'A' => {
                format!("{}{}", self.prim as char, self.subtype_string(level, show_objects))
            }
            T_FUNCTION_POINTER => "^?".to_string(),
            T_BLOCK => "@?".to_string(),
            _ => format!("{}", self.prim as char),
        }
    }

    fn subtype_string(&self, level: i64, show_objects: bool) -> String {
        match &self.subtype {
            Some(s) => s._type_string(level, show_objects),
            None => String::new(),
        }
    }

    fn record_string(&self, open: char, close: char, level: i64, show_objects: bool) -> String {
        match &self.type_name {
            None => format!("{}{}{}", open, self.members_string(level, show_objects), close),
            Some(name) if self.members.is_empty() => format!("{}{}{}", open, name, close),
            Some(name) => format!(
                "{}{}={}{}",
                open,
                name,
                self.members_string(level, show_objects),
                close
            ),
        }
    }

    fn members_string(&self, level: i64, show_objects: bool) -> String {
        let mut s = String::new();
        for m in &self.members {
            if level > 0 {
                if let Some(vn) = &m.variable_name {
                    s.push_str(&format!("\"{}\"", vn));
                }
            }
            s.push_str(&m._type_string(level - 1, show_objects));
        }
        s
    }

    // ----- structure depth -----

    pub fn structure_depth(&self) -> usize {
        if let Some(s) = &self.subtype {
            return s.structure_depth();
        }
        if self.prim == b'{' || self.prim == b'(' {
            let mut max = 0;
            for m in &self.members {
                let d = m.structure_depth();
                if d > max {
                    max = d;
                }
            }
            return max + 1;
        }
        0
    }

    // ----- merging -----

    pub fn can_merge_with(&self, other: &CDType) -> bool {
        if self.is_id_type() && other.is_named_object() {
            return true;
        }
        if self.is_named_object() && other.is_id_type() {
            return true;
        }
        if self.prim != other.prim {
            return false;
        }
        match (&self.subtype, &other.subtype) {
            (Some(a), Some(b)) => {
                if !a.can_merge_with(b) {
                    return false;
                }
            }
            (None, Some(_)) => return false,
            _ => {}
        }
        let count = self.members.len();
        let other_count = other.members.len();
        if count != 0 && other_count == 0 {
            return false;
        }
        if count != 0 && count != other_count {
            return false;
        }
        if count == other_count {
            for i in 0..count {
                let a = &self.members[i];
                let b = &other.members[i];
                // Conflicting struct/union tag names block the merge.
                if let (Some(an), Some(bn)) = (&a.type_name, &b.type_name) {
                    if an != bn {
                        return false;
                    }
                }
                // Conflicting member variable names block the merge.
                if let (Some(an), Some(bn)) = (&a.variable_name, &b.variable_name) {
                    if an != bn {
                        return false;
                    }
                }
                if !a.can_merge_with(b) {
                    return false;
                }
            }
        }
        true
    }

    pub fn merge_with(&mut self, other: &CDType) {
        self.recursively_merge_with(other);
    }

    fn recursively_merge_with(&mut self, other: &CDType) {
        if self.is_id_type() && other.is_named_object() {
            self.prim = T_NAMED_OBJECT;
            self.type_name = other.type_name.clone();
            return;
        }
        if self.is_named_object() && other.is_id_type() {
            return;
        }
        if self.prim != other.prim {
            return;
        }
        if let (Some(a), Some(b)) = (self.subtype.as_mut(), other.subtype.as_ref()) {
            a.recursively_merge_with(b);
        }
        let count = self.members.len();
        let other_count = other.members.len();
        if other_count == 0 {
            return;
        } else if count == 0 && other_count != 0 {
            self.members = other.members.clone();
            return;
        } else if count != other_count {
            return;
        }
        for i in 0..count {
            if let Some(ovn) = &other.members[i].variable_name {
                if self.members[i].variable_name.is_none() {
                    self.members[i].variable_name = Some(ovn.clone());
                }
            }
            let om = other.members[i].clone();
            self.members[i].recursively_merge_with(&om);
        }
    }

    // ----- member name generation -----

    pub fn generate_member_names(&mut self) {
        if self.prim == b'{' || self.prim == b'(' {
            let used: std::collections::HashSet<String> = self
                .members
                .iter()
                .filter_map(|m| m.variable_name.clone())
                .collect();
            let mut number = 1usize;
            for m in &mut self.members {
                m.generate_member_names();
                if m.variable_name.is_none() && m.prim != b'b' {
                    let mut name;
                    loop {
                        name = format!("_field{}", number);
                        number += 1;
                        if !used.contains(&name) {
                            break;
                        }
                    }
                    m.variable_name = Some(name);
                }
            }
        }
        if let Some(s) = self.subtype.as_mut() {
            s.generate_member_names();
        }
    }

    // ----- formatting -----

    pub fn formatted_string(
        &self,
        previous_name: Option<&str>,
        namer: &dyn TypeNamer,
        cfg: &FormatterCfg,
        level: usize,
    ) -> String {
        let current_name: Option<String> = if self.variable_name.is_some() {
            self.variable_name.clone()
        } else {
            previous_name.map(|s| s.to_string())
        };
        let cn = current_name.as_deref();

        match self.prim {
            T_NAMED_OBJECT => {
                let type_name = if self.protocols.is_empty() {
                    self.type_name.clone().unwrap_or_default()
                } else {
                    format!(
                        "{}<{}>",
                        self.type_name.clone().unwrap_or_default(),
                        self.protocols.join(", ")
                    )
                };
                match cn {
                    None => format!("{} *", type_name),
                    Some(n) => format!("{} *{}", type_name, n),
                }
            }
            b'@' => match cn {
                None => {
                    if self.protocols.is_empty() {
                        "id".to_string()
                    } else {
                        format!("id <{}>", self.protocols.join(", "))
                    }
                }
                Some(n) => {
                    if self.protocols.is_empty() {
                        format!("id {}", n)
                    } else {
                        format!("id <{}> {}", self.protocols.join(", "), n)
                    }
                }
            },
            b'b' => match cn {
                None => format!("unsigned int :{}", self.bitfield_size),
                Some(n) => format!("unsigned int {}:{}", n, self.bitfield_size),
            },
            b'[' => {
                let result = match cn {
                    None => format!("[{}]", self.array_size),
                    Some(n) => format!("{}[{}]", n, self.array_size),
                };
                match &self.subtype {
                    Some(s) => s.formatted_string(Some(&result), namer, cfg, level),
                    None => result,
                }
            }
            b'(' => self.format_record('(', "union", cn, namer, cfg, level),
            b'{' => self.format_record('{', "struct", cn, namer, cfg, level),
            b'^' => {
                let mut result = match cn {
                    None => "*".to_string(),
                    Some(n) => format!("*{}", n),
                };
                if let Some(s) = &self.subtype {
                    if s.prim == b'[' {
                        result = format!("({})", result);
                    }
                    return s.formatted_string(Some(&result), namer, cfg, level);
                }
                result
            }
            T_FUNCTION_POINTER => match cn {
                None => "CDUnknownFunctionPointerType".to_string(),
                Some(n) => format!("CDUnknownFunctionPointerType {}", n),
            },
            T_BLOCK => {
                if self.block_types.is_some() {
                    self.block_signature_string(namer)
                } else {
                    match cn {
                        None => "CDUnknownBlockType".to_string(),
                        Some(n) => format!("CDUnknownBlockType {}", n),
                    }
                }
            }
            b'j' | b'r' | b'n' | b'N' | b'o' | b'O' | b'R' | b'V' | b'A' => match &self.subtype {
                None => match cn {
                    None => simple_type_name(self.prim).to_string(),
                    Some(n) => format!("{} {}", simple_type_name(self.prim), n),
                },
                Some(s) => format!(
                    "{} {}",
                    simple_type_name(self.prim),
                    s.formatted_string(cn, namer, cfg, level)
                ),
            },
            _ => match cn {
                None => simple_type_name(self.prim).to_string(),
                Some(n) => format!("{} {}", simple_type_name(self.prim), n),
            },
        }
    }

    fn format_record(
        &self,
        open: char,
        keyword: &str,
        current_name: Option<&str>,
        namer: &dyn TypeNamer,
        cfg: &FormatterCfg,
        level: usize,
    ) -> String {
        let mut base_type: Option<String> = namer.typedef_name_for_structure(self, cfg, level);

        if base_type.is_none() {
            let name_desc = self.type_name_description();
            let mut bt = if self.type_name.is_none() || name_desc == "?" {
                keyword.to_string()
            } else {
                format!("{} {}", keyword, name_desc)
            };
            let expand = (cfg.should_auto_expand
                && namer.should_expand_type(self)
                && !self.members.is_empty())
                || (level == 0 && cfg.should_expand && !self.members.is_empty());
            if expand {
                let inner = self.formatted_members(namer, cfg, level + 1);
                let indent = " ".repeat((cfg.base_level + level) * 4);
                bt.push_str(&format!(" {{\n{}{}}}", inner, indent));
            }
            base_type = Some(bt);
        }
        let base_type = base_type.unwrap();
        let _ = open;
        match current_name {
            None => base_type,
            Some(n) => format!("{} {}", base_type, n),
        }
    }

    fn formatted_members(&self, namer: &dyn TypeNamer, cfg: &FormatterCfg, level: usize) -> String {
        let mut s = String::new();
        let indent = " ".repeat((cfg.base_level + level) * 4);
        for m in &self.members {
            s.push_str(&indent);
            s.push_str(&m.formatted_string(None, namer, cfg, level));
            s.push_str(";\n");
        }
        s
    }

    fn block_signature_string(&self, _namer: &dyn TypeNamer) -> String {
        // The block-signature formatter has no type controller, so struct/union tags are
        // emitted bare (no CDStruct_ typedef names, no expansion).
        let cfg = FormatterCfg {
            should_expand: false,
            should_auto_expand: false,
            base_level: 0,
            is_struct_decl: false,
        };
        let namer = &NullNamer;
        let types = self.block_types.as_ref().unwrap();
        let mut s = String::new();
        let n = types.len();
        for (idx, t) in types.iter().enumerate() {
            if idx != 1 {
                s.push_str(&t.formatted_string(None, namer, &cfg, 0));
            } else {
                s.push_str("(^)");
            }
            let is_last = idx == n - 1;
            if idx == 0 {
                s.push(' ');
            } else if idx == 1 {
                s.push('(');
            } else if idx >= 2 && !is_last {
                s.push_str(", ");
            }
            if is_last {
                if n == 2 {
                    s.push_str("void");
                }
                s.push(')');
            }
        }
        s
    }

    /// Walk all struct/union subtypes (used by phase registration in the controller).
    pub fn walk_structs<F: FnMut(&CDType)>(&self, f: &mut F) {
        if let Some(s) = &self.subtype {
            s.walk_structs(f);
        }
        if (self.prim == b'{' || self.prim == b'(') && !self.members.is_empty() {
            f(self);
            for m in &self.members {
                m.walk_structs(f);
            }
        }
    }
}

fn is_simple_type(c: u8) -> bool {
    matches!(
        c,
        b'c' | b'i' | b's' | b'l' | b'q' | b'C' | b'I' | b'S' | b'L' | b'Q'
        | b'f' | b'd' | b'D' | b'B' | b'v' | b'*' | b'#' | b':' | b'%' | b'?'
    )
}

fn missing_type() -> CDType {
    CDType { prim: T_NAMED_OBJECT, type_name: Some("MISSING_TYPE".to_string()), ..Default::default() }
}

fn is_identifier_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || matches!(c, b'$' | b'_' | b':' | b'*')
}
fn is_identifier_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'$' | b'_' | b':' | b'*')
}

fn simple_type_name(prim: u8) -> &'static str {
    match prim {
        b'c' => "char",
        b'i' => "int",
        b's' => "short",
        b'l' => "long",
        b'q' => "long long",
        b'C' => "unsigned char",
        b'I' => "unsigned int",
        b'S' => "unsigned short",
        b'L' => "unsigned long",
        b'Q' => "unsigned long long",
        b'f' => "float",
        b'd' => "double",
        b'D' => "long double",
        b'B' => "_Bool",
        b'v' => "void",
        b'*' => "STR",
        b'#' => "Class",
        b':' => "SEL",
        b'%' => "NXAtom",
        b'?' => "void",
        b'j' => "_Complex",
        b'r' => "const",
        b'n' => "in",
        b'N' => "inout",
        b'o' => "out",
        b'O' => "bycopy",
        b'R' => "byref",
        b'V' => "oneway",
        b'A' => "_Atomic",
        _ => "UNKNOWN",
    }
}

// ===== Parser (port of CDTypeParser / CDTypeLexer) =====

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

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn read_number(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned()
    }

    fn read_quoted(&mut self) -> String {
        // assumes current char is '"'
        self.pos += 1;
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == b'"' {
                break;
            }
            self.pos += 1;
        }
        let s = String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned();
        if self.peek() == Some(b'"') {
            self.pos += 1;
        }
        s
    }

    /// Parse a single type. Public for property types.
    pub fn parse_type(&mut self) -> CDType {
        self.parse_type_in_struct(false)
    }

    fn is_type_start(&self, c: u8) -> bool {
        matches!(
            c,
            b'r' | b'n' | b'N' | b'o' | b'O' | b'R' | b'V' | b'A' | b'j'
            | b'^' | b'b' | b'@' | b'{' | b'(' | b'['
            | b'c' | b'i' | b's' | b'l' | b'q' | b'C' | b'I' | b'S' | b'L' | b'Q'
            | b'f' | b'd' | b'D' | b'B' | b'v' | b'*' | b'#' | b':' | b'%' | b'?'
        )
    }

    fn parse_type_in_struct(&mut self, in_struct: bool) -> CDType {
        let c = match self.peek() {
            Some(c) => c,
            None => return missing_type(),
        };
        match c {
            b'j' | b'r' | b'n' | b'N' | b'o' | b'O' | b'R' | b'V' | b'A' => {
                self.pos += 1;
                let sub = if self.peek().map(|x| self.is_type_start(x)).unwrap_or(false) {
                    Some(Box::new(self.parse_type_in_struct(in_struct)))
                } else {
                    None
                };
                CDType { prim: c, subtype: sub, ..Default::default() }
            }
            b'^' => {
                self.pos += 1;
                match self.peek() {
                    Some(b'"') | Some(b'}') | Some(b')') | None => {
                        CDType { prim: b'^', subtype: Some(Box::new(CDType::simple(b'v'))), ..Default::default() }
                    }
                    Some(b'?') => {
                        self.pos += 1;
                        CDType { prim: T_FUNCTION_POINTER, ..Default::default() }
                    }
                    _ => {
                        let sub = self.parse_type_in_struct(in_struct);
                        CDType { prim: b'^', subtype: Some(Box::new(sub)), ..Default::default() }
                    }
                }
            }
            b'b' => {
                self.pos += 1;
                let n = self.read_number();
                CDType { prim: b'b', bitfield_size: n, ..Default::default() }
            }
            b'@' => {
                self.pos += 1;
                if self.peek() == Some(b'"')
                    && (!in_struct || self.quoted_is_object_name())
                {
                    let s = self.read_quoted();
                    self.parse_object_name(s)
                } else if self.peek() == Some(b'?') {
                    self.pos += 1;
                    let mut block_types = None;
                    if self.peek() == Some(b'<') {
                        self.pos += 1;
                        block_types = Some(self.parse_method_type_list(b'>'));
                        if self.peek() == Some(b'>') {
                            self.pos += 1;
                        }
                    }
                    CDType { prim: T_BLOCK, block_types, ..Default::default() }
                } else {
                    CDType::simple(b'@')
                }
            }
            b'{' => {
                self.pos += 1;
                let name = self.parse_type_name(false);
                let members = self.parse_optional_members(b'}');
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                }
                CDType { prim: b'{', type_name: name, members, ..Default::default() }
            }
            b'(' => {
                self.pos += 1;
                // union: either a name (identifier) then optional '=' members, or a bare list of types.
                let starts_name = self
                    .peek()
                    .map(|c| is_identifier_start(c) || c == b'?')
                    .unwrap_or(false);
                if starts_name {
                    let name = self.parse_type_name(false);
                    let members = self.parse_optional_members(b')');
                    if self.peek() == Some(b')') {
                        self.pos += 1;
                    }
                    CDType { prim: b'(', type_name: name, members, ..Default::default() }
                } else {
                    let mut members = Vec::new();
                    while let Some(c) = self.peek() {
                        if c == b')' {
                            break;
                        }
                        members.push(self.parse_type_in_struct(true));
                    }
                    if self.peek() == Some(b')') {
                        self.pos += 1;
                    }
                    CDType { prim: b'(', type_name: None, members, ..Default::default() }
                }
            }
            b'[' => {
                self.pos += 1;
                let n = self.read_number();
                let sub = self.parse_type();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                }
                CDType { prim: b'[', array_size: n, subtype: Some(Box::new(sub)), ..Default::default() }
            }
            b'*' => {
                // class-dump represents char* (`*`) as ^c (pointer to char).
                self.pos += 1;
                CDType { prim: b'^', subtype: Some(Box::new(CDType::simple(b'c'))), ..Default::default() }
            }
            _ if is_simple_type(c) => {
                self.pos += 1;
                CDType::simple(c)
            }
            _ => {
                // Unrecognized token: class-dump produces a named object "MISSING_TYPE".
                self.pos += 1;
                missing_type()
            }
        }
    }

    /// Heuristic for `@` inside a struct: a quoted string is an object name (vs a member name)
    /// if the next type token doesn't immediately follow as a member.
    fn quoted_is_object_name(&self) -> bool {
        // Peek the quoted content's first letter and the char after the closing quote.
        // Mirrors: isFirstLetterUppercase OR the following token is not a type start.
        let mut i = self.pos + 1;
        let first = self.bytes.get(i).copied().unwrap_or(0);
        while i < self.bytes.len() && self.bytes[i] != b'"' {
            i += 1;
        }
        let after = self.bytes.get(i + 1).copied().unwrap_or(0);
        first.is_ascii_uppercase() || !self.is_type_start(after)
    }

    fn parse_object_name(&self, s: String) -> CDType {
        if let Some(open) = s.find('<') {
            if let Some(close) = s.rfind('>') {
                if close > open {
                    let protocols: Vec<String> =
                        s[open + 1..close].split(',').map(|x| x.to_string()).collect();
                    let name = s[..open].trim().to_string();
                    if !name.is_empty() && name != "id" {
                        return CDType {
                            prim: T_NAMED_OBJECT,
                            type_name: Some(name),
                            protocols,
                            ..Default::default()
                        };
                    }
                    return CDType { prim: b'@', protocols, ..Default::default() };
                }
            }
        }
        CDType { prim: T_NAMED_OBJECT, type_name: Some(s), ..Default::default() }
    }

    /// Parse a (possibly templated) type name, mirroring CDTypeParser.parseTypeName.
    /// `in_template` selects the lexer behaviour: identifier scan at top level,
    /// "anything but <,>" runs inside template arguments.
    fn parse_type_name(&mut self, in_template: bool) -> Option<String> {
        let base = if in_template {
            self.scan_template_run()
        } else {
            self.scan_identifier()
        };
        let base = match base {
            Some(b) => b,
            None => return None,
        };
        if self.peek() != Some(b'<') {
            return Some(base);
        }
        // template arguments
        self.pos += 1; // '<'
        let mut args: Vec<String> = Vec::new();
        args.push(self.parse_type_name(true).unwrap_or_default());
        while self.peek() == Some(b',') {
            self.pos += 1;
            args.push(self.parse_type_name(true).unwrap_or_default());
        }
        if self.peek() == Some(b'>') {
            self.pos += 1;
        }
        let suffix = if in_template {
            self.scan_template_run().unwrap_or_default()
        } else {
            String::new()
        };
        Some(format!("{}<{}>{}", base, args.join(", "), suffix))
    }

    fn scan_identifier(&mut self) -> Option<String> {
        if self.peek() == Some(b'?') {
            self.pos += 1;
            return Some("?".to_string());
        }
        match self.peek() {
            Some(c) if is_identifier_start(c) => {}
            _ => return None,
        }
        let start = self.pos;
        while let Some(c) = self.peek() {
            if is_identifier_char(c) {
                self.pos += 1;
            } else {
                break;
            }
        }
        Some(String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned())
    }

    fn scan_template_run(&mut self) -> Option<String> {
        // skip leading whitespace (lexer skips whitespace in TemplateTypes state)
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == b'<' || c == b'>' || c == b',' {
                break;
            }
            self.pos += 1;
        }
        if self.pos == start {
            None
        } else {
            Some(String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned())
        }
    }

    fn parse_optional_members(&mut self, close: u8) -> Vec<CDType> {
        let mut members = Vec::new();
        if self.peek() == Some(b'=') {
            self.pos += 1;
            while let Some(c) = self.peek() {
                if c == close {
                    break;
                }
                let mut var_name = None;
                if c == b'"' {
                    var_name = Some(self.read_quoted());
                    if self.peek() == Some(close) {
                        break;
                    }
                }
                let mut ty = self.parse_type_in_struct(true);
                ty.variable_name = var_name;
                members.push(ty);
            }
        }
        members
    }

    /// Parse a sequence of (type, number) pairs until `end` or end-of-input; return the types.
    fn parse_method_type_list(&mut self, end: u8) -> Vec<CDType> {
        let mut out = Vec::new();
        while let Some(c) = self.peek() {
            if c == end {
                break;
            }
            let ty = self.parse_type();
            // skip offset number
            let _ = self.read_number();
            out.push(ty);
        }
        out
    }
}

/// Parse a full method type string into (type, _offset) types: [return, self, _cmd, args...].
pub fn parse_method_types(s: &str) -> Vec<CDType> {
    let mut p = Parser::new(s);
    let mut out = Vec::new();
    while !p.at_end() {
        if p.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            p.read_number();
            continue;
        }
        let ty = p.parse_type();
        p.read_number();
        out.push(ty);
    }
    out
}
