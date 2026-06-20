//! Port of CDTypeController + CDStructureTable + CDStructureInfo: the multi-phase
//! structure registration/merging that assigns CDStruct_/CDUnion_ typedef names and
//! decides expansion vs reference, then emits the structure declaration sections.
//!
//! Walks are driven at the controller level so each struct/union node is dispatched
//! to the correct table (mirroring CDTypeController's phaseNReplacementForType:).

use crate::sha1::sha1_hex;
use crate::typ::{CDType, FormatterCfg, TypeNamer, T_BLOCK, T_FUNCTION_POINTER};
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
struct Info {
    ty: CDType,
    reference_count: usize,
    is_used_in_method: bool,
    typedef_name: Option<String>,
}

impl Info {
    fn new(ty: CDType) -> Info {
        Info { ty, reference_count: 0, is_used_in_method: false, typedef_name: None }
    }
    fn name(&self) -> String {
        self.ty.type_name_description()
    }
    fn generate_typedef_name(&mut self, base: &str) {
        let digest = sha1_hex(self.ty.type_string().as_bytes());
        let last8 = &digest[digest.len() - 8..];
        self.typedef_name = Some(format!("{}{}", base, last8));
    }
}

#[derive(Default)]
struct Table {
    anonymous_base_name: String,
    phase0: HashMap<String, Info>,
    phase1: HashMap<String, Info>,
    phase1_max_depth: usize,
    phase2_named: HashMap<String, Info>,
    phase2_anon: HashMap<String, Info>,
    phase2_name_exceptions: Vec<Info>,
    phase2_anon_exceptions: Vec<Info>,
    phase3_named: HashMap<String, Info>,
    phase3_anon: HashMap<String, Info>,
    phase3_name_exceptions: HashMap<String, Info>,
    phase3_anon_exceptions: HashMap<String, Info>,
    phase3_exceptional_names: HashSet<String>,
}

fn depth_sort(infos: &mut Vec<Info>) {
    infos.sort_by(|a, b| {
        a.ty.structure_depth()
            .cmp(&b.ty.structure_depth())
            .then_with(|| a.ty.really_bare_type_string().cmp(&b.ty.really_bare_type_string()))
            .then_with(|| a.ty.type_string().cmp(&b.ty.type_string()))
    });
}

impl Table {
    fn new(base: &str) -> Table {
        Table { anonymous_base_name: base.to_string(), ..Default::default() }
    }

    fn phase0_register(&mut self, ty: &CDType, used_in_method: bool) {
        let e = self.phase0.entry(ty.type_string()).or_insert_with(|| Info::new(ty.clone()));
        e.reference_count += 1;
        if used_in_method {
            e.is_used_in_method = true;
        }
    }

    fn phase1_register(&mut self, ty: &CDType) {
        self.phase1.entry(ty.type_string()).or_insert_with(|| Info::new(ty.clone()));
    }

    fn finish_phase1(&mut self) {
        for info in self.phase1.values() {
            let d = info.ty.structure_depth();
            if self.phase1_max_depth < d {
                self.phase1_max_depth = d;
            }
        }
    }

    fn phase2_replacement(&self, ty: &CDType) -> Option<CDType> {
        let name = ty.type_name_description();
        if name == "?" {
            self.phase2_anon.get(&ty.really_bare_type_string()).map(|i| i.ty.clone())
        } else {
            self.phase2_named.get(&name).map(|i| i.ty.clone())
        }
    }

    fn phase3_replacement(&self, ty: &CDType) -> Option<CDType> {
        let name = ty.type_name_description();
        if name == "?" {
            self.phase3_anon.get(&ty.really_bare_type_string()).map(|i| i.ty.clone())
        } else {
            self.phase3_named.get(&name).map(|i| i.ty.clone())
        }
    }

    /// Returns true if the caller should recurse and register this structure's members.
    fn phase3_register(&mut self, structure: &CDType, count: usize, used: bool) -> bool {
        let name = structure.type_name_description();
        if name == "?" {
            let ts = structure.type_string();
            let key = structure.really_bare_type_string();
            if let Some(info) = self.phase3_anon_exceptions.get_mut(&ts) {
                info.reference_count += count;
                if used {
                    info.is_used_in_method = true;
                }
                return info.reference_count == count;
            }
            if let Some(info) = self.phase3_anon.get_mut(&key) {
                info.reference_count += count;
                if used {
                    info.is_used_in_method = true;
                }
                return false;
            }
            let mut info = Info::new(structure.clone());
            info.reference_count = count;
            info.is_used_in_method = used;
            self.phase3_anon.insert(key, info);
            true
        } else if self.phase3_exceptional_names.contains(&name) {
            let ts = structure.type_string();
            if let Some(info) = self.phase3_name_exceptions.get_mut(&ts) {
                info.reference_count += count;
                return info.reference_count == count;
            }
            false
        } else if let Some(info) = self.phase3_named.get_mut(&name) {
            let was_empty = info.ty.members.is_empty();
            if was_empty {
                info.ty.merge_with(structure);
            }
            info.reference_count += count;
            if used {
                info.is_used_in_method = true;
            }
            was_empty
        } else {
            let mut info = Info::new(structure.clone());
            info.reference_count = count;
            info.is_used_in_method = used;
            self.phase3_named.insert(name, info);
            true
        }
    }

    fn generate_typedef_names(&mut self) {
        for info in self.phase3_anon.values_mut() {
            info.generate_typedef_name(&self.anonymous_base_name);
        }
        for info in self.phase3_anon_exceptions.values_mut() {
            info.generate_typedef_name(&self.anonymous_base_name);
        }
        for info in self.phase3_name_exceptions.values_mut() {
            let full = info.ty.type_name.clone().unwrap_or_default();
            // Use the bare name (before any template args) for the typedef base.
            let (bare, template) = match full.find('<') {
                Some(i) => (full[..i].to_string(), full[i..].to_string()),
                None => (full.clone(), String::new()),
            };
            info.generate_typedef_name(&format!("{}_", bare));
            info.ty.type_name = Some(format!("?{}", template));
        }
        // Template named structures used in methods also get a typedef name.
        for info in self.phase3_named.values_mut() {
            if info.ty.is_template_type() && info.is_used_in_method {
                let full = info.ty.type_name.clone().unwrap_or_default();
                let bare = match full.find('<') {
                    Some(i) => full[..i].to_string(),
                    None => full,
                };
                info.generate_typedef_name(&format!("{}_", bare));
            }
        }
    }

    fn generate_member_names(&mut self) {
        for m in self.phase3_named.values_mut() {
            m.ty.generate_member_names();
        }
        for m in self.phase3_anon.values_mut() {
            m.ty.generate_member_names();
        }
        for m in self.phase3_name_exceptions.values_mut() {
            m.ty.generate_member_names();
        }
        for m in self.phase3_anon_exceptions.values_mut() {
            m.ty.generate_member_names();
        }
    }

    fn should_expand_info(&self, info: Option<&Info>) -> bool {
        match info {
            None => true,
            Some(info) => {
                let name = info.name();
                !info.is_used_in_method
                    && info.reference_count < 2
                    && ((name.starts_with('_') && !has_underscore_capital_prefix(&name))
                        || name == "?")
            }
        }
    }

    fn lookup_phase3(&self, ty: &CDType) -> Option<&Info> {
        let name = ty.type_name_description();
        if name == "?" {
            self.phase3_anon
                .get(&ty.really_bare_type_string())
                .or_else(|| self.phase3_anon_exceptions.get(&ty.type_string()))
        } else {
            self.phase3_named
                .get(&name)
                .or_else(|| self.phase3_name_exceptions.get(&ty.type_string()))
        }
    }

    fn should_expand_type(&self, ty: &CDType) -> bool {
        self.should_expand_info(self.lookup_phase3(ty))
    }

    fn typedef_name_for_type(&self, ty: &CDType) -> Option<String> {
        self.phase3_anon
            .get(&ty.really_bare_type_string())
            .or_else(|| self.phase3_anon_exceptions.get(&ty.type_string()))
            .or_else(|| self.phase3_name_exceptions.get(&ty.type_string()))
            .or_else(|| self.phase3_named.get(&ty.type_name_description()))
            .and_then(|i| i.typedef_name.clone())
    }
}

fn has_underscore_capital_prefix(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0] == b'_' && b[1].is_ascii_uppercase()
}

fn combine(group: &[Info]) -> Option<Info> {
    let mut combined: Option<Info> = None;
    for info in group {
        match combined.as_mut() {
            None => combined = Some(info.clone()),
            Some(c) => {
                if c.ty.can_merge_with(&info.ty) {
                    c.ty.merge_with(&info.ty);
                    c.reference_count += info.reference_count;
                } else {
                    return None;
                }
            }
        }
    }
    combined
}

pub struct TypeController {
    structs: Table,
    unions: Table,
    pub has_unknown_func_ptrs: bool,
    pub has_unknown_blocks: bool,
}

impl TypeController {
    pub fn new() -> TypeController {
        TypeController {
            structs: Table::new("CDStruct_"),
            unions: Table::new("CDUnion_"),
            has_unknown_func_ptrs: false,
            has_unknown_blocks: false,
        }
    }

    // ----- Phase 0 -----
    pub fn register_type(&mut self, ty: &CDType, used_in_method: bool) {
        self.phase0_walk(ty, used_in_method);
    }

    fn phase0_walk(&mut self, ty: &CDType, used: bool) {
        if let Some(s) = &ty.subtype {
            self.phase0_walk(s, used);
        }
        if (ty.prim == b'{' || ty.prim == b'(') && !ty.members.is_empty() {
            self.table_mut(ty).phase0_register(ty, used);
        } else if ty.prim == T_FUNCTION_POINTER {
            self.has_unknown_func_ptrs = true;
        } else if ty.prim == T_BLOCK && ty.block_types.is_none() {
            self.has_unknown_blocks = true;
        }
    }

    fn table_mut(&mut self, ty: &CDType) -> &mut Table {
        if ty.prim == b'(' {
            &mut self.unions
        } else {
            &mut self.structs
        }
    }
    fn table_for(&self, ty: &CDType) -> &Table {
        if ty.prim == b'(' {
            &self.unions
        } else {
            &self.structs
        }
    }

    pub fn work_some_magic(&mut self) {
        self.run_phase1();
        self.structs.finish_phase1();
        self.unions.finish_phase1();

        let max_depth = self.structs.phase1_max_depth.max(self.unions.phase1_max_depth);
        for depth in 1..=max_depth {
            self.run_phase2_at_depth(depth, false);
            self.run_phase2_at_depth(depth, true);
        }

        self.phase2_replacement_on_phase0();
        self.build_phase3_exceptions();
        self.run_phase3();

        self.structs.generate_typedef_names();
        self.unions.generate_typedef_names();
        self.structs.generate_member_names();
        self.unions.generate_member_names();
    }

    // ----- Phase 1 -----
    fn run_phase1(&mut self) {
        let mut types: Vec<CDType> = self.structs.phase0.values().map(|i| i.ty.clone()).collect();
        types.extend(self.unions.phase0.values().map(|i| i.ty.clone()));
        for t in &types {
            self.phase1_walk(t);
        }
    }
    fn phase1_walk(&mut self, ty: &CDType) {
        if let Some(s) = &ty.subtype {
            self.phase1_walk(s);
        }
        if (ty.prim == b'{' || ty.prim == b'(') && !ty.members.is_empty() {
            self.table_mut(ty).phase1_register(ty);
            for m in &ty.members.clone() {
                self.phase1_walk(m);
            }
        }
    }

    // ----- Phase 2 -----
    fn phase2_merge(&self, ty: &mut CDType) {
        if let Some(s) = ty.subtype.as_mut() {
            self.phase2_merge(s);
        }
        for m in ty.members.iter_mut() {
            self.phase2_merge(m);
        }
        if (ty.prim == b'{' || ty.prim == b'(') && !ty.members.is_empty() {
            if let Some(repl) = self.table_for(ty).phase2_replacement(ty) {
                if ty.can_merge_with(&repl) {
                    ty.merge_with(&repl);
                }
            }
        }
    }

    fn run_phase2_at_depth(&mut self, depth: usize, is_union: bool) {
        let mut infos: Vec<Info> = {
            let table = if is_union { &self.unions } else { &self.structs };
            table.phase1.values().filter(|i| i.ty.structure_depth() == depth).cloned().collect()
        };
        for info in &mut infos {
            self.phase2_merge(&mut info.ty);
        }
        let mut name_dict: HashMap<String, Vec<Info>> = HashMap::new();
        let mut anon_dict: HashMap<String, Vec<Info>> = HashMap::new();
        for info in infos {
            let name = info.ty.type_name_description();
            if name == "?" {
                anon_dict.entry(info.ty.really_bare_type_string()).or_default().push(info);
            } else {
                name_dict.entry(name).or_default().push(info);
            }
        }
        let table = if is_union { &mut self.unions } else { &mut self.structs };
        for (key, group) in name_dict {
            match combine(&group) {
                Some(c) => {
                    if table.phase2_named.contains_key(&key) {
                        if let Some(prev) = table.phase2_named.remove(&key) {
                            table.phase2_name_exceptions.push(prev);
                        }
                        table.phase2_name_exceptions.push(c);
                    } else {
                        table.phase2_named.insert(key, c);
                    }
                }
                None => table.phase2_name_exceptions.extend(group),
            }
        }
        for (key, group) in anon_dict {
            match combine(&group) {
                Some(c) => {
                    table.phase2_anon.insert(key, c);
                }
                None => table.phase2_anon_exceptions.extend(group),
            }
        }
    }

    // ----- Phase 3 -----
    fn phase2_replacement_on_phase0(&mut self) {
        for is_union in [false, true] {
            let keys: Vec<String> = {
                let t = if is_union { &self.unions } else { &self.structs };
                t.phase0.keys().cloned().collect()
            };
            for k in keys {
                let mut info = {
                    let t = if is_union { &mut self.unions } else { &mut self.structs };
                    t.phase0.remove(&k).unwrap()
                };
                self.phase2_merge(&mut info.ty);
                let t = if is_union { &mut self.unions } else { &mut self.structs };
                t.phase0.insert(k, info);
            }
        }
    }

    fn build_phase3_exceptions(&mut self) {
        for table in [&mut self.structs, &mut self.unions] {
            let name_exc = std::mem::take(&mut table.phase2_name_exceptions);
            for info in name_exc {
                let mut ni = info.clone();
                ni.reference_count = 0;
                ni.is_used_in_method = false;
                table.phase3_exceptional_names.insert(ni.name());
                table.phase3_name_exceptions.insert(ni.ty.type_string(), ni);
            }
            let anon_exc = std::mem::take(&mut table.phase2_anon_exceptions);
            for info in anon_exc {
                let mut ni = info.clone();
                ni.reference_count = 0;
                ni.is_used_in_method = false;
                table.phase3_anon_exceptions.insert(ni.ty.type_string(), ni);
            }
        }
    }

    fn run_phase3(&mut self) {
        let mut infos: Vec<Info> = self.structs.phase0.values().cloned().collect();
        infos.extend(self.unions.phase0.values().cloned());
        // class-dump processes each table's phase0 separately (sorted by depth);
        // do structs then unions, each depth-sorted.
        let mut struct_infos: Vec<Info> = self.structs.phase0.values().cloned().collect();
        let mut union_infos: Vec<Info> = self.unions.phase0.values().cloned().collect();
        depth_sort(&mut struct_infos);
        depth_sort(&mut union_infos);
        for info in struct_infos.iter().chain(union_infos.iter()) {
            self.phase3_register_dispatch(&info.ty, info.reference_count, info.is_used_in_method);
        }
        let _ = infos;
    }

    fn phase3_register_dispatch(&mut self, ty: &CDType, count: usize, used: bool) {
        let register_members = self.table_mut(ty).phase3_register(ty, count, used);
        if register_members {
            for m in &ty.members.clone() {
                self.phase3_register_with(m);
            }
        }
    }

    fn phase3_register_with(&mut self, ty: &CDType) {
        if let Some(s) = &ty.subtype {
            self.phase3_register_with(s);
        }
        if ty.prim == b'{' || ty.prim == b'(' {
            self.phase3_register_dispatch(ty, 1, false);
        }
    }

    fn phase3_merge(&self, ty: &mut CDType) {
        if let Some(s) = ty.subtype.as_mut() {
            self.phase3_merge(s);
        }
        for m in ty.members.iter_mut() {
            self.phase3_merge(m);
        }
        if (ty.prim == b'{' || ty.prim == b'(') && !ty.members.is_empty() {
            if let Some(repl) = self.table_for(ty).phase3_replacement(ty) {
                if ty.can_merge_with(&repl) {
                    ty.merge_with(&repl);
                }
            }
        }
    }

    // ----- Formatting / output -----
    pub fn format_variable(&self, name: Option<&str>, ty: &CDType, cfg: &FormatterCfg) -> String {
        let indent = " ".repeat(cfg.base_level * 4);
        if ty.prim == b'c' {
            return match name {
                None => format!("{}BOOL", indent),
                Some(n) => format!("{}BOOL {}", indent, n),
            };
        }
        let mut t = ty.clone();
        t.variable_name = name.map(|s| s.to_string());
        self.phase3_merge(&mut t);
        format!("{}{}", indent, t.formatted_string(None, self, cfg, 0))
    }

    /// Format a method return/argument type (no phase-3 merge; matches formatMethodName).
    pub fn format_type_no_merge(&self, ty: &CDType, cfg: &FormatterCfg) -> String {
        if ty.prim == b'c' {
            return "BOOL".to_string();
        }
        ty.formatted_string(None, self, cfg, 0)
    }

    pub fn append_structures(&self, out: &mut String) {
        if self.has_unknown_func_ptrs && self.has_unknown_blocks {
            out.push_str("#pragma mark Function Pointers and Blocks\n\n");
        } else if self.has_unknown_func_ptrs {
            out.push_str("#pragma mark Function Pointers\n\n");
        } else if self.has_unknown_blocks {
            out.push_str("#pragma mark Blocks\n\n");
        }
        if self.has_unknown_func_ptrs {
            out.push_str("typedef void (*CDUnknownFunctionPointerType)(void); // return type and parameters are unknown\n\n");
        }
        if self.has_unknown_blocks {
            out.push_str("typedef void (^CDUnknownBlockType)(void); // return type and parameters are unknown\n\n");
        }
        self.append_named(out, &self.structs, "Named Structures");
        self.append_typedefs(out, &self.structs, "Typedef'd Structures");
        self.append_named(out, &self.unions, "Named Unions");
        self.append_typedefs(out, &self.unions, "Typedef'd Unions");
    }

    fn decl_cfg(&self) -> FormatterCfg {
        FormatterCfg { should_expand: true, should_auto_expand: true, base_level: 0, is_struct_decl: true }
    }

    fn append_named(&self, out: &mut String, table: &Table, mark: &str) {
        let mut added_mark = false;
        let cfg = self.decl_cfg();
        let mut keys: Vec<&String> = table.phase3_named.keys().collect();
        keys.sort();
        for key in keys {
            let info = &table.phase3_named[key];
            if !table.should_expand_info(Some(info)) {
                if !added_mark {
                    out.push_str(&format!("#pragma mark {}\n\n", mark));
                    added_mark = true;
                }
                let s = self.format_variable(None, &info.ty, &cfg);
                out.push_str(&s);
                out.push_str(";\n\n");
            }
        }

        // Name exceptions (conflicting types), inside an #if 0 block.
        let mut shown_exc = false;
        let mut excs: Vec<Info> = table.phase3_name_exceptions.values().cloned().collect();
        depth_sort(&mut excs);
        for info in &excs {
            if !table.should_expand_info(Some(info)) {
                if !added_mark {
                    out.push_str(&format!("#pragma mark {}\n\n", mark));
                    added_mark = true;
                }
                if !shown_exc {
                    out.push_str("#if 0\n// Names with conflicting types:\n");
                    shown_exc = true;
                }
                let s = self.format_variable(None, &info.ty, &cfg);
                out.push_str(&format!("typedef {} {};\n\n", s, info.typedef_name.clone().unwrap_or_default()));
            }
        }
        if shown_exc {
            out.push_str("#endif\n\n");
        }
    }

    fn append_typedefs(&self, out: &mut String, table: &Table, mark: &str) {
        let mut added_mark = false;
        let cfg = self.decl_cfg();
        let mut infos: Vec<Info> = table.phase3_anon.values().cloned().collect();
        depth_sort(&mut infos);
        for info in &infos {
            if !table.should_expand_info(Some(info)) {
                if !added_mark {
                    out.push_str(&format!("#pragma mark {}\n\n", mark));
                    added_mark = true;
                }
                let s = self.format_variable(None, &info.ty, &cfg);
                out.push_str(&format!("typedef {} {};\n\n", s, info.typedef_name.clone().unwrap_or_default()));
            }
        }

        // Anonymous exceptions ("Ambiguous groups").
        let mut shown_exc = false;
        let mut excs: Vec<Info> = table.phase3_anon_exceptions.values().cloned().collect();
        depth_sort(&mut excs);
        for info in &excs {
            if !table.should_expand_info(Some(info)) {
                if !added_mark {
                    out.push_str(&format!("#pragma mark {}\n\n", mark));
                    added_mark = true;
                }
                if !shown_exc {
                    out.push_str("// Ambiguous groups\n");
                    shown_exc = true;
                }
                let s = self.format_variable(None, &info.ty, &cfg);
                out.push_str(&format!("typedef {} {};\n\n", s, info.typedef_name.clone().unwrap_or_default()));
            }
        }

        // Named template types used in methods.
        let mut keys: Vec<&String> = table.phase3_named.keys().collect();
        keys.sort();
        for key in keys {
            let info = &table.phase3_named[key];
            if info.ty.is_template_type() && info.is_used_in_method {
                if !added_mark {
                    out.push_str(&format!("#pragma mark {}\n\n", mark));
                    added_mark = true;
                }
                let s = self.format_variable(None, &info.ty, &cfg);
                out.push_str(&format!("typedef {} {};\n\n", s, info.typedef_name.clone().unwrap_or_default()));
            }
        }
    }
}

impl TypeNamer for TypeController {
    fn typedef_name_for_structure(&self, ty: &CDType, cfg: &FormatterCfg, level: usize) -> Option<String> {
        if level == 0 && cfg.is_struct_decl {
            return None;
        }
        let table = self.table_for(ty);
        if !table.should_expand_type(ty) {
            return table.typedef_name_for_type(ty);
        }
        None
    }

    fn should_expand_type(&self, ty: &CDType) -> bool {
        self.table_for(ty).should_expand_type(ty)
    }
}
