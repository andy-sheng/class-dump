//! Objective-C 2 metadata model and processor, mirroring CDObjectiveC2Processor and the
//! CDOC* model classes.

use crate::cursor::Cursor;
use crate::macho::MachOFile;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Method {
    pub name: String,        // selector
    pub type_string: String, // @encode method signature
}

#[derive(Clone)]
pub struct Ivar {
    pub name: String,
    pub type_string: String,
    pub offset: u64,
}

#[derive(Clone)]
pub struct Property {
    pub name: String,
    pub attributes: String,
}

#[derive(Clone, Default)]
pub struct Protocol {
    pub name: String,
    pub adopted_protocols: Vec<String>,
    pub instance_methods: Vec<Method>,
    pub class_methods: Vec<Method>,
    pub optional_instance_methods: Vec<Method>,
    pub optional_class_methods: Vec<Method>,
    pub properties: Vec<Property>,
}

#[derive(Clone, Default)]
pub struct Class {
    pub name: String,
    pub superclass_name: Option<String>,
    pub is_swift: bool,
    pub is_exported: bool,
    pub protocols: Vec<String>,
    pub instance_methods: Vec<Method>,
    pub class_methods: Vec<Method>,
    pub ivars: Vec<Ivar>,
    pub properties: Vec<Property>,
}

#[derive(Clone, Default)]
pub struct Category {
    pub name: String,
    pub class_name: String,
    pub instance_methods: Vec<Method>,
    pub class_methods: Vec<Method>,
    pub protocols: Vec<String>,
    pub properties: Vec<Property>,
}

pub struct ObjcImage {
    pub classes: Vec<Class>,
    pub categories: Vec<Category>,
    pub protocols: Vec<Protocol>,
}

pub struct Processor<'a> {
    macho: &'a MachOFile,
    protocols_by_address: HashMap<u64, Protocol>,
    protocol_order: Vec<u64>,
}

impl<'a> Processor<'a> {
    pub fn new(macho: &'a MachOFile) -> Self {
        Processor { macho, protocols_by_address: HashMap::new(), protocol_order: Vec::new() }
    }

    fn cursor_at(&self, address: u64) -> Option<Cursor<'a>> {
        let off = self.macho.data_offset_for_address(address)? as usize;
        Some(Cursor::at(
            &self.macho.data,
            self.macho.byte_order,
            self.macho.ptr_size(),
            off,
        ))
    }

    fn section_by_name(&self, name: &str) -> Option<&crate::macho::Section> {
        for seg in &self.macho.segments {
            for sect in &seg.sections {
                if sect.sectname == name {
                    return Some(sect);
                }
            }
        }
        None
    }

    pub fn process(&mut self) -> ObjcImage {
        // Load protocols first (from __objc_protolist), mirroring CDObjectiveCProcessor.
        self.load_protocols();
        let classes = self.load_classes();
        let categories = self.load_categories();
        // Collect protocols in discovery order.
        let mut protocols: Vec<Protocol> = Vec::new();
        for addr in &self.protocol_order {
            if let Some(p) = self.protocols_by_address.get(addr) {
                protocols.push(p.clone());
            }
        }
        ObjcImage { classes, categories, protocols }
    }

    /// Look up a class/category protocol address in the uniquer. Returns the protocol name only
    /// if that exact address was registered while loading __objc_protolist (+ adopted protocols).
    fn uniqued_protocol_name(&self, address: u64) -> Option<String> {
        self.protocols_by_address.get(&address).map(|p| p.name.clone())
    }

    fn load_protocols(&mut self) {
        let sect = match self.section_by_name("__objc_protolist") {
            Some(s) => s.clone(),
            None => return,
        };
        let ptr = self.macho.ptr_size() as u64;
        let count = sect.size / ptr;
        for i in 0..count {
            let addr = sect.addr + i * ptr;
            if let Some(mut cur) = self.cursor_at(addr) {
                let proto_ptr = cur.read_ptr();
                self.protocol_at(proto_ptr);
            }
        }
    }

    fn load_classes(&mut self) -> Vec<Class> {
        let mut classes = Vec::new();
        let sect = match self.section_by_name("__objc_classlist") {
            Some(s) => s.clone(),
            None => return classes,
        };
        let ptr = self.macho.ptr_size() as u64;
        let count = sect.size / ptr;
        for i in 0..count {
            let addr = sect.addr + i * ptr;
            if let Some(mut cur) = self.cursor_at(addr) {
                let class_ptr = cur.read_ptr();
                if let Some(c) = self.load_class_at(class_ptr) {
                    classes.push(c);
                }
            }
        }
        classes
    }

    fn load_class_at(&mut self, address: u64) -> Option<Class> {
        if address == 0 {
            return None;
        }
        let mut cur = self.cursor_at(address)?;
        let _isa = cur.read_ptr();
        let superclass = cur.read_ptr();
        let _cache = cur.read_ptr();
        let _vtable = cur.read_ptr();
        let data_val = cur.read_ptr();
        let is_swift = (data_val & 0x1) != 0;
        let data = data_val & !7;
        if data == 0 {
            return None;
        }

        let mut class = Class { is_swift, ..Default::default() };
        let ro = self.read_class_ro(data)?;
        class.name = self.macho.string_at_address(ro.name).unwrap_or_default();
        class.instance_methods = self.load_methods(ro.base_methods, &mut None);
        class.ivars = self.load_ivars(ro.ivars);
        class.properties = self.load_properties(ro.base_properties);
        for paddr in self.protocol_address_list(ro.base_protocols) {
            // Class protocols are looked up in the uniquer (populated from __objc_protolist
            // + adopted protocols), never created; unknown addresses are skipped.
            if let Some(name) = self.uniqued_protocol_name(paddr) {
                if !class.protocols.contains(&name) {
                    class.protocols.push(name);
                }
            }
        }
        // class methods live on the metaclass (isa).
        if _isa != 0 {
            if let Some(meta_ro) = self
                .read_class_meta_ro(_isa)
            {
                class.class_methods = self.load_methods(meta_ro, &mut None);
            }
        }

        // isExported: external class symbol.
        if let Some(sym) = self.macho.class_symbol(&class.name) {
            class.is_exported = sym.is_external();
        }

        // Superclass name resolution.
        let class_name_address = address + self.macho.ptr_size() as u64;
        if self.macho.has_relocation_entry_for_address(class_name_address) {
            class.superclass_name = self.macho.external_class_name_for_address(class_name_address);
        } else if superclass != 0 {
            // Internal superclass: read its class_ro name.
            if let Some(sc_ro) = self.read_superclass_name(superclass) {
                class.superclass_name = Some(sc_ro);
            }
        }

        Some(class)
    }

    fn read_superclass_name(&self, address: u64) -> Option<String> {
        let mut cur = self.cursor_at(address)?;
        let _isa = cur.read_ptr();
        let _superclass = cur.read_ptr();
        let _cache = cur.read_ptr();
        let _vtable = cur.read_ptr();
        let data = cur.read_ptr() & !7;
        if data == 0 {
            return None;
        }
        let ro = self.read_class_ro(data)?;
        self.macho.string_at_address(ro.name)
    }

    fn read_class_meta_ro(&self, isa: u64) -> Option<u64> {
        let mut cur = self.cursor_at(isa)?;
        let _isa = cur.read_ptr();
        let _superclass = cur.read_ptr();
        let _cache = cur.read_ptr();
        let _vtable = cur.read_ptr();
        let data = cur.read_ptr() & !7;
        if data == 0 {
            return None;
        }
        let ro = self.read_class_ro(data)?;
        Some(ro.base_methods)
    }

    fn read_class_ro(&self, address: u64) -> Option<ClassRo> {
        let mut cur = self.cursor_at(address)?;
        let _flags = cur.read_u32();
        let _instance_start = cur.read_u32();
        let _instance_size = cur.read_u32();
        if self.macho.uses64 {
            let _reserved = cur.read_u32();
        }
        let _ivar_layout = cur.read_ptr();
        let name = cur.read_ptr();
        let base_methods = cur.read_ptr();
        let base_protocols = cur.read_ptr();
        let ivars = cur.read_ptr();
        let _weak_ivar_layout = cur.read_ptr();
        let base_properties = cur.read_ptr();
        Some(ClassRo { name, base_methods, base_protocols, ivars, base_properties })
    }

    fn load_methods(&self, address: u64, ext_cur: &mut Option<Cursor<'a>>) -> Vec<Method> {
        let mut methods = Vec::new();
        if address == 0 {
            return methods;
        }
        let mut cur = match self.cursor_at(address) {
            Some(c) => c,
            None => return methods,
        };
        let entsize_and_flags = cur.read_u32();
        let count = cur.read_u32();
        let is_small = (entsize_and_flags & 0x8000_0000) != 0;
        let direct_selectors = (entsize_and_flags & 0x4000_0000) != 0;

        if is_small {
            let ptr = self.macho.ptr_size() as u64;
            for index in 0..count as u64 {
                let name_field_address = address + 8 + index * 12;
                let types_field_address = name_field_address + 4;
                let imp_field_address = name_field_address + 8;
                let name_offset = cur.read_u32() as i32;
                let types_offset = cur.read_u32() as i32;
                let _imp_offset = cur.read_u32() as i32;

                let name_address = if direct_selectors {
                    (name_field_address as i64 + name_offset as i64) as u64
                } else {
                    let selref = (name_field_address as i64 + name_offset as i64) as u64;
                    match self.cursor_at(selref) {
                        Some(mut c) => c.read_ptr(),
                        None => 0,
                    }
                };
                let name = self.macho.string_at_address(name_address).unwrap_or_default();
                let mut types = self
                    .macho
                    .string_at_address((types_field_address as i64 + types_offset as i64) as u64)
                    .unwrap_or_default();
                if let Some(ec) = ext_cur.as_mut() {
                    let ext = ec.read_ptr();
                    types = self.macho.string_at_address(ext).unwrap_or_default();
                }
                let _ = ptr;
                methods.push(Method { name, type_string: types });
            }
        } else {
            for _ in 0..count {
                let name_ptr = cur.read_ptr();
                let types_ptr = cur.read_ptr();
                let _imp = cur.read_ptr();
                let name = self.macho.string_at_address(name_ptr).unwrap_or_default();
                let mut types = self.macho.string_at_address(types_ptr).unwrap_or_default();
                if let Some(ec) = ext_cur.as_mut() {
                    let ext = ec.read_ptr();
                    types = self.macho.string_at_address(ext).unwrap_or_default();
                }
                methods.push(Method { name, type_string: types });
            }
        }
        methods.reverse();
        methods
    }

    fn load_ivars(&self, address: u64) -> Vec<Ivar> {
        let mut ivars = Vec::new();
        if address == 0 {
            return ivars;
        }
        let mut cur = match self.cursor_at(address) {
            Some(c) => c,
            None => return ivars,
        };
        let _entsize = cur.read_u32();
        let count = cur.read_u32();
        for _ in 0..count {
            let offset_ptr = cur.read_ptr();
            let name_ptr = cur.read_ptr();
            let type_ptr = cur.read_ptr();
            let _alignment = cur.read_u32();
            let _size = cur.read_u32();
            if name_ptr != 0 {
                let name = self.macho.string_at_address(name_ptr).unwrap_or_default();
                let type_string = self.macho.string_at_address(type_ptr).unwrap_or_default();
                let offset = match self.cursor_at(offset_ptr) {
                    Some(mut c) => c.read_ptr() & 0xffff_ffff,
                    None => 0,
                };
                ivars.push(Ivar { name, type_string, offset });
            }
        }
        ivars
    }

    fn load_properties(&self, address: u64) -> Vec<Property> {
        let mut props = Vec::new();
        if address == 0 {
            return props;
        }
        let mut cur = match self.cursor_at(address) {
            Some(c) => c,
            None => return props,
        };
        let _entsize = cur.read_u32();
        let count = cur.read_u32();
        for _ in 0..count {
            let name_ptr = cur.read_ptr();
            let attr_ptr = cur.read_ptr();
            let name = self.macho.string_at_address(name_ptr).unwrap_or_default();
            let attributes = self.macho.string_at_address(attr_ptr).unwrap_or_default();
            props.push(Property { name, attributes });
        }
        props
    }

    fn protocol_address_list(&self, address: u64) -> Vec<u64> {
        let mut addrs = Vec::new();
        if address == 0 {
            return addrs;
        }
        if let Some(mut cur) = self.cursor_at(address) {
            let count = cur.read_ptr();
            for _ in 0..count {
                let v = cur.read_ptr();
                if v != 0 {
                    addrs.push(v);
                }
            }
        }
        addrs
    }

    /// Load (uniquing) a protocol; returns its name.
    fn protocol_at(&mut self, address: u64) -> Option<String> {
        if address == 0 {
            return None;
        }
        if let Some(p) = self.protocols_by_address.get(&address) {
            return Some(p.name.clone());
        }
        // Reserve slot to break cycles.
        self.protocols_by_address.insert(address, Protocol::default());
        self.protocol_order.push(address);

        let mut cur = self.cursor_at(address)?;
        let _isa = cur.read_ptr();
        let name_ptr = cur.read_ptr();
        let protocols = cur.read_ptr();
        let instance_methods = cur.read_ptr();
        let class_methods = cur.read_ptr();
        let optional_instance_methods = cur.read_ptr();
        let optional_class_methods = cur.read_ptr();
        let instance_properties = cur.read_ptr();
        let size = cur.read_u32();
        let _flags = cur.read_u32();
        let ptr = self.macho.ptr_size() as u64;
        let has_ext = size as u64 > 8 * ptr + 8;
        let ext_types = if has_ext { cur.read_ptr() } else { 0 };

        let name = self.macho.string_at_address(name_ptr).unwrap_or_default();

        let mut adopted = Vec::new();
        for paddr in self.protocol_address_list(protocols) {
            if let Some(n) = self.protocol_at(paddr) {
                if !adopted.contains(&n) {
                    adopted.push(n);
                }
            }
        }

        // A single extended-method-types cursor is shared across all four method lists and
        // advances continuously (matches CDObjectiveC2Processor.protocolAtAddress:).
        let mut ext_cur = if ext_types != 0 { self.cursor_at(ext_types) } else { None };
        let p = Protocol {
            name: name.clone(),
            adopted_protocols: adopted,
            instance_methods: self.load_methods(instance_methods, &mut ext_cur),
            class_methods: self.load_methods(class_methods, &mut ext_cur),
            optional_instance_methods: self.load_methods(optional_instance_methods, &mut ext_cur),
            optional_class_methods: self.load_methods(optional_class_methods, &mut ext_cur),
            properties: self.load_properties(instance_properties),
        };
        self.protocols_by_address.insert(address, p);
        Some(name)
    }

    fn load_categories(&mut self) -> Vec<Category> {
        let mut cats = Vec::new();
        let sect = match self.section_by_name("__objc_catlist") {
            Some(s) => s.clone(),
            None => return cats,
        };
        let ptr = self.macho.ptr_size() as u64;
        let count = sect.size / ptr;
        for i in 0..count {
            let addr = sect.addr + i * ptr;
            if let Some(mut cur) = self.cursor_at(addr) {
                let cat_ptr = cur.read_ptr();
                if let Some(c) = self.load_category_at(cat_ptr) {
                    cats.push(c);
                }
            }
        }
        cats
    }

    fn load_category_at(&mut self, address: u64) -> Option<Category> {
        if address == 0 {
            return None;
        }
        let mut cur = self.cursor_at(address)?;
        let name_ptr = cur.read_ptr();
        let class_ptr = cur.read_ptr();
        let instance_methods = cur.read_ptr();
        let class_methods = cur.read_ptr();
        let protocols = cur.read_ptr();
        let instance_properties = cur.read_ptr();

        let mut category = Category::default();
        category.name = self.macho.string_at_address(name_ptr).unwrap_or_default();
        category.instance_methods = self.load_methods(instance_methods, &mut None);
        category.class_methods = self.load_methods(class_methods, &mut None);
        for paddr in self.protocol_address_list(protocols) {
            if let Some(n) = self.uniqued_protocol_name(paddr) {
                if !category.protocols.contains(&n) {
                    category.protocols.push(n);
                }
            }
        }
        category.properties = self.load_properties(instance_properties);

        let class_name_address = address + self.macho.ptr_size() as u64;
        if self.macho.has_relocation_entry_for_address(class_name_address) {
            category.class_name = self
                .macho
                .external_class_name_for_address(class_name_address)
                .unwrap_or_default();
        } else if class_ptr != 0 {
            category.class_name = self.read_superclass_name(class_ptr).unwrap_or_default();
        }

        Some(category)
    }
}

struct ClassRo {
    name: u64,
    base_methods: u64,
    base_protocols: u64,
    ivars: u64,
    base_properties: u64,
}
