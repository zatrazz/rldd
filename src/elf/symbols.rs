// Parse the dynamic symbol table and the dynamic relocations of an ELF object.
// It is used to mimic the loader symbol resolution for the --data-relocs,
// --function-relocs, and --unused options.

use std::collections::HashSet;
use std::path::Path;
use std::str;

use object::elf::*;
use object::read::elf::{
    Dyn, FileHeader, ProgramHeader, Rel, Rela, SectionHeader, SectionTable, Sym, SymbolTable,
    VersionTable,
};
use object::read::SymbolIndex;
use object::Endianness;

// An undefined symbol referenced by a dynamic relocation.
#[derive(Debug)]
pub struct SymbolRef {
    pub name: String,
    // The required symbol version, from the .gnu.version information.
    pub version: Option<String>,
    // Whether the reference is weak (unresolved weak symbols are not an error).
    pub weak: bool,
    // Whether the relocation comes from the DT_JMPREL table (function/PLT
    // relocation, only processed in bind-now mode by the loader).
    pub plt: bool,
}

// A version required from a dependency, from the .gnu.version_r information.
#[derive(Debug)]
pub struct VersionNeed {
    // The dependency file name (vn_file).
    pub file: String,
    pub version: String,
    // Weak version references (VER_FLG_WEAK) are not an error.
    pub weak: bool,
}

#[derive(Debug, Default)]
pub struct ObjectSymbols {
    // Global visible defined symbols, candidates to resolve other objects
    // undefined references.
    pub defined: HashSet<String>,
    // Defined symbols along their version definition.
    pub defined_versioned: HashSet<(String, String)>,
    // Whether the object defines any version (.gnu.version_d presence).
    pub has_verdef: bool,
    // The version names the object defines.
    pub verdef_names: HashSet<String>,
    // The versions the object requires from its dependencies.
    pub verneeded: Vec<VersionNeed>,
    // Undefined symbols referenced by the object dynamic relocations.
    pub references: Vec<SymbolRef>,
    // Whether the object sets DF_BIND_NOW/DF_1_NOW, which makes the loader
    // also process the PLT relocations in --data-relocs mode.
    pub bind_now: bool,
}

pub fn parse<P: AsRef<Path>>(filename: &P) -> Option<ObjectSymbols> {
    let file = std::fs::File::open(filename).ok()?;
    let mmap = unsafe { memmap2::Mmap::map(&file) }.ok()?;
    let data: &[u8] = &mmap;

    match object::FileKind::parse(data).ok()? {
        object::FileKind::Elf32 => parse_elf(FileHeader32::<Endianness>::parse(data).ok()?, data),
        object::FileKind::Elf64 => parse_elf(FileHeader64::<Endianness>::parse(data).ok()?, data),
        _ => None,
    }
}

fn parse_elf<Elf: FileHeader<Endian = Endianness>>(elf: &Elf, data: &[u8]) -> Option<ObjectSymbols> {
    let endian = elf.endian().ok()?;

    let sections = elf.sections(endian, data).ok()?;
    let dynsyms = sections.symbols(endian, data, SHT_DYNSYM).ok()?;
    let versions = sections.versions(endian, data).ok().flatten();

    let mut obj = ObjectSymbols::default();

    parse_verdef(&mut obj, endian, &sections, data);
    parse_verneed(&mut obj, endian, &sections, data);

    for (symidx, sym) in dynsyms.enumerate() {
        if sym.st_shndx(endian) == SHN_UNDEF {
            continue;
        }
        let bind = sym.st_bind();
        if bind != STB_GLOBAL && bind != STB_WEAK && bind != STB_GNU_UNIQUE {
            continue;
        }
        // Hidden and internal symbols do not participate in the dynamic
        // resolution of other objects.
        let visibility = sym.st_visibility();
        if visibility != STV_DEFAULT && visibility != STV_PROTECTED {
            continue;
        }
        if let Some(name) = symbol_name(endian, &dynsyms, sym) {
            obj.defined.insert(name.to_string());
            if let Some(version) = symbol_version(endian, &versions, symidx) {
                obj.defined_versioned.insert((name.to_string(), version));
            }
        }
    }

    // The address of the PLT relocation table, used to distinguish function
    // relocations from data ones, and the object bind-now state.
    let dyninfo = parse_dynamic_info(endian, elf, data);
    let jmprel = dyninfo.jmprel;
    obj.bind_now = dyninfo.bind_now;
    let is_mips64el = elf.is_mips64el(endian);

    // Track already seen references to avoid reporting a symbol multiple times
    // for the same object.
    let mut seen = HashSet::<(String, bool)>::new();

    for section in sections.iter() {
        // The loader only processes the allocated relocation tables.
        if !section.sh_flags(endian).contains(SHF_ALLOC) {
            continue;
        }
        let plt = jmprel.is_some_and(|addr| section.sh_addr(endian).into() == addr);

        if let Ok(Some((relas, _link))) = section.rela(endian, data) {
            for rela in relas {
                add_reference(
                    endian,
                    &dynsyms,
                    &versions,
                    rela.symbol(endian, is_mips64el),
                    plt,
                    &mut seen,
                    &mut obj.references,
                );
            }
        } else if let Ok(Some((rels, _link))) = section.rel(endian, data) {
            for rel in rels {
                add_reference(
                    endian,
                    &dynsyms,
                    &versions,
                    rel.symbol(endian),
                    plt,
                    &mut seen,
                    &mut obj.references,
                );
            }
        }
    }

    Some(obj)
}

fn symbol_name<'data, Elf: FileHeader>(
    endian: Elf::Endian,
    dynsyms: &SymbolTable<'data, Elf, &'data [u8]>,
    sym: &Elf::Sym,
) -> Option<&'data str> {
    let name = dynsyms.symbol_name(endian, sym).ok()?;
    let name = str::from_utf8(name).ok()?;
    if name.is_empty() {
        return None;
    }
    Some(name)
}

#[allow(clippy::too_many_arguments)]
fn add_reference<'data, Elf: FileHeader>(
    endian: Elf::Endian,
    dynsyms: &SymbolTable<'data, Elf, &'data [u8]>,
    versions: &Option<VersionTable<'data, Elf>>,
    symidx: Option<SymbolIndex>,
    plt: bool,
    seen: &mut HashSet<(String, bool)>,
    references: &mut Vec<SymbolRef>,
) {
    let Some(symidx) = symidx else {
        return;
    };
    let Ok(sym) = dynsyms.symbol(symidx) else {
        return;
    };
    // Only undefined symbols require a lookup on the loaded objects scope.
    if sym.st_shndx(endian) != SHN_UNDEF {
        return;
    }
    let Some(name) = symbol_name(endian, dynsyms, sym) else {
        return;
    };
    if seen.insert((name.to_string(), plt)) {
        references.push(SymbolRef {
            name: name.to_string(),
            version: symbol_version(endian, versions, symidx),
            weak: sym.st_bind() == STB_WEAK,
            plt,
        });
    }
}

fn symbol_version<'data, Elf: FileHeader>(
    endian: Elf::Endian,
    versions: &Option<VersionTable<'data, Elf>>,
    symidx: SymbolIndex,
) -> Option<String> {
    let versions = versions.as_ref()?;
    let version = versions
        .version(versions.version_index(endian, symidx).index())
        .ok()??;
    str::from_utf8(version.name()).ok().map(|s| s.to_string())
}

fn parse_verdef<'data, Elf: FileHeader>(
    obj: &mut ObjectSymbols,
    endian: Elf::Endian,
    sections: &SectionTable<'data, Elf, &'data [u8]>,
    data: &'data [u8],
) {
    let Ok(Some((mut verdefs, link))) = sections.gnu_verdef(endian, data) else {
        return;
    };
    let Ok(strings) = sections.strings(endian, data, link) else {
        return;
    };
    while let Ok(Some((verdef, mut verdauxs))) = verdefs.next() {
        obj.has_verdef = true;
        // The base version is the object name itself, not a symbol version.
        if verdef.vd_flags.get(endian).contains(VER_FLG_BASE) {
            continue;
        }
        if let Ok(Some(verdaux)) = verdauxs.next() {
            if let Some(name) = verdaux
                .name(endian, strings)
                .ok()
                .and_then(|name| str::from_utf8(name).ok())
            {
                obj.verdef_names.insert(name.to_string());
            }
        }
    }
}

fn parse_verneed<'data, Elf: FileHeader>(
    obj: &mut ObjectSymbols,
    endian: Elf::Endian,
    sections: &SectionTable<'data, Elf, &'data [u8]>,
    data: &'data [u8],
) {
    let Ok(Some((mut verneeds, link))) = sections.gnu_verneed(endian, data) else {
        return;
    };
    let Ok(strings) = sections.strings(endian, data, link) else {
        return;
    };
    while let Ok(Some((verneed, mut vernauxs))) = verneeds.next() {
        let Some(file) = verneed
            .file(endian, strings)
            .ok()
            .and_then(|file| str::from_utf8(file).ok())
        else {
            continue;
        };
        while let Ok(Some(vernaux)) = vernauxs.next() {
            if let Some(version) = vernaux
                .name(endian, strings)
                .ok()
                .and_then(|name| str::from_utf8(name).ok())
            {
                obj.verneeded.push(VersionNeed {
                    file: file.to_string(),
                    version: version.to_string(),
                    weak: vernaux.vna_flags.get(endian).contains(VER_FLG_WEAK),
                });
            }
        }
    }
}

struct DynamicInfo {
    jmprel: Option<u64>,
    bind_now: bool,
}

fn parse_dynamic_info<Elf: FileHeader>(
    endian: Elf::Endian,
    elf: &Elf,
    data: &[u8],
) -> DynamicInfo {
    let mut r = DynamicInfo {
        jmprel: None,
        bind_now: false,
    };
    let Ok(headers) = elf.program_headers(endian, data) else {
        return r;
    };
    let Some(segment) = headers
        .iter()
        .find(|&&hdr| hdr.p_type(endian) == PT_DYNAMIC)
    else {
        return r;
    };
    let Ok(Some(dynamic)) = segment.dynamic(endian, data) else {
        return r;
    };
    for d in dynamic {
        let tag = d.d_tag(endian);
        if tag == DT_NULL {
            break;
        }
        if tag == DT_JMPREL {
            r.jmprel = Some(d.d_val(endian).into());
        } else if tag == DT_BIND_NOW {
            r.bind_now = true;
        } else if tag == DT_FLAGS {
            r.bind_now |= DynamicFlags(d.d_val(endian).into()).contains(DF_BIND_NOW);
        } else if tag == DT_FLAGS_1 {
            r.bind_now |= DynamicFlags1(d.d_val(endian).into()).contains(DF_1_NOW);
        }
    }
    r
}
