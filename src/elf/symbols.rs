// Parse the dynamic symbol table and the dynamic relocations of an ELF object.
// It is used to mimic the loader symbol resolution for the --data-relocs,
// --function-relocs, and --unused options.

use std::collections::HashSet;
use std::path::Path;
use std::str;

use object::elf::*;
use object::read::elf::{Dyn, FileHeader, ProgramHeader, Rel, Rela, SectionHeader, Sym, SymbolTable};
use object::read::SymbolIndex;
use object::Endianness;

// An undefined symbol referenced by a dynamic relocation.
#[derive(Debug)]
pub struct SymbolRef {
    pub name: String,
    // Whether the reference is weak (unresolved weak symbols are not an error).
    pub weak: bool,
    // Whether the relocation comes from the DT_JMPREL table (function/PLT
    // relocation, only processed in bind-now mode by the loader).
    pub plt: bool,
}

#[derive(Debug, Default)]
pub struct ObjectSymbols {
    // Global visible defined symbols, candidates to resolve other objects
    // undefined references.
    pub defined: HashSet<String>,
    // Undefined symbols referenced by the object dynamic relocations.
    pub references: Vec<SymbolRef>,
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

    let mut obj = ObjectSymbols::default();

    for sym in dynsyms.iter() {
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
        }
    }

    // The address of the PLT relocation table, used to distinguish function
    // relocations from data ones.
    let jmprel = parse_dt_jmprel(endian, elf, data);
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

fn add_reference<'data, Elf: FileHeader>(
    endian: Elf::Endian,
    dynsyms: &SymbolTable<'data, Elf, &'data [u8]>,
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
            weak: sym.st_bind() == STB_WEAK,
            plt,
        });
    }
}

fn parse_dt_jmprel<Elf: FileHeader>(
    endian: Elf::Endian,
    elf: &Elf,
    data: &[u8],
) -> Option<u64> {
    let headers = elf.program_headers(endian, data).ok()?;
    let segment = headers
        .iter()
        .find(|&&hdr| hdr.p_type(endian) == PT_DYNAMIC)?;
    for d in segment.dynamic(endian, data).ok()?? {
        let tag = d.d_tag(endian);
        if tag == DT_NULL {
            break;
        }
        if tag == DT_JMPREL {
            return Some(d.d_val(endian).into());
        }
    }
    None
}
