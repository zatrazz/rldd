use std::path::Path;
use std::{fmt, fs, str};

use object::elf::*;
use object::read::elf::*;
use object::read::StringTable;
use object::Endianness;

use crate::arenatree;
use crate::depmode::*;
#[cfg(target_os = "linux")]
use crate::interp;
use crate::platform;
use crate::search_path;
#[cfg(target_os = "linux")]
use crate::system_dirs;

type DepsVec = Vec<String>;

// A parsed ELF object with the relevant informations:
// - ei_class/ei_data/ei_osabi: ElfXX_Ehdr fields used in system library paths resolution,
// - soname: DT_SONAME, if present.
// - rpath: DT_RPATH search list paths, if present.
// - runpatch: DT_RUNPATH search list paths, if present.
// - nodeflibs: set if DF_1_NODEFLIB from DT_FLAGS_1 is set.
#[derive(Debug)]
pub struct ElfInfo {
    pub ei_class: u8,
    pub ei_data: u8,
    pub ei_osabi: u8,
    pub e_machine: u16,

    pub interp: Option<String>,
    pub soname: Option<String>,
    pub rpath: search_path::SearchPathVec,
    pub runpath: search_path::SearchPathVec,
    pub nodeflibs: bool,
    pub is_musl: bool,

    pub deps: DepsVec,
}

// A resolved dependency, after ELF parsing.
#[derive(PartialEq, Clone, Debug)]
pub struct DepNode {
    pub path: Option<String>,
    pub name: String,
    pub mode: DepMode,
    pub found: bool,
}

impl arenatree::EqualString for DepNode {
    fn eqstr(&self, other: &String) -> bool {
        self.name == *other
    }
}

// The resolved binary dependency tree.
pub type DepTree = arenatree::ArenaTree<DepNode>;

// ELF Parsing routines.

fn parse_object(
    data: &[u8],
    origin: &str,
    platform: Option<&String>,
) -> Result<ElfInfo, &'static str> {
    let kind = match object::FileKind::parse(data) {
        Ok(file) => file,
        Err(_err) => return Err("Failed to parse file"),
    };

    match kind {
        object::FileKind::Elf32 => parse_elf32(data, origin, platform),
        object::FileKind::Elf64 => parse_elf64(data, origin, platform),
        _ => Err("Invalid object"),
    }
}

fn parse_elf32(
    data: &[u8],
    origin: &str,
    platform: Option<&String>,
) -> Result<ElfInfo, &'static str> {
    if let Some(elf) = FileHeader32::<Endianness>::parse(data).handle_err() {
        return parse_elf(elf, data, origin, platform);
    }
    Err("Invalid ELF32 object")
}

fn parse_elf64(
    data: &[u8],
    origin: &str,
    platform: Option<&String>,
) -> Result<ElfInfo, &'static str> {
    if let Some(elf) = FileHeader64::<Endianness>::parse(data).handle_err() {
        return parse_elf(elf, data, origin, platform);
    }
    Err("Invalid ELF64 object")
}

fn parse_elf<Elf: FileHeader<Endian = Endianness>>(
    elf: &Elf,
    data: &[u8],
    origin: &str,
    platform: Option<&String>,
) -> Result<ElfInfo, &'static str> {
    let endian = match elf.endian() {
        Ok(val) => val,
        Err(_) => return Err("invalid endianess"),
    };

    match elf.e_type(endian) {
        ET_EXEC | ET_DYN => parse_header_elf(endian, elf, data, origin, platform),
        _ => Err("Invalid ELF file"),
    }
}

trait HandleErr<T> {
    fn handle_err(self) -> Option<T>;
}

impl<T, E: fmt::Display> HandleErr<T> for Result<T, E> {
    fn handle_err(self) -> Option<T> {
        match self {
            Ok(val) => Some(val),
            _ => None,
        }
    }
}

fn parse_header_elf<Elf: FileHeader<Endian = Endianness>>(
    endian: Elf::Endian,
    elf: &Elf,
    data: &[u8],
    origin: &str,
    platform: Option<&String>,
) -> Result<ElfInfo, &'static str> {
    match elf.program_headers(endian, data) {
        Ok(segments) => parse_elf_program_headers(endian, data, elf, segments, origin, platform),
        Err(_) => Err("invalid segment"),
    }
}

#[cfg(target_os = "linux")]
fn handle_loader(elc: &mut ElfInfo) {
    elc.is_musl = interp::is_musl(&elc.interp)
}
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
fn handle_loader(_elc: &mut ElfInfo) {}

fn parse_elf_program_headers<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    headers: &[Elf::ProgramHeader],
    origin: &str,
    platform: Option<&String>,
) -> Result<ElfInfo, &'static str> {
    match parse_elf_dynamic_program_header(endian, data, elf, headers, origin, platform) {
        Ok(mut elc) => {
            elc.interp = parse_elf_interp::<Elf>(endian, data, headers);
            handle_loader(&mut elc);
            return Ok(elc);
        }
        Err(e) => Err(e),
    }
}

fn parse_elf_interp<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    headers: &[Elf::ProgramHeader],
) -> Option<String> {
    match headers.iter().find(|&hdr| hdr.p_type(endian) == PT_INTERP) {
        Some(hdr) => {
            let offset = hdr.p_offset(endian).into() as usize;
            let fsize = hdr.p_filesz(endian).into() as usize;
            str::from_utf8(&data[offset..offset + fsize])
                .ok()
                .map(|s| s.trim_matches(char::from(0)).to_string())
        }
        None => None,
    }
}

fn parse_elf_dynamic_program_header<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    headers: &[Elf::ProgramHeader],
    origin: &str,
    platform: Option<&String>,
) -> Result<ElfInfo, &'static str> {
    match headers
        .iter()
        .find(|&&hdr| hdr.p_type(endian) == PT_DYNAMIC)
    {
        Some(hdr) => parse_elf_segment_dynamic(endian, data, elf, headers, hdr, origin, platform),
        None => Err("No dynamic segments found"),
    }
}

fn parse_elf_segment_dynamic<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segments: &[Elf::ProgramHeader],
    segment: &Elf::ProgramHeader,
    origin: &str,
    platform: Option<&String>,
) -> Result<ElfInfo, &'static str> {
    if let Ok(Some(dynamic)) = segment.dynamic(endian, data) {
        let mut strtab = 0;
        let mut strsz = 0;

        // To obtain the DT_NEEDED name we first need to find the DT_STRTAB/DT_STRSZ.
        dynamic.iter().for_each(|d| {
            let tag = d.d_tag(endian).into();
            if tag == DT_STRTAB.into() {
                strtab = d.d_val(endian).into();
            } else if tag == DT_STRSZ.into() {
                strsz = d.d_val(endian).into();
            }
        });

        let dynstr = match parse_elf_stringtable::<Elf>(endian, data, segments, strtab, strsz) {
            Some(dynstr) => dynstr,
            None => return Err("Failure to parse the string table"),
        };

        let df_1_nodeflib = u64::from(DF_1_NODEFLIB);
        let dt_flags_1 = parse_elf_dyn_flags::<Elf>(endian, DT_FLAGS_1, dynamic);
        let nodeflibs = dt_flags_1 & df_1_nodeflib == df_1_nodeflib;

        return match parse_elf_dtneeded::<Elf>(endian, dynamic, dynstr) {
            Ok(dtneeded) => Ok(ElfInfo {
                ei_class: elf.e_ident().class,
                ei_data: elf.e_ident().data,
                ei_osabi: elf.e_ident().os_abi,
                e_machine: elf.e_machine(endian),
                interp: None,
                soname: parse_elf_dyn_str::<Elf>(endian, DT_SONAME, dynamic, dynstr),
                rpath: parse_elf_dyn_searchpath(
                    endian, elf, DT_RPATH, dynamic, dynstr, origin, platform,
                ),
                runpath: parse_elf_dyn_searchpath(
                    endian, elf, DT_RUNPATH, dynamic, dynstr, origin, platform,
                ),
                nodeflibs: nodeflibs,
                deps: dtneeded,
                is_musl: false,
            }),
            Err(e) => Err(e),
        };
    }
    Err("Failure to parse dynamic segment")
}

fn parse_elf_stringtable<'a, Elf: FileHeader>(
    endian: Elf::Endian,
    data: &'a [u8],
    segments: &'a [Elf::ProgramHeader],
    strtab: u64,
    strsz: u64,
) -> Option<StringTable<'a>> {
    for s in segments {
        if let Ok(Some(data)) = s.data_range(endian, data, strtab, strsz) {
            return Some(StringTable::new(data, 0, data.len() as u64));
        }
    }
    None
}

fn parse_elf_dyn_str<Elf: FileHeader>(
    endian: Elf::Endian,
    tag: u32,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
) -> Option<String> {
    for d in dynamic {
        if d.d_tag(endian).into() == DT_NULL.into() {
            break;
        }

        if d.tag32(endian).is_none() || d.d_tag(endian).into() != tag.into() {
            continue;
        }

        if let Ok(s) = d.string(endian, dynstr) {
            if let Ok(s) = str::from_utf8(s) {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn replace_dyn_str(dynstr: &String, token: &str, value: &str) -> String {
    let newdynstr = dynstr.replace(&format!("${}", token), value);
    // Also handle ${token}
    newdynstr.replace(&format!("${{{}}}", token), value)
}

#[cfg(target_os = "linux")]
fn parse_elf_dyn_searchpath_lib<Elf: FileHeader>(
    endian: Elf::Endian,
    elf: &Elf,
    dynstr: &mut String,
) {
    let libdir = system_dirs::get_slibdir(elf.e_machine(endian), elf.e_ident().class).unwrap();
    *dynstr = replace_dyn_str(dynstr, "LIB", libdir);
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
fn parse_elf_dyn_searchpath_lib<Elf: FileHeader>(
    _endian: Elf::Endian,
    _elf: &Elf,
    _dynstr: &mut String,
) {
}

fn parse_elf_dyn_searchpath<Elf: FileHeader>(
    endian: Elf::Endian,
    elf: &Elf,
    tag: u32,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
    origin: &str,
    platform: Option<&String>,
) -> search_path::SearchPathVec {
    if let Some(dynstr) = parse_elf_dyn_str::<Elf>(endian, tag, dynamic, dynstr) {
        // EXpand $ORIGIN, $LIB, and $PLATFORM.
        let mut newdynstr = replace_dyn_str(&dynstr, "ORIGIN", origin);

        parse_elf_dyn_searchpath_lib(endian, elf, &mut newdynstr);

        let platform = match platform {
            Some(platform) => platform.to_string(),
            None => platform::get(elf.e_machine(endian), elf.e_ident().data),
        };
        let newdynstr = replace_dyn_str(&newdynstr, "$PLATFORM", platform.as_str());

        return search_path::from_string(newdynstr.as_str(), &[':']);
    }
    search_path::SearchPathVec::new()
}

fn parse_elf_dtneeded<Elf: FileHeader>(
    endian: Elf::Endian,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
) -> Result<DepsVec, &'static str> {
    let mut dtneeded = DepsVec::new();
    for d in dynamic {
        if d.d_tag(endian).into() == DT_NULL.into() {
            break;
        }

        if d.tag32(endian).is_none()
            || !d.is_string(endian)
            || d.d_tag(endian).into() != DT_NEEDED.into()
        {
            continue;
        }

        match d.string(endian, dynstr) {
            Err(_) => continue,
            Ok(s) => {
                if let Ok(s) = str::from_utf8(s) {
                    dtneeded.push(s.to_string());
                }
            }
        }
    }
    Ok(dtneeded)
}

fn parse_elf_dyn_flags<Elf: FileHeader>(
    endian: Elf::Endian,
    tag: u32,
    dynamic: &[Elf::Dyn],
) -> u64 {
    for d in dynamic {
        if d.d_tag(endian).into() == DT_NULL.into() {
            break;
        }

        if d.tag32(endian).is_none() || d.d_tag(endian).into() != tag.into() {
            continue;
        }

        return d.d_val(endian).into();
    }
    0
}

pub fn open_elf_file<'a, P: AsRef<Path>>(
    filename: &P,
    melc: Option<&ElfInfo>,
    dtneeded: Option<&String>,
    platform: Option<&String>,
) -> Result<ElfInfo, &'static str> {
    let file = match fs::File::open(&filename) {
        Ok(file) => file,
        Err(_) => return Err("Failed to open file"),
    };

    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return Err("Failed to map file"),
    };

    let parent = match filename.as_ref().parent().and_then(Path::to_str) {
        Some(parent) => parent,
        None => "",
    };

    match parse_object(&*mmap, parent, platform) {
        Ok(elc) => {
            if let Some(melc) = melc {
                if !match_elf_name(melc, dtneeded, &elc) {
                    return Err("Error parsing ELF object");
                }
            }
            Ok(elc)
        }
        Err(e) => Err(e),
    }
}

fn match_elf_name(melc: &ElfInfo, dtneeded: Option<&String>, elc: &ElfInfo) -> bool {
    if !check_elf_header(&elc) || !match_elf_header(&melc, &elc) {
        return false;
    }

    // If DT_SONAME is defined compare against it.
    if let Some(dtneeded) = dtneeded {
        return match_elf_soname(dtneeded, elc);
    };

    true
}

#[cfg(target_os = "linux")]
fn check_elf_header(elc: &ElfInfo) -> bool {
    // TODO: ARM also accepts ELFOSABI_SYSV
    elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_GNU
}
#[cfg(target_os = "freebsd")]
fn check_elf_header(elc: &ElfInfo) -> bool {
    elc.ei_osabi == ELFOSABI_FREEBSD
}
#[cfg(target_os = "openbsd")]
fn check_elf_header(elc: &ElfInfo) -> bool {
    elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_OPENBSD
}

fn match_elf_header(a1: &ElfInfo, a2: &ElfInfo) -> bool {
    a1.ei_class == a2.ei_class && a1.ei_data == a2.ei_data && a1.e_machine == a2.e_machine
}

fn match_elf_soname(dtneeded: &String, elc: &ElfInfo) -> bool {
    let soname = &elc.soname;
    if let Some(soname) = soname {
        return dtneeded == soname;
    }
    true
}
