use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::{env, fmt, fs, process, str};

use object::elf::*;
use object::read::elf::*;
use object::read::StringTable;
use object::Endianness;

mod ld_conf;
mod search_path;

struct Config {
    ld_library_path: search_path::SearchPathVec,
    ld_so_conf: search_path::SearchPathVec,
    system_dirs: search_path::SearchPathVec,
}

type DtNeededVec = Vec<String>;

struct ElfLoaderConf {
    ei_class: u8,
    ei_data: u8,
    ei_osabi: u8,
    e_machine: u16,

    soname: Option<String>,
    rpath: search_path::SearchPathVec,
    runpath: search_path::SearchPathVec,
    dtneeded: DtNeededVec,
}

// Keep track of DT_NEEDED already found.
type DtNeededSet = HashSet<String>;

#[derive(PartialEq)]
enum DtNeededMode {
    DtRpath,
    LdLibraryPath,
    DtRunpath,
    LdSoConf,
    SystemDirs,
    NotFound,
}

fn parse_object(data: &[u8], origin: &str) -> Result<ElfLoaderConf, &'static str> {
    let kind = match object::FileKind::parse(data) {
        Ok(file) => file,
        Err(_err) => return Err("Failed to parse file"),
    };

    match kind {
        object::FileKind::Elf32 => parse_elf32(data, origin),
        object::FileKind::Elf64 => parse_elf64(data, origin),
        _ => Err("Invalid object"),
    }
}

fn parse_elf32(data: &[u8], origin: &str) -> Result<ElfLoaderConf, &'static str> {
    if let Some(elf) = FileHeader32::<Endianness>::parse(data).handle_err() {
        return parse_elf(elf, data, origin);
    }
    Err("Invalid ELF32 object")
}

fn parse_elf64(data: &[u8], origin: &str) -> Result<ElfLoaderConf, &'static str> {
    if let Some(elf) = FileHeader64::<Endianness>::parse(data).handle_err() {
        return parse_elf(elf, data, origin);
    }
    Err("Invalid ELF64 object")
}

fn parse_elf<Elf: FileHeader<Endian = Endianness>>(
    elf: &Elf,
    data: &[u8],
    origin: &str,
) -> Result<ElfLoaderConf, &'static str> {
    let endian = match elf.endian() {
        Ok(val) => val,
        Err(_) => return Err("invalid endianess"),
    };

    match elf.e_type(endian) {
        ET_EXEC | ET_DYN => parse_header_elf(endian, elf, data, origin),
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
) -> Result<ElfLoaderConf, &'static str> {
    match elf.program_headers(endian, data) {
        Ok(segments) => parse_elf_program_headers(endian, data, elf, segments, origin),
        Err(_) => Err("invalid segment"),
    }
}

fn parse_elf_program_headers<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segments: &[Elf::ProgramHeader],
    origin: &str,
) -> Result<ElfLoaderConf, &'static str> {
    match segments
        .iter()
        .find(|&&seg| seg.p_type(endian) == PT_DYNAMIC)
    {
        Some(seg) => parse_elf_segment_dynamic(endian, data, elf, segments, seg, origin),
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
) -> Result<ElfLoaderConf, &'static str> {
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

        let dynstr = match parse_elf_stringtable(endian, data, elf, segments, strtab, strsz) {
            Some(dynstr) => dynstr,
            None => return Err("Failure to parse the string table"),
        };

        return match parse_elf_dtneeded::<Elf>(endian, dynamic, dynstr) {
            Ok(dtneeded) => Ok(ElfLoaderConf {
                ei_class: elf.e_ident().class,
                ei_data: elf.e_ident().data,
                ei_osabi: elf.e_ident().os_abi,
                e_machine: elf.e_machine(endian),
                soname: parse_elf_dyn_str::<Elf>(endian, DT_SONAME, dynamic, dynstr),
                rpath: parse_elf_dyn_searchpath(endian, elf, DT_RPATH, dynamic, dynstr, origin),
                runpath: parse_elf_dyn_searchpath(endian, elf, DT_RUNPATH, dynamic, dynstr, origin),
                dtneeded: dtneeded,
            }),
            Err(e) => Err(e),
        };
    }
    Err("Failure to parse dynamic segment")
}

fn parse_elf_stringtable<'a, Elf: FileHeader>(
    endian: Elf::Endian,
    data: &'a [u8],
    _elf: &Elf,
    segments: &'a [Elf::ProgramHeader],
    strtab: u64,
    strsz: u64
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

fn parse_elf_dyn_searchpath<Elf: FileHeader>(
    endian: Elf::Endian,
    elf: &Elf,
    tag: u32,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
    origin: &str,
) -> search_path::SearchPathVec {
    if let Some(dynstr) = parse_elf_dyn_str::<Elf>(endian, tag, dynamic, dynstr) {
        // Replace $ORIGIN and $LIB
        // TODO: Add $PLATFORM support.
        let newdynstr = dynstr.replace("$ORIGIN", origin);

        let libdir = search_path::get_slibdir(
            elf.e_machine(endian),
            elf.e_ident().class).unwrap();
        let newdynstr = newdynstr.replace("$LIB", libdir);

        return search_path::from_string(newdynstr.as_str());
    }
    search_path::SearchPathVec::new()
}

fn parse_elf_dtneeded<Elf: FileHeader>(
    endian: Elf::Endian,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
) -> Result<DtNeededVec, &'static str> {
    let mut dtneeded = DtNeededVec::new();
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

fn print_dependencies(
    config: &Config,
    elc: &ElfLoaderConf,
    dtneededset: &mut DtNeededSet,
    idx: usize,
) {
    for entry in &elc.dtneeded {
        resolve_dependency(&entry, &config, &elc, dtneededset, idx);
    }
}

fn resolve_dependency(
    dtneeded: &String,
    config: &Config,
    elc: &ElfLoaderConf,
    dtneededset: &mut DtNeededSet,
    idx: usize,
) {
    if dtneededset.contains(dtneeded) {
        return;
    }

    let (r, path, mode) = resolve_dependency_1(dtneeded, config, elc);
    if mode != DtNeededMode::NotFound {
        dtneededset.insert(dtneeded.to_string());

        let modestr = match mode {
            DtNeededMode::DtRpath => "rpath",
            DtNeededMode::LdLibraryPath => "LD_LIBRARY_PATH",
            DtNeededMode::DtRunpath => "runpath",
            DtNeededMode::LdSoConf => "ld.so.conf",
            DtNeededMode::SystemDirs => "system default paths",
            DtNeededMode::NotFound => "not found",
        };
        println!(
            "{:>width$}{} => {} ({})",
            "",
            dtneeded,
            path.unwrap().display(),
            modestr,
            width = idx
        );
        let nextidx = idx + 2;
        print_dependencies(&config, &r.unwrap(), dtneededset, nextidx);
    } else {
        println!("{:>width$}{} (not found)", "", dtneeded, width = idx);
    }
}

fn resolve_dependency_1<'a>(
    dtneeded: &String,
    config: &Config,
    elc: &ElfLoaderConf,
) -> (Option<ElfLoaderConf>, Option<PathBuf>, DtNeededMode) {
    // Consider DT_RPATH iff DT_RUNPATH is not set
    if elc.runpath.is_empty() {
        for searchpath in &elc.rpath {
            let path = Path::new(&searchpath.path).join(dtneeded);
            if let Ok(r) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
                return (
                    Some(r),
                    Some(path.to_path_buf()),
                    DtNeededMode::DtRpath);
            }
        }
    }

    // Check LD_LIBRARY_PATH paths.
    for searchpath in &config.ld_library_path {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(r) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
            return (
                Some(r),
                Some(path.to_path_buf()),
                DtNeededMode::LdLibraryPath,
            );
        }
    }

    // Check DT_RUNPATH.
    for searchpath in &elc.runpath {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(r) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
            return (
                Some(r),
                Some(path.to_path_buf()),
                DtNeededMode::DtRunpath);
        }
    }

    // Check the cached search paths from ld.so.conf.
    for searchpath in &config.ld_so_conf {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(r) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
            return (Some(r), Some(path.to_path_buf()), DtNeededMode::LdSoConf);
        }
    }

    // Finally the system directories.
    for searchpath in &config.system_dirs {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(r) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
            return (Some(r), Some(path.to_path_buf()), DtNeededMode::SystemDirs);
        }
    }

    (None, None, DtNeededMode::NotFound)
}

fn open_elf_file<P: AsRef<Path>>(
    filename: &P,
    melc: Option<&ElfLoaderConf>,
    dtneeded: Option<&String>,
) -> Result<ElfLoaderConf, &'static str> {
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
        None => ""
    };

    match parse_object(&*mmap, parent) {
        Ok(elc) => {
            if let Some(melc) = melc {
                if !match_elf_name(melc, dtneeded, &elc) {
                    return Err("Error parsing ELF object");
                }
            }
            Ok(elc)
        },
        Err(e) => Err(e),
    }
}

fn match_elf_name(
    melc: &ElfLoaderConf,
    dtneeded: Option<&String>,
    elc: &ElfLoaderConf
) -> bool {
    if !check_elf_header(&elc) || !match_elf_header(&melc, &elc) {
        return false;
    }

    // If DT_SONAME is defined compare against it.
    if let Some(dtneeded) = dtneeded {
        return match_elf_soname(dtneeded, elc);
    };

    true
}

fn check_elf_header(elc: &ElfLoaderConf) -> bool {
    // TODO: ARM also accepts ELFOSABI_SYSV
    elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_GNU
}

fn match_elf_header(a1: &ElfLoaderConf, a2: &ElfLoaderConf) -> bool {
    a1.ei_class == a2.ei_class && a1.ei_data == a2.ei_data && a1.e_machine == a2.e_machine
}

fn match_elf_soname(dtneeded: &String, elc: &ElfLoaderConf) -> bool {
    let soname = &elc.soname;
    if let Some(soname) = soname {
        return dtneeded == soname;
    }
    true
}

fn main() {
    let mut args = env::args();
    let cmd = args.next().unwrap();
    if args.len() == 0 {
        eprintln!("Usage {} file", cmd);
        process::exit(1);
    }
    let filename = args.next().unwrap();

    let ld_so_conf = match ld_conf::parse_ld_so_conf(&Path::new("/etc/ld.so.conf")) {
        Ok(ld_so_conf) => ld_so_conf,
        Err(err) => {
            eprintln!("Failed to read loader cache config: {}", err,);
            process::exit(1);
        }
    };

    let elc = match open_elf_file(&filename, None, None) {
        Ok(elc) => elc,
        Err(err) => {
            eprintln!("Faile to read file '{}': {}", filename, err,);
            process::exit(1);
        }
    };

    let system_dirs = match search_path::get_system_dirs(elc.e_machine, elc.ei_class) {
        Some(r) => r,
        None => {
            eprintln!("Invalid ELF architcture");
            process::exit(1);
        }
    };

    let config = Config {
        ld_library_path: search_path::get_ld_library_path(),
        ld_so_conf: ld_so_conf,
        system_dirs: system_dirs,
    };

    print_dependencies(&config, &elc, &mut DtNeededSet::new(), 0)
}
