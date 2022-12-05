use std::path::Path;
use std::{fmt, fs, process, str};

use object::elf::*;
use object::read::elf::*;
use object::read::StringTable;
use object::Endianness;

use argparse::{ArgumentParser, List, Store, StoreTrue};

mod arenatree;
#[cfg(target_os = "linux")]
mod interp;
#[cfg(target_os = "linux")]
mod ld_conf;
#[cfg(target_os = "freebsd")]
mod ld_hints;
mod platform;
mod printer;
mod search_path;
mod system_dirs;
use printer::*;

// Global configuration used on program dynamic resolution:
// - ld_preload: Search path parser from ld.so.preload
// - ld_library_path: Search path parsed from --ld-library-path.
// - ld_so_conf: paths parsed from the ld.so.conf in the system.
// - system_dirs: system defaults deirectories based on binary architecture.
struct Config<'a> {
    ld_preload: &'a search_path::SearchPathVec,
    ld_library_path: &'a search_path::SearchPathVec,
    ld_so_conf: &'a Option<search_path::SearchPathVec>,
    system_dirs: search_path::SearchPathVec,
    platform: Option<&'a String>,
    unique: bool,
}

type DepsVec = Vec<String>;

// A parsed ELF object with the relevant informations:
// - ei_class/ei_data/ei_osabi: ElfXX_Ehdr fields used in system library paths resolution,
// - soname: DT_SONAME, if present.
// - rpath: DT_RPATH search list paths, if present.
// - runpatch: DT_RUNPATH search list paths, if present.
// - nodeflibs: set if DF_1_NODEFLIB from DT_FLAGS_1 is set.
#[derive(Debug)]
struct ElfInfo {
    ei_class: u8,
    ei_data: u8,
    ei_osabi: u8,
    e_machine: u16,

    interp: Option<String>,
    soname: Option<String>,
    rpath: search_path::SearchPathVec,
    runpath: search_path::SearchPathVec,
    nodeflibs: bool,
    is_musl: bool,

    deps: DepsVec,
}

// The resolution mode for a dependency, used mostly for printing.
#[derive(PartialEq, Clone, Copy, Debug)]
enum DepMode {
    Preload,       // Preload library.
    Direct,        // DT_SONAME refers to an aboslute path.
    DtRpath,       // DT_RPATH.
    LdLibraryPath, // LD_LIBRARY_PATH.
    DtRunpath,     // DT_RUNPATH.
    LdSoConf,      // ld.so.conf.
    SystemDirs,    // Default system directory (i.e '/lib64').
    Executable,    // The root executable/library.
    NotFound,
}

impl fmt::Display for DepMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DepMode::Preload => write!(f, "[preload]"),
            DepMode::Direct => write!(f, "[direct]"),
            DepMode::DtRpath => write!(f, "[rpath]"),
            DepMode::LdLibraryPath => write!(f, "[LD_LIBRARY_PATH]"),
            DepMode::DtRunpath => write!(f, "[runpath]"),
            #[cfg(target_os = "linux")]
            DepMode::LdSoConf => write!(f, "[ld.so.conf]"),
            #[cfg(target_os = "freebsd")]
            DepMode::LdSoConf => write!(f, "[ld-elf.so.hints]"),
            DepMode::SystemDirs => write!(f, "[system default paths]"),
            DepMode::Executable => write!(f, ""),
            DepMode::NotFound => write!(f, "[not found]"),
        }
    }
}

// A resolved dependency, after ELF parsing.
#[derive(PartialEq, Clone, Debug)]
struct DepNode {
    path: Option<String>,
    name: String,
    mode: DepMode,
    found: bool,
}

impl arenatree::EqualString for DepNode {
    fn eqstr(&self, other: &String) -> bool {
        self.name == *other
    }
}

// The resolved binary dependency tree.
type DepTree = arenatree::ArenaTree<DepNode>;

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
#[cfg(target_os = "freebsd")]
fn handle_loader(_elc: &mut ElfInfo) {
}

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

#[cfg(target_os = "linux")]
fn parse_elf_dyn_searchpath_lib<Elf: FileHeader>(
    endian: Elf::Endian,
    elf: &Elf,
    dynstr: &mut String,
) {
    let libdir = system_dirs::get_slibdir(elf.e_machine(endian), elf.e_ident().class).unwrap();
    *dynstr = dynstr.replace("$LIB", libdir);
}

#[cfg(target_os = "freebsd")]
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
        let mut newdynstr = dynstr.replace("$ORIGIN", origin);

        parse_elf_dyn_searchpath_lib(endian, elf, &mut newdynstr);

        let platform = match platform {
            Some(platform) => platform.to_string(),
            None => platform::get(elf.e_machine(endian), elf.e_ident().data),
        };
        let newdynstr = newdynstr.replace("$PLATFORM", platform.as_str());

        return search_path::from_string(newdynstr.as_str());
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

// Function that mimic the dynamic loader resolution.
#[cfg(target_os = "linux")]
fn resolve_binary_arch(elc: &ElfInfo, deptree: &mut DepTree, depp: usize) {
    // musl loader and libc is on the same shared object, so adds a synthetic dependendy for
    // the binary so it is also shown and to be returned in case a objects has libc.so
    // as needed.
    if elc.is_musl {
        deptree.addnode(
            DepNode {
                path: interp::get_interp_path(&elc.interp),
                name: interp::get_interp_name(&elc.interp).unwrap().to_string(),
                mode: DepMode::SystemDirs,
                found: true,
            },
            depp,
        );
    }

}
#[cfg(target_os = "freebsd")]
fn resolve_binary_arch(_elc: &ElfInfo, _deptree: &mut DepTree, _depp: usize) {
}

fn resolve_binary(filename: &Path, config: &Config, elc: &ElfInfo) -> DepTree {
    let mut deptree = DepTree::new();

    let depp = deptree.addroot(DepNode {
        path: filename
            .parent()
            .and_then(|s| s.to_str())
            .and_then(|s| Some(s.to_string())),
        name: filename
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string(),
        mode: DepMode::Executable,
        found: false,
    });

    resolve_binary_arch(&elc, &mut deptree, depp);

    for ld_preload in config.ld_preload {
        resolve_dependency(&config, &ld_preload.path, &elc, &mut deptree, depp, true);
    }

    for dep in &elc.deps {
        resolve_dependency(&config, &dep, &elc, &mut deptree, depp, false);
    }

    deptree
}

// Returned from resolve_dependency_1 with resolved information.
struct ResolvedDependency<'a> {
    elc: ElfInfo,
    path: &'a String,
    mode: DepMode,
}

fn resolve_dependency(
    config: &Config,
    dependency: &String,
    elc: &ElfInfo,
    deptree: &mut DepTree,
    depp: usize,
    preload: bool,
) {
    if elc.is_musl && dependency == "libc.so" {
        return;
    }

    // If DF_1_NODEFLIB is set ignore the search cache in the case a dependency could
    // resolve the library.
    if !elc.nodeflibs {
        if let Some(entry) = deptree.get(dependency) {
            if !config.unique {
                deptree.addnode(
                    DepNode {
                        path: entry.path,
                        name: dependency.to_string(),
                        mode: entry.mode.clone(),
                        found: true,
                    },
                    depp,
                );
            }
            return;
        }
    }

    if let Some(dep) = resolve_dependency_1(dependency, config, elc, preload) {
        let c = deptree.addnode(
            DepNode {
                path: Some(dep.path.to_string()),
                name: dependency.to_string(),
                mode: dep.mode,
                found: false,
            },
            depp,
        );

        let elc = &dep.elc;
        for dep in &elc.deps {
            resolve_dependency(&config, &dep, &elc, deptree, c, preload);
        }
    } else {
        deptree.addnode(
            DepNode {
                path: None,
                name: dependency.to_string(),
                mode: DepMode::NotFound,
                found: false,
            },
            depp,
        );
    }
}

fn resolve_dependency_1<'a>(
    dtneeded: &'a String,
    config: &'a Config,
    elc: &'a ElfInfo,
    preload: bool,
) -> Option<ResolvedDependency<'a>> {
    let path = Path::new(&dtneeded);

    // If the path is absolute skip the other modes.
    if path.is_absolute() {
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
            return Some(ResolvedDependency {
                elc: elc,
                path: dtneeded,
                mode: if preload {
                    DepMode::Preload
                } else {
                    DepMode::Direct
                },
            });
        }
        return None;
    }

    // Consider DT_RPATH iff DT_RUNPATH is not set.
    if elc.runpath.is_empty() {
        for searchpath in &elc.rpath {
            let path = Path::new(&searchpath.path).join(dtneeded);
            if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
                return Some(ResolvedDependency {
                    elc: elc,
                    path: &searchpath.path,
                    mode: DepMode::DtRpath,
                });
            }
        }
    }

    // Check LD_LIBRARY_PATH paths.
    for searchpath in config.ld_library_path {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: DepMode::LdLibraryPath,
            });
        }
    }

    // Check DT_RUNPATH.
    for searchpath in &elc.runpath {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: DepMode::DtRunpath,
            });
        }
    }

    // Skip system paths if DF_1_NODEFLIB is set.
    if elc.nodeflibs {
        return None;
    }

    // Check the cached search paths from ld.so.conf
    if let Some(ld_so_conf) = config.ld_so_conf {
        for searchpath in ld_so_conf {
            let path = Path::new(&searchpath.path).join(dtneeded);
            if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
                return Some(ResolvedDependency {
                    elc: elc,
                    path: &searchpath.path,
                    mode: DepMode::LdSoConf,
                });
            }
        }
    }

    // Finally the system directories.
    for searchpath in &config.system_dirs {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: DepMode::SystemDirs,
            });
        }
    }

    None
}

fn open_elf_file<'a, P: AsRef<Path>>(
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

#[cfg(target_os = "linux")]
fn load_so_conf(interp: &Option<String>) -> Option<search_path::SearchPathVec> {
    if interp::is_glibc(interp) {
        match ld_conf::parse_ld_so_conf(&Path::new("/etc/ld.so.conf")) {
            Ok(ld_so_conf) => return Some(ld_so_conf),
            Err(err) => {
                eprintln!("Failed to read loader cache config: {}", err);
                process::exit(1);
            }
        }
    }
    None
}
#[cfg(target_os = "freebsd")]
fn load_so_conf(_interp: &Option<String>) -> Option<search_path::SearchPathVec> {
    ld_hints::parse_ld_so_hints(&Path::new("/var/run/ld-elf.so.hints")).ok()
}

#[cfg(target_os = "linux")]
fn load_ld_so_preload(interp: &Option<String>) -> search_path::SearchPathVec {
    if interp::is_glibc(interp) {
        return ld_conf::parse_ld_so_preload(&Path::new("/etc/ld.so.preload"));
    }
    search_path::SearchPathVec::new()
}
#[cfg(target_os = "freebsd")]
fn load_ld_so_preload(_interp: &Option<String>) -> search_path::SearchPathVec {
    search_path::SearchPathVec::new()
}

// Printing functions.

fn print_deps(p: &Printer, deps: &DepTree) {
    let bin = deps.arena.first().unwrap();
    p.print_executable(&bin.val.path, &bin.val.name);

    let mut deptrace = Vec::<bool>::new();
    print_deps_children(p, deps, &bin.children, &mut deptrace);
}

fn print_deps_children(
    p: &Printer,
    deps: &DepTree,
    children: &Vec<usize>,
    deptrace: &mut Vec<bool>,
) {
    let mut iter = children.iter().peekable();
    while let Some(c) = iter.next() {
        let dep = &deps.arena[*c];
        deptrace.push(children.len() > 1);
        if dep.val.mode == DepMode::NotFound {
            p.print_not_found(&dep.val.name, &deptrace);
        } else if dep.val.found {
            p.print_already_found(
                &dep.val.name,
                dep.val.path.as_ref().unwrap(),
                &dep.val.mode.to_string(),
                &deptrace,
            );
        } else {
            p.print_dependency(
                &dep.val.name,
                dep.val.path.as_ref().unwrap(),
                &dep.val.mode.to_string(),
                &deptrace,
            );
        }
        deptrace.pop();

        deptrace.push(children.len() > 1 && !iter.peek().is_none());
        print_deps_children(p, deps, &dep.children, deptrace);
        deptrace.pop();
    }
}

fn print_binary_dependencies(
    p: &Printer,
    ld_preload: &search_path::SearchPathVec,
    ld_so_conf: &mut Option<search_path::SearchPathVec>,
    ld_library_path: &search_path::SearchPathVec,
    platform: Option<&String>,
    unique: bool,
    arg: &str,
) {
    // On glibc/Linux the RTLD_DI_ORIGIN for the executable itself (used for $ORIGIN
    // expansion) is obtained by first following the '/proc/self/exe' symlink and if
    // it is not available the loader also checks the 'LD_ORIGIN_PATH' environment
    // variable.
    // The '/proc/self/exec' is an absolute path and to mimic loader behavior we first
    // try to canocalize the input filename to remove any symlinks.  There is not much
    // sense in trying LD_ORIGIN_PATH, since it is only checked by the loader if
    // the binary can not dereference the procfs entry.
    let filename = match Path::new(arg).canonicalize() {
        Ok(filename) => filename,
        Err(err) => {
            eprintln!("Failed to read file {}: {}", arg, err,);
            process::exit(1);
        }
    };

    let elc = match open_elf_file(&filename, None, None, platform) {
        Ok(elc) => elc,
        Err(err) => {
            eprintln!("Failed to parse file {}: {}", arg, err,);
            process::exit(1);
        }
    };

    if ld_so_conf.is_none() {
        *ld_so_conf = load_so_conf(&elc.interp);
    }

    let mut preload = ld_preload.to_vec();
    // glibc first parses LD_PRELOAD and then ld.so.preload.
    // We need a new vector for the case of binaries with different interpreters.
    preload.extend(load_ld_so_preload(&elc.interp));

    let system_dirs = match system_dirs::get_system_dirs(elc.e_machine, elc.ei_class) {
        Some(r) => r,
        None => {
            eprintln!("Invalid ELF architcture");
            process::exit(1);
        }
    };

    let config = Config {
        ld_preload: &preload,
        ld_library_path: ld_library_path,
        ld_so_conf: ld_so_conf,
        system_dirs: system_dirs,
        platform: platform,
        unique: unique,
    };

    let mut deptree = resolve_binary(&filename, &config, &elc);

    print_deps(p, &mut deptree);
}

fn main() {
    let mut showpath = false;
    let mut ld_library_path = String::new();
    let mut ld_preload = String::new();
    let mut platform = String::new();
    let mut unique = false;
    let mut ldd = false;
    let mut args: Vec<String> = vec![];

    {
        let mut ap = ArgumentParser::new();
        ap.refer(&mut showpath).add_option(
            &["-p"],
            StoreTrue,
            "Show the resolved path instead of the library soname",
        );
        ap.refer(&mut ld_library_path).add_option(
            &["--ld-library-path"],
            Store,
            "Assume the LD_LIBRATY_PATH is set",
        );
        ap.refer(&mut ld_preload).add_option(
            &["--ld-preload"],
            Store,
            "Assume the LD_PRELOAD is set",
        );
        ap.refer(&mut platform).add_option(
            &["--platform"],
            Store,
            "Set the value of $PLATFORM in rpath/runpath expansion",
        );
        ap.refer(&mut unique).add_option(
            &["-u", "--unique"],
            StoreTrue,
            "Do not print already resolved dependencies",
        );
        ap.refer(&mut ldd).add_option(
            &["-l", "--ldd"],
            StoreTrue,
            "Output similar to lld (unique dependencies, one per line)",
        );
        ap.refer(&mut args)
            .add_argument("binary", List, "binaries to print the dependencies");
        ap.stop_on_first_argument(true);
        ap.parse_args_or_exit();
    }

    let mut printer = printer::create(showpath, ldd, args.len() == 1);
    if ldd {
        unique = true;
    }

    let ld_library_path = search_path::from_string(&ld_library_path.as_str());
    let ld_preload = search_path::from_preload(&ld_preload.as_str());

    // The loader search cache is lazy loaded if the binary has a loader that
    // actually supports it.
    let mut ld_so_conf: Option<search_path::SearchPathVec> = None;
    let plat = if platform.is_empty() {
        None
    } else {
        Some(&platform)
    };

    for arg in args {
        print_binary_dependencies(
            &mut printer,
            &ld_preload,
            &mut ld_so_conf,
            &ld_library_path,
            plat,
            unique,
            arg.as_str(),
        )
    }
}
