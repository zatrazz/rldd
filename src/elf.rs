use std::io::{Error, ErrorKind};
use std::path::Path;
use std::{fmt, fs, str};

use object::elf::*;
use object::read::elf::*;
use object::read::StringTable;
use object::Endianness;

#[cfg(target_os = "linux")]
mod interp;
use crate::deptree::*;
#[cfg(target_os = "linux")]
mod ld_conf;
mod platform;
use crate::search_path;
mod system_dirs;
#[cfg(target_os = "openbsd")]
mod ld_hints_openbsd;
#[cfg(target_os = "freebsd")]
mod ld_hints_freebsd;

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
) -> Result<ElfInfo, std::io::Error> {
    let file = match fs::File::open(&filename) {
        Ok(file) => file,
        Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to open file")),
    };

    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to map file")),
    };

    let parent = match filename.as_ref().parent().and_then(Path::to_str) {
        Some(parent) => parent,
        None => "",
    };

    match parse_object(&*mmap, parent, platform) {
        Ok(elc) => {
            if let Some(melc) = melc {
                if !match_elf_name(melc, dtneeded, &elc) {
                    return Err(Error::new(ErrorKind::Other, "Error parsing ELF object"));
                }
            }
            Ok(elc)
        }
        Err(e) => return Err(Error::new(ErrorKind::Other, e)),
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
    all: bool,
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
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
fn resolve_binary_arch(_elc: &ElfInfo, _deptree: &mut DepTree, _depp: usize) {}

pub fn resolve_binary(
    ld_preload: &search_path::SearchPathVec,
    ld_so_conf: &mut Option<search_path::SearchPathVec>,
    ld_library_path: &search_path::SearchPathVec,
    platform: Option<&String>,
    all: bool,
    arg: &str,
) -> Result<DepTree, std::io::Error> {
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
            return Err(Error::new(
                ErrorKind::Other,
                format!("Failed to read file {}: {}", arg, err),
            ))
        }
    };

    let elc = match open_elf_file(&filename, None, None, platform) {
        Ok(elc) => elc,
        Err(err) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Failed to parse file {}: {}", arg, err),
            ))
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
        None => return Err(Error::new(ErrorKind::Other, "Invalid ELF architcture")),
    };

    let config = Config {
        ld_preload: &preload,
        ld_library_path: ld_library_path,
        ld_so_conf: ld_so_conf,
        system_dirs: system_dirs,
        platform: platform,
        all: all,
    };

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

    Ok(deptree)
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
            if config.all {
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

    if let Some(mut dep) = resolve_dependency_1(dependency, config, elc, preload) {
        let r = if dep.mode == DepMode::Direct {
            // Decompose the direct object path in path and filename so when print the dependencies
            // only the file name is showed in default mode.
            let p = Path::new(dependency);
            (
                p.parent()
                    .and_then(|s| s.to_str())
                    .and_then(|s| Some(s.to_string())),
                p.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string(),
            )
        } else {
            (Some(dep.path.to_string()), dependency.to_string())
        };
        let c = deptree.addnode(
            DepNode {
                path: r.0,
                name: r.1,
                mode: dep.mode,
                found: false,
            },
            depp,
        );

        // Use parent R_PATH if dependency does not define it.
        if dep.elc.rpath.is_empty() {
            dep.elc.rpath.extend(elc.rpath.clone());
        }

        for sdep in &dep.elc.deps {
            resolve_dependency(&config, &sdep, &dep.elc, deptree, c, preload);
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

#[cfg(target_os = "linux")]
fn load_so_conf(interp: &Option<String>) -> Option<search_path::SearchPathVec> {
    if interp::is_glibc(interp) {
        return ld_conf::parse_ld_so_conf(&Path::new("/etc/ld.so.conf")).ok();
    };
    None
}
#[cfg(target_os = "freebsd")]
fn load_so_conf(_interp: &Option<String>) -> Option<search_path::SearchPathVec> {
    ld_hints_freebsd::parse_ld_so_hints(&Path::new("/var/run/ld-elf.so.hints")).ok()
}
#[cfg(target_os = "openbsd")]
fn load_so_conf(_interp: &Option<String>) -> Option<search_path::SearchPathVec> {
    ld_hints_openbsd::parse_ld_so_hints(&Path::new("/var/run/ld.so.hints")).ok()
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
#[cfg(target_os = "openbsd")]
fn load_ld_so_preload(_interp: &Option<String>) -> search_path::SearchPathVec {
    search_path::SearchPathVec::new()
}
