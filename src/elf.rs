use std::io::Error;
use std::path::Path;
use std::{fmt, fs, str};

use object::elf::*;
use object::read::elf::*;
use object::read::StringTable;
use object::Endianness;

use crate::deptree::*;
mod platform;
use crate::pathutils;
use crate::search_path;

mod system_dirs;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "linux")]
mod interp;
#[cfg(target_os = "android")]
mod ld_config_txt;
#[cfg(target_os = "freebsd")]
mod ld_hints_freebsd;
#[cfg(target_os = "openbsd")]
mod ld_hints_openbsd;
#[cfg(target_os = "freebsd")]
mod ld_libmap_freebsd;
#[cfg(target_os = "linux")]
mod ld_preload;
#[cfg(target_os = "linux")]
mod ld_so_cache;
#[cfg(target_os = "netbsd")]
mod ld_so_conf_netbsd;
#[cfg(target_os = "linux")]
mod symbols;

#[cfg(target_os = "linux")]
type LoaderCache = ld_so_cache::LdCache;
#[cfg(target_os = "android")]
type LoaderCache = ld_config_txt::LdCache;
#[cfg(all(
    target_family = "unix",
    not(any(target_os = "linux", target_os = "android"))
))]
type LoaderCache = search_path::SearchPathVec;

type DepsVec = Vec<String>;

// A parsed ELF object with the relevant informations:
// - ei_class/ei_data/ei_osabi: ElfXX_Ehdr fields used in system library paths resolution,
// - soname: DT_SONAME, if present.
// - rpath: DT_RPATH search list paths, if present.
// - runpatch: DT_RUNPATH search list paths, if present.
// - nodeflibs: set if DF_1_NODEFLIB from DT_FLAGS_1 is set.
#[derive(Debug)]
struct ElfInfo {
    ei_class: FileClass,
    ei_data: DataEncoding,
    ei_osabi: OsAbi,
    #[allow(dead_code)]
    ei_abiver: u8,
    e_machine: Machine,
    #[allow(dead_code)]
    e_flags: FileFlags,

    interp: Option<String>,
    // Not used on OpenBSD, where the loader ignores DT_SONAME.
    #[cfg_attr(target_os = "openbsd", allow(dead_code))]
    soname: Option<String>,
    rpath: search_path::SearchPathVec,
    runpath: search_path::SearchPathVec,
    // Whether DT_RUNPATH is present.  It can not be derived from the runpath field,
    // since non existent directories are filtered out while the loader semantics
    // (ignoring DT_RPATH) only depend on the tag presence.
    has_runpath: bool,
    nodeflibs: bool,
    is_musl: bool,

    deps: DepsVec,
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
        self.ok()
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
#[cfg(all(target_family = "unix", not(target_os = "linux")))]
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
            Ok(elc)
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
            data.get(offset..offset.checked_add(fsize)?)
                .and_then(|interp| str::from_utf8(interp).ok())
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
        // The loader rejects an object whose dynamic section has no entries (for instance the
        // separated debug info files).
        if !dynamic.iter().any(|d| {
            let tag = d.d_tag(endian);
            tag != DT_NULL
        }) {
            return Err("Object file has no dynamic section");
        }
        let mut strtab = 0;
        let mut strsz = 0;

        // To obtain the DT_NEEDED name we first need to find the DT_STRTAB/DT_STRSZ.
        dynamic.iter().for_each(|d| {
            let tag = d.d_tag(endian);
            if tag == DT_STRTAB {
                strtab = d.d_val(endian).into();
            } else if tag == DT_STRSZ {
                strsz = d.d_val(endian).into();
            }
        });

        let dynstr = match parse_elf_stringtable::<Elf>(endian, data, segments, strtab, strsz) {
            Some(dynstr) => dynstr,
            None => return Err("Failure to parse the string table"),
        };

        let dt_flags_1 = DynamicFlags1(parse_elf_dyn_flags::<Elf>(endian, DT_FLAGS_1, dynamic));
        let nodeflibs = dt_flags_1.contains(DF_1_NODEFLIB);

        return match parse_elf_dtneeded::<Elf>(endian, dynamic, dynstr) {
            Ok(dtneeded) => Ok(ElfInfo {
                ei_class: elf.e_ident().class,
                ei_data: elf.e_ident().data,
                ei_osabi: elf.e_ident().os_abi,
                ei_abiver: elf.e_ident().abi_version,
                e_machine: elf.e_machine(endian),
                e_flags: elf.e_flags(endian),
                interp: None,
                soname: parse_elf_dyn_str::<Elf>(endian, DT_SONAME, dynamic, dynstr),
                rpath: parse_elf_dyn_searchpath(
                    endian, elf, DT_RPATH, dynamic, dynstr, origin, platform,
                ),
                runpath: parse_elf_dyn_searchpath(
                    endian, elf, DT_RUNPATH, dynamic, dynstr, origin, platform,
                ),
                has_runpath: parse_elf_dyn_str::<Elf>(endian, DT_RUNPATH, dynamic, dynstr)
                    .is_some(),
                nodeflibs,
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
    tag: DynamicTag,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
) -> Option<String> {
    for d in dynamic {
        if d.d_tag(endian) == DT_NULL {
            break;
        }

        if d.tag32(endian).is_none() || d.d_tag(endian) != tag {
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

fn replace_dyn_str(dynstr: &str, token: &str, value: &str) -> String {
    let newdynstr = dynstr.replace(&format!("${token}"), value);
    // Also handle ${token}
    newdynstr.replace(&format!("${{{token}}}"), value)
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

#[cfg(all(target_family = "unix", not(target_os = "linux")))]
fn parse_elf_dyn_searchpath_lib<Elf: FileHeader>(
    _endian: Elf::Endian,
    _elf: &Elf,
    _dynstr: &mut str,
) {
}

fn parse_elf_dyn_searchpath<Elf: FileHeader>(
    endian: Elf::Endian,
    elf: &Elf,
    tag: DynamicTag,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
    origin: &str,
    platform: Option<&String>,
) -> search_path::SearchPathVec {
    if let Some(dynstr) = parse_elf_dyn_str::<Elf>(endian, tag, dynamic, dynstr) {
        // Expand $ORIGIN, $LIB, and $PLATFORM.
        let mut newdynstr = replace_dyn_str(&dynstr, "ORIGIN", origin);

        parse_elf_dyn_searchpath_lib(endian, elf, &mut newdynstr);

        let platform = match platform {
            Some(platform) => platform.to_string(),
            None => platform::get(elf.e_machine(endian), elf.e_ident().data),
        };
        let newdynstr = replace_dyn_str(&newdynstr, "PLATFORM", platform.as_str());

        return search_path::from_string(newdynstr, &[':']);
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
        if d.d_tag(endian) == DT_NULL {
            break;
        }

        if d.tag32(endian).is_none() || !d.is_string(endian) || d.d_tag(endian) != DT_NEEDED {
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
    tag: DynamicTag,
    dynamic: &[Elf::Dyn],
) -> u64 {
    for d in dynamic {
        if d.d_tag(endian) == DT_NULL {
            break;
        }

        if d.tag32(endian).is_none() || d.d_tag(endian) != tag {
            continue;
        }

        return d.d_val(endian).into();
    }
    0
}

fn open_elf_file<P: AsRef<Path>>(
    filename: &P,
    melc: Option<&ElfInfo>,
    dtneeded: Option<&String>,
    platform: Option<&String>,
    preload: bool,
) -> Result<ElfInfo, std::io::Error> {
    let file = match fs::File::open(filename) {
        Ok(file) => file,
        Err(_) => return Err(Error::other("Failed to open file")),
    };

    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return Err(Error::other("Failed to map file")),
    };

    let parent = filename
        .as_ref()
        .parent()
        .and_then(Path::to_str)
        .unwrap_or("");

    match parse_object(&mmap, parent, platform) {
        Ok(elc) => {
            if let Some(melc) = melc {
                // Skip DT_NEEDED and SONAME checks for preload objects.
                if !preload && !match_elf_name(melc, dtneeded, &elc) {
                    return Err(Error::other("Error parsing ELF object"));
                }
            }
            Ok(elc)
        }
        Err(e) => Err(Error::other(e)),
    }
}

fn match_elf_name(melc: &ElfInfo, dtneeded: Option<&String>, elc: &ElfInfo) -> bool {
    if !check_elf_header(elc) || !match_elf_header(melc, elc) {
        return false;
    }

    // If DT_SONAME is defined compare against it.
    if let Some(dtneeded) = dtneeded {
        return match_elf_soname(dtneeded, elc);
    };

    true
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn check_elf_header(elc: &ElfInfo) -> bool {
    let maxver = match elc.e_machine {
        EM_MIPS | EM_MIPS_RS3_LE => 6,
        EM_PPC | EM_PPC64 | EM_SPARC | EM_X86_64 | EM_RISCV => 5,
        _ => 4,
    };

    let check_elf_osabi = match elc.e_machine {
        EM_ARM => |osabi: OsAbi| {
            osabi == ELFOSABI_SYSV || osabi == ELFOSABI_GNU || osabi == ELFOSABI_ARM_AEABI
        },
        _ => |osabi: OsAbi| osabi == ELFOSABI_SYSV || osabi == ELFOSABI_GNU,
    };

    let check_elf_abiversion = match elc.e_machine {
        EM_MIPS => |osabi: OsAbi, ver: u8, maxver: u8| {
            ver == 0
                || (osabi == ELFOSABI_SYSV && ver < 6)
                || (osabi == ELFOSABI_GNU && ver < maxver)
        },
        _ => {
            |osabi: OsAbi, ver: u8, maxver: u8| ver == 0 || (osabi == ELFOSABI_GNU && ver < maxver)
        }
    };

    check_elf_osabi(elc.ei_osabi) && check_elf_abiversion(elc.ei_osabi, elc.ei_abiver, maxver)
}
#[cfg(target_os = "freebsd")]
fn check_elf_header(elc: &ElfInfo) -> bool {
    elc.ei_osabi == ELFOSABI_FREEBSD
}
#[cfg(target_os = "openbsd")]
fn check_elf_header(elc: &ElfInfo) -> bool {
    elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_OPENBSD
}
#[cfg(target_os = "netbsd")]
fn check_elf_header(elc: &ElfInfo) -> bool {
    elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_NETBSD
}
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn check_elf_header(elc: &ElfInfo) -> bool {
    elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_SOLARIS
}

fn match_elf_header(a1: &ElfInfo, a2: &ElfInfo) -> bool {
    a1.ei_class == a2.ei_class && a1.ei_data == a2.ei_data && a1.e_machine == a2.e_machine
}

#[cfg(not(target_os = "openbsd"))]
fn match_elf_soname(dtneeded: &String, elc: &ElfInfo) -> bool {
    let soname = &elc.soname;
    if let Some(soname) = soname {
        return dtneeded == soname;
    }
    true
}
// The OpenBSD loader does not take DT_SONAME in consideration, the resolution
// is done by file name with major/minor version matching (so a DT_NEEDED with
// an older minor is satisfied by a newer minor with a different DT_SONAME).
#[cfg(target_os = "openbsd")]
fn match_elf_soname(_dtneeded: &String, _elc: &ElfInfo) -> bool {
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
    ld_cache: &'a Option<LoaderCache>,
    system_dirs: search_path::SearchPathVec,
    platform: Option<&'a String>,
    all: bool,
    #[cfg(target_os = "freebsd")]
    libmap: Option<ld_libmap_freebsd::LibMap>,
}

// Remap the dependency name using the libmap.conf mappings for the referencing
// object path (FreeBSD only).
#[cfg(target_os = "freebsd")]
fn libmap_dependency(config: &Config, refpath: &str, dependency: &String) -> String {
    match &config.libmap {
        Some(libmap) => libmap
            .lookup(refpath, dependency)
            .map(|target| target.to_string())
            .unwrap_or_else(|| dependency.to_string()),
        None => dependency.to_string(),
    }
}
#[cfg(all(target_family = "unix", not(target_os = "freebsd")))]
fn libmap_dependency(_config: &Config, _refpath: &str, dependency: &String) -> String {
    dependency.to_string()
}

#[cfg(target_os = "linux")]
fn format_ld_cache(ld_cache: &Option<LoaderCache>) -> String {
    match ld_cache {
        Some(ld_cache) => format!("{} entries", ld_cache.len()),
        None => "(none)".to_string(),
    }
}
#[cfg(target_os = "android")]
fn format_ld_cache(ld_cache: &Option<LoaderCache>) -> String {
    match ld_cache {
        Some(ld_cache) => format!("{} namespaces", ld_cache.namespaces_count()),
        None => "(none)".to_string(),
    }
}
#[cfg(all(
    target_family = "unix",
    not(any(target_os = "linux", target_os = "android"))
))]
fn format_ld_cache(ld_cache: &Option<LoaderCache>) -> String {
    match ld_cache {
        Some(ld_cache) => search_path::format_list(ld_cache),
        None => "(none)".to_string(),
    }
}

fn push_searched(r: &mut Vec<String>, name: &str, searchpaths: &search_path::SearchPathVec) {
    if !searchpaths.is_empty() {
        r.push(format!("{name}: {}", search_path::format_list(searchpaths)));
    }
}

// Describe the locations searched while failing to resolve a dependency, shown
// on the not found diagnostics in verbose mode.
fn searched_locations(config: &Config, elc: &ElfInfo, dependency: &str) -> Vec<String> {
    let mut r = Vec::new();
    if Path::new(dependency).is_absolute() {
        r.push(dependency.to_string());
        return r;
    }
    if !elc.has_runpath {
        push_searched(&mut r, "rpath", &elc.rpath);
    }
    push_searched(&mut r, "library path", config.ld_library_path);
    push_searched(&mut r, "runpath", &elc.runpath);
    if !elc.nodeflibs {
        if config.ld_cache.is_some() {
            r.push(format!("cache {}", DepMode::LdCache));
        }
        push_searched(&mut r, "default paths", &config.system_dirs);
    }
    r
}

fn print_search_path_information<P: AsRef<Path>>(filename: &P, config: &Config, elc: &ElfInfo) {
    println!(
        "{}: search path information\n\
        \x20 rpath: {}\n\
        \x20 preload: {}\n\
        \x20 library path: {}\n\
        \x20 runpath: {}\n\
        \x20 cache ({}): {}\n\
        \x20 default paths: {}",
        filename.as_ref().display(),
        search_path::format_list(&elc.rpath),
        search_path::format_list(config.ld_preload),
        search_path::format_list(config.ld_library_path),
        search_path::format_list(&elc.runpath),
        DepMode::LdCache,
        format_ld_cache(config.ld_cache),
        search_path::format_list(&config.system_dirs),
    );
}

// Function that mimic the dynamic loader resolution.
#[cfg(target_os = "linux")]
fn resolve_binary_arch(
    elc: &ElfInfo,
    deptree: &mut DepTree,
    depp: usize,
) -> Result<(), std::io::Error> {
    // musl loader and libc is on the same shared object, so adds a synthetic dependendy for
    // the binary so it is also shown and to be returned in case a objects has libc.so
    // as needed.
    if !elc.is_musl {
        return Ok(());
    }

    if let Some(interp) = &elc.interp {
        let path = Path::new(&interp);
        deptree.addnode(
            DepNode {
                //path: interp::get_interp_path(&elc.interp),
                path: pathutils::get_path(&path),
                //name: interp::get_interp_name(&elc.interp).unwrap().to_string(),
                name: pathutils::get_name(&path),
                mode: DepMode::SystemDirs,
                found: true,
                attrs: Vec::new(),
                version: None,
                searched: Vec::new(),
            },
            depp,
        );
        return Ok(());
    }

    Err(std::io::Error::other("musl: failed to get INTERP value"))
}
#[cfg(all(target_family = "unix", not(target_os = "linux")))]
fn resolve_binary_arch(
    _elc: &ElfInfo,
    _deptree: &mut DepTree,
    _depp: usize,
) -> Result<(), std::io::Error> {
    Ok(())
}

// The loader search cache is lazy loaded if the binary has a loader that actually
// supports it.
pub fn create_context() -> Option<LoaderCache> {
    None
}

pub fn resolve_binary(
    ld_cache: &mut Option<LoaderCache>,
    ld_preload: &search_path::SearchPathVec,
    ld_library_path: &search_path::SearchPathVec,
    platform: &Option<String>,
    all: bool,
    verbose: bool,
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
    let filename = Path::new(arg).canonicalize()?;

    let elc = open_elf_file(&filename, None, None, platform.as_ref(), false)?;

    // The OpenBSD loader matches a library by name and major version, picking the best
    // minor available on the directory (even for the dlopen argument). Mimic it for
    // shared library inputs (executables are executed directly, with no redirection).
    #[cfg(target_os = "openbsd")]
    let (filename, elc) = redirect_to_best_minor(filename, elc, platform.as_ref());

    let mut elc = elc;

    // DT_RPATH is ignored if the object also defines DT_RUNPATH (the latter only
    // applies to the object own dependencies, so it is not propagated).
    if elc.has_runpath {
        elc.rpath.clear();
    }

    // The cache/hints/config file is usually an optional file and failing to open it
    // does not incur on a resolution failure.
    load_so_cache(ld_cache, &filename, &elc);

    // Same for glibc ld.so.preload file.
    let mut preload = ld_preload.to_vec();
    // glibc first parses LD_PRELOAD and then ld.so.preload.
    // We need a new vector for the case of binaries with different interpreters.
    preload.extend(load_ld_so_preload(&elc.interp));

    // android loader only uses the default system search patch if the ld.so.config file can not
    // be loader or if an error was found parsing it (for instance if the executable does not
    // has an entry associated in the section).
    #[cfg(target_os = "android")]
    fn load_system_dirs(ld_cache: &Option<LoaderCache>) -> bool {
        ld_cache.is_none()
    }
    #[cfg(not(target_os = "android"))]
    fn load_system_dirs(_ld_cache: &Option<LoaderCache>) -> bool {
        true
    }

    let system_dirs = if load_system_dirs(&*ld_cache) {
        system_dirs::get_system_dirs(&elc.interp, elc.e_machine, elc.ei_class)?
    } else {
        search_path::SearchPathVec::new()
    };

    let config = Config {
        ld_preload: &preload,
        ld_library_path,
        ld_cache,
        system_dirs,
        platform: platform.as_ref(),
        all,
        #[cfg(target_os = "freebsd")]
        libmap: ld_libmap_freebsd::parse_libmap(&Path::new("/etc/libmap.conf")),
    };

    if verbose {
        print_search_path_information(&filename, &config, &elc);
    }

    let mut deptree = DepTree::new();

    let depp = deptree.addroot(DepNode {
        path: pathutils::get_path(&filename),
        name: pathutils::get_name(&filename),
        mode: DepMode::Executable,
        found: false,
        attrs: Vec::new(),
        version: None,
        searched: Vec::new(),
    });

    resolve_binary_arch(&elc, &mut deptree, depp)?;

    let refpath = filename.to_string_lossy().into_owned();
    resolve_dependencies(&config, elc, refpath, &mut deptree, depp);

    Ok(deptree)
}

#[cfg(target_os = "openbsd")]
fn redirect_to_best_minor(
    filename: std::path::PathBuf,
    elc: ElfInfo,
    platform: Option<&String>,
) -> (std::path::PathBuf, ElfInfo) {
    if elc.interp.is_some() {
        return (filename, elc);
    }
    let (Some(dir), Some(name)) = (
        filename.parent().and_then(|p| p.to_str()),
        filename.file_name().and_then(|n| n.to_str()),
    ) else {
        return (filename, elc);
    };
    let candidate = dependency_path(dir, name);
    if candidate != filename {
        if let Ok(nelc) = open_elf_file(&candidate, None, None, platform, false) {
            return (candidate, nelc);
        }
    }
    (filename, elc)
}

#[cfg(target_os = "linux")]
fn load_so_cache<P: AsRef<Path>>(ld_cache: &mut Option<LoaderCache>, _binary: &P, elc: &ElfInfo) {
    if interp::is_glibc(&elc.interp) {
        // glibc's ld.so.cache is shared between all executables, so there is no need
        // to reload for multiple entries.
        if ld_cache.is_none() {
            *ld_cache = ld_so_cache::parse_ld_so_cache(
                &Path::new("/etc/ld.so.cache"),
                elc.ei_class,
                elc.e_machine,
                elc.e_flags,
            )
            .ok();
        }
    };
}
#[cfg(target_os = "android")]
fn load_so_cache<P: AsRef<Path>>(ld_cache: &mut Option<LoaderCache>, binary: &P, elc: &ElfInfo) {
    if let Some(ld_config_path) =
        ld_config_txt::get_ld_config_path(binary, elc.e_machine, elc.ei_class)
    {
        // On Android 10 and forward each executable might have a associated ld.config.txt
        // file in different paths, so we need to reload for each argument.
        *ld_cache = ld_config_txt::parse_ld_config_txt(
            &Path::new(&ld_config_path),
            binary,
            elc.interp.as_ref().unwrap(),
            elc.e_machine,
            elc.ei_class,
        )
        .ok();
    }
}
#[cfg(target_os = "freebsd")]
fn load_so_cache<P: AsRef<Path>>(ld_cache: &mut Option<LoaderCache>, _binary: &P, elc: &ElfInfo) {
    // The 32-bit compat objects use a separate hints file (the rtld
    // COMPAT_libcompat suffix), so the cache is reloaded for each binary.
    let hints = if cfg!(target_pointer_width = "64") && elc.ei_class == ELFCLASS32 {
        "/var/run/ld-elf32.so.hints"
    } else {
        "/var/run/ld-elf.so.hints"
    };
    *ld_cache = ld_hints_freebsd::parse_ld_so_hints(&Path::new(hints)).ok();
}
#[cfg(target_os = "openbsd")]
fn load_so_cache<P: AsRef<Path>>(ld_cache: &mut Option<LoaderCache>, _binary: &P, _ecl: &ElfInfo) {
    if ld_cache.is_none() {
        *ld_cache = ld_hints_openbsd::parse_ld_so_hints(&Path::new("/var/run/ld.so.hints")).ok()
    }
}
#[cfg(target_os = "netbsd")]
fn load_so_cache<P: AsRef<Path>>(ld_cache: &mut Option<LoaderCache>, _binary: &P, _ecl: &ElfInfo) {
    if ld_cache.is_none() {
        *ld_cache = ld_so_conf_netbsd::parse_ld_so_conf(&Path::new("/etc/ld.so.conf")).ok()
    }
}
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn load_so_cache<P: AsRef<Path>>(_ld_cache: &mut Option<LoaderCache>, _binary: &P, _ecl: &ElfInfo) {
}

#[cfg(target_os = "linux")]
fn load_ld_so_preload(interp: &Option<String>) -> search_path::SearchPathVec {
    if interp::is_glibc(interp) {
        return ld_preload::parse_ld_so_preload(&Path::new("/etc/ld.so.preload"));
    }
    search_path::SearchPathVec::new()
}
#[cfg(all(target_family = "unix", not(target_os = "linux")))]
fn load_ld_so_preload(_interp: &Option<String>) -> search_path::SearchPathVec {
    search_path::SearchPathVec::new()
}

// Return the path candidate for a dependency on a search directory.  OpenBSD
// shared objects do not have a DT_SONAME and the DT_NEEDED entries carry the
// full libname.so.major.minor name, with the loader matching the major version
// and picking the best minor available on the directory.
#[cfg(target_os = "openbsd")]
fn dependency_path(dir: &str, dtneeded: &str) -> std::path::PathBuf {
    fn parse_version(name: &str) -> Option<(&str, u64)> {
        let idx = name.find(".so.")?;
        let stem = &name[..idx + 3];
        // The version might be either major.minor or only the major.
        let major = match name[idx + 4..].split_once('.') {
            Some((major, minor)) => {
                minor.parse::<u64>().ok()?;
                major
            }
            None => &name[idx + 4..],
        };
        Some((stem, major.parse().ok()?))
    }

    if let Some((stem, major)) = parse_version(dtneeded) {
        let prefix = format!("{stem}.{major}.");
        let mut best: Option<(u64, std::path::PathBuf)> = None;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Some(minor) = entry
                    .file_name()
                    .to_str()
                    .and_then(|filename| filename.strip_prefix(&prefix))
                    .and_then(|minor| minor.parse::<u64>().ok())
                {
                    if best.as_ref().is_none_or(|(m, _)| minor > *m) {
                        best = Some((minor, entry.path()));
                    }
                }
            }
        }
        if let Some((_, path)) = best {
            return path;
        }
    }
    Path::new(dir).join(dtneeded)
}
#[cfg(all(target_family = "unix", not(target_os = "openbsd")))]
fn dependency_path(dir: &str, dtneeded: &str) -> std::path::PathBuf {
    Path::new(dir).join(dtneeded)
}

#[cfg(target_os = "linux")]
fn rpath_search(elc: &ElfInfo) -> bool {
    !elc.has_runpath
}
#[cfg(all(target_family = "unix", not(target_os = "linux")))]
fn rpath_search(_elc: &ElfInfo) -> bool {
    true
}

// Returned from resolve_dependency_1 with resolved information.
#[derive(Debug)]
struct ResolvedDependency<'a> {
    elc: ElfInfo,
    path: &'a String,
    // The resolved file name, which might differ from the DT_NEEDED entry
    // (for instance on OpenBSD minor version matching).
    filename: String,
    mode: DepMode,
}

// A pending dependency to resolve: the DT_NEEDED name along the index of the
// loading object information (on the parents vector) and the dependency tree
// node to attach the resolution result.
struct WorkItem {
    dependency: String,
    parent: usize,
    depp: usize,
    preload: bool,
}

// Resolve the dependencies in breadth-first order, mimicking the loader: each
// object DT_NEEDED list is fully processed before the dependencies own
// dependencies, so a shared dependency is attributed to the first object that
// requests it in load order (which defines the search path used).
fn resolve_dependencies(
    config: &Config,
    root_elc: ElfInfo,
    root_refpath: String,
    deptree: &mut DepTree,
    root_depp: usize,
) {
    use std::collections::VecDeque;

    // The already loaded objects information, used to resolve their own
    // dependencies (rpath chain and libmap reference path).
    let mut parents: Vec<(ElfInfo, String)> = Vec::new();

    let mut queue = VecDeque::new();
    for searchpath in config.ld_preload {
        queue.push_back(WorkItem {
            dependency: searchpath.path.clone(),
            parent: 0,
            depp: root_depp,
            preload: true,
        });
    }
    for dep in &root_elc.deps {
        queue.push_back(WorkItem {
            dependency: dep.clone(),
            parent: 0,
            depp: root_depp,
            preload: false,
        });
    }
    parents.push((root_elc, root_refpath));

    while let Some(item) = queue.pop_front() {
        let (elc, refpath) = &parents[item.parent];

        // FreeBSD libmap.conf may remap the dependency name based on the
        // referencing object path.
        let dependency = &libmap_dependency(config, refpath, &item.dependency);

        if elc.is_musl && dependency == "libc.so" {
            continue;
        }

        // If DF_1_NODEFLIB is set ignore the search cache in the case a
        // dependency could resolve the library.
        if !elc.nodeflibs {
            if let Some(entry) = deptree.get(dependency) {
                if config.all {
                    deptree.addnode(
                        DepNode {
                            path: entry.path,
                            name: pathutils::get_name(&Path::new(dependency)),
                            mode: entry.mode,
                            found: true,
                            attrs: Vec::new(),
                            version: None,
                            searched: Vec::new(),
                        },
                        item.depp,
                    );
                }
                continue;
            }
        }

        if let Some(mut dep) = resolve_dependency_1(dependency, config, elc, item.preload) {
            let r = if dep.mode == DepMode::Direct {
                // Decompose the direct object path in path and filename so when
                // print the dependencies only the file name is showed in
                // default mode.
                let p = Path::new(dependency);
                (pathutils::get_path(&p), pathutils::get_name(&p))
            } else {
                (Some(dep.path.to_string()), dep.filename.clone())
            };
            // The resolved path of this dependency, used as the reference path
            // for its own dependencies resolution.
            let depref = match &r.0 {
                Some(path) => format!("{}{}{}", path, std::path::MAIN_SEPARATOR, r.1),
                None => r.1.clone(),
            };
            let c = deptree.addnode(
                DepNode {
                    path: r.0,
                    name: r.1,
                    mode: dep.mode,
                    found: false,
                    attrs: Vec::new(),
                    version: None,
                    searched: Vec::new(),
                },
                item.depp,
            );

            // The DT_RPATH scope used for the indirect dependencies is system
            // specific: the glibc loader searches the object own DT_RPATH and
            // then walks up the chain of loading objects (up to the
            // executable), the FreeBSD and OpenBSD loaders search the object
            // own DT_RPATH and then the main object one, while the NetBSD
            // loader only searches the requesting object DT_RPATH.  In all
            // cases an object DT_RPATH is ignored if the object also defines
            // DT_RUNPATH, without affecting the inherited part.
            if dep.elc.has_runpath {
                dep.elc.rpath.clear();
            }
            #[cfg(target_os = "linux")]
            dep.elc.rpath.extend(elc.rpath.clone());
            #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
            dep.elc.rpath.extend(parents[0].0.rpath.clone());

            let parent = parents.len();
            for sdep in &dep.elc.deps {
                queue.push_back(WorkItem {
                    dependency: sdep.clone(),
                    parent,
                    depp: c,
                    preload: item.preload,
                });
            }
            parents.push((dep.elc, depref));
        } else {
            let path = Path::new(dependency);
            let searched = searched_locations(config, elc, dependency);
            deptree.addnode(
                DepNode {
                    path: pathutils::get_path(&path),
                    name: pathutils::get_name(&path),
                    mode: DepMode::NotFound,
                    found: false,
                    attrs: Vec::new(),
                    version: None,
                    searched,
                },
                item.depp,
            );
        }
    }

    add_loader_dependency(config, &parents[0].0, deptree, root_depp);
}

// The dynamic loader is always loaded, and ldd always shows it.  The libc.so is
// explicitly lists it as a dependency, but an object might not depend on libc at
// all.  Objects without any dependency are skipped, since the loader is not
// involved.
#[cfg(target_os = "linux")]
fn add_loader_dependency(config: &Config, elc: &ElfInfo, deptree: &mut DepTree, root_depp: usize) {
    if !interp::is_glibc(&elc.interp) || deptree.arena[root_depp].children.is_empty() {
        return;
    }
    if deptree
        .arena
        .iter()
        .any(|n| interp::is_glibc_name(&n.val.name))
    {
        return;
    }

    // For an executable the PT_INTERP segment has the loader path.
    if let Some(interp) = &elc.interp {
        let path = Path::new(interp);
        if path.exists() {
            deptree.addnode(
                DepNode {
                    path: pathutils::get_path(&path),
                    name: pathutils::get_name(&path),
                    mode: DepMode::Direct,
                    found: false,
                    attrs: Vec::new(),
                    version: None,
                    searched: Vec::new(),
                },
                root_depp,
            );
            return;
        }
    }

    // Otherwise resolve the loader soname through the loader cache and the
    // system directories (only the soname matching the object architecture
    // resolves).  The object search paths do not apply, since the loader is
    // not subject to the dependency search.
    for name in interp::glibc_names() {
        let dtneeded = name.to_string();
        let mut dep = None;
        if let Some(ld_cache) = config.ld_cache {
            dep = resolve_dependency_ld_cache(&dtneeded, ld_cache, config.platform, elc);
        }
        if dep.is_none() {
            for searchpath in &config.system_dirs {
                let path = dependency_path(&searchpath.path, &dtneeded);
                if let Ok(elc) =
                    open_elf_file(&path, Some(elc), Some(&dtneeded), config.platform, false)
                {
                    dep = Some(ResolvedDependency {
                        elc,
                        path: &searchpath.path,
                        filename: pathutils::get_name(&path),
                        mode: DepMode::SystemDirs,
                    });
                    break;
                }
            }
        }
        if let Some(dep) = dep {
            deptree.addnode(
                DepNode {
                    path: Some(dep.path.to_string()),
                    name: dep.filename.clone(),
                    mode: dep.mode,
                    found: false,
                    attrs: Vec::new(),
                    version: None,
                    searched: Vec::new(),
                },
                root_depp,
            );
            return;
        }
    }
}
// The OpenBSD ldd lists the loader (/usr/libexec/ld.so) for executables (the
// dlopen trace used for shared libraries does not show it).
#[cfg(target_os = "openbsd")]
fn add_loader_dependency(_config: &Config, elc: &ElfInfo, deptree: &mut DepTree, root_depp: usize) {
    if let Some(interp) = &elc.interp {
        let path = Path::new(interp);
        if path.exists() {
            deptree.addnode(
                DepNode {
                    path: pathutils::get_path(&path),
                    name: pathutils::get_name(&path),
                    mode: DepMode::Direct,
                    found: false,
                    attrs: Vec::new(),
                    version: None,
                    searched: Vec::new(),
                },
                root_depp,
            );
        }
    }
}
#[cfg(all(
    target_family = "unix",
    not(target_os = "linux"),
    not(target_os = "openbsd")
))]
fn add_loader_dependency(
    _config: &Config,
    _elc: &ElfInfo,
    _deptree: &mut DepTree,
    _root_depp: usize,
) {
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
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform, preload) {
            return Some(ResolvedDependency {
                elc,
                path: dtneeded,
                filename: pathutils::get_name(&path),
                mode: if preload {
                    DepMode::Preload
                } else {
                    DepMode::Direct
                },
            });
        }
        return None;
    }

    // The rpath field holds the object own DT_RPATH along with any inherited
    // part.  The glibc loader skips the whole search (including the inherited
    // chain) if the object issuing the load has a DT_RUNPATH, while the BSD
    // loaders still search the main object DT_RPATH (the object own rpath is
    // already cleared on DT_RUNPATH presence).
    if rpath_search(elc) {
        for searchpath in &elc.rpath {
            let path = dependency_path(&searchpath.path, dtneeded);
            if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform, false)
            {
                return Some(ResolvedDependency {
                    elc,
                    path: &searchpath.path,
                    filename: pathutils::get_name(&path),
                    mode: DepMode::DtRpath,
                });
            }
        }
    }

    // Check LD_LIBRARY_PATH paths.
    for searchpath in config.ld_library_path {
        let path = dependency_path(&searchpath.path, dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform, false) {
            return Some(ResolvedDependency {
                elc,
                path: &searchpath.path,
                filename: pathutils::get_name(&path),
                mode: DepMode::LdLibraryPath,
            });
        }
    }

    // Check DT_RUNPATH.
    for searchpath in &elc.runpath {
        let path = dependency_path(&searchpath.path, dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform, false) {
            return Some(ResolvedDependency {
                elc,
                path: &searchpath.path,
                filename: pathutils::get_name(&path),
                mode: DepMode::DtRunpath,
            });
        }
    }

    // Skip system paths if DF_1_NODEFLIB is set.
    if elc.nodeflibs {
        return None;
    }

    // Check the loader cache.
    if let Some(ld_cache) = config.ld_cache {
        if let Some(dep) = resolve_dependency_ld_cache(dtneeded, ld_cache, config.platform, elc) {
            return Some(dep);
        }
    }

    // Finally the system directories.
    for searchpath in &config.system_dirs {
        let path = dependency_path(&searchpath.path, dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), config.platform, false) {
            return Some(ResolvedDependency {
                elc,
                path: &searchpath.path,
                filename: pathutils::get_name(&path),
                mode: DepMode::SystemDirs,
            });
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn resolve_dependency_ld_cache<'a>(
    dtneeded: &'a String,
    ld_cache: &'a LoaderCache,
    platform: Option<&String>,
    elc: &'a ElfInfo,
) -> Option<ResolvedDependency<'a>> {
    use std::path::PathBuf;
    if let Some(path) = ld_cache.get(dtneeded) {
        let mut pathbuf = PathBuf::new();
        pathbuf.push(path);
        pathbuf.push(dtneeded);
        if let Ok(elc) = open_elf_file(&pathbuf, Some(elc), Some(dtneeded), platform, false) {
            return Some(ResolvedDependency {
                elc,
                path,
                filename: pathutils::get_name(&pathbuf),
                mode: DepMode::LdCache,
            });
        }
    }
    None
}

#[cfg(target_os = "android")]
fn resolve_dependency_ld_cache<'a>(
    dtneeded: &'a String,
    ld_cache: &'a LoaderCache,
    platform: Option<&String>,
    elc: &'a ElfInfo,
) -> Option<ResolvedDependency<'a>> {
    // The constraint function is used to instruct the compiler with a higher-ranked trait
    // bounds (for <...>) that the closure must return a reference of the same lifetime as
    // the argument.  Otherwise it complains that the closure arguments has a different
    // lifetime than result.
    fn constraint<F>(f: F) -> F
    where
        F: for<'a> Fn(&'a ld_config_txt::NamespaceConfig) -> Option<ResolvedDependency<'a>>,
    {
        f
    }

    let search_namespace = constraint(|namespace: &ld_config_txt::NamespaceConfig| {
        for searchpath in &namespace.search_paths {
            let path = Path::new(&searchpath.path).join(dtneeded);
            if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), platform, false) {
                return Some(ResolvedDependency {
                    elc,
                    path: &searchpath.path,
                    filename: pathutils::get_name(&path),
                    mode: DepMode::LdCache,
                });
            }
        }
        None
    });

    // First check the default namespace and then the linked namespaces for the default one.
    // For latter, do not follow further linked namespaces.
    if let Some(default_ns) = ld_cache.get_default_namespace() {
        if let Some(resolved) = search_namespace(default_ns) {
            return Some(resolved);
        }

        for linked_ns in &default_ns.namespaces {
            if let Some(namespace) = ld_cache.get_namespace(linked_ns) {
                if !namespace.is_accessible(dtneeded) {
                    continue;
                }

                if let Some(resolved) = search_namespace(namespace) {
                    return Some(resolved);
                }
            }
        }
    }

    None
}

#[cfg(all(
    target_family = "unix",
    not(any(target_os = "linux", target_os = "android"))
))]
fn resolve_dependency_ld_cache<'a>(
    dtneeded: &'a String,
    ld_cache: &'a LoaderCache,
    platform: Option<&String>,
    elc: &'a ElfInfo,
) -> Option<ResolvedDependency<'a>> {
    for searchpath in ld_cache {
        let path = dependency_path(&searchpath.path, dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded), platform, false) {
            return Some(ResolvedDependency {
                elc,
                path: &searchpath.path,
                filename: pathutils::get_name(&path),
                mode: DepMode::LdCache,
            });
        }
    }
    None
}

// Symbol resolution mimicking, used to implement the ldd like --data-relocs,
// --function-relocs, and --unused options.  The checks mimic the glibc loader
// and are only enabled on Linux; on Android the linker provides the loader
// symbols with mangled names, while the BSD run-time linkers were not verified.

// An unresolved symbol reference found while processing the dynamic relocations.
#[cfg(target_os = "linux")]
pub struct UndefinedSymbol {
    pub name: String,
    // The required symbol version, if any.
    pub version: Option<String>,
    // Full path of the object with the undefined reference.
    pub object: String,
}

// A version definition required by some object that the dependency providing
// it does not define (the loader version check).
#[cfg(target_os = "linux")]
pub struct VersionError {
    // Full path of the object that should provide the version.
    pub object: String,
    pub version: String,
    // Full path of the object requiring the version.
    pub required_by: String,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct RelocCheckResult {
    pub version_errors: Vec<VersionError>,
    pub undefined: Vec<UndefinedSymbol>,
    pub unused: Vec<String>,
}

#[cfg(target_os = "linux")]
fn deptree_node_path(node: &DepNode) -> Option<String> {
    node.path.as_ref().map(|path| {
        Path::new(path)
            .join(&node.name)
            .to_string_lossy()
            .into_owned()
    })
}

// Build the loader global search scope: the resolved objects from the dependency
// tree in breadth-first order (the order the loader uses for symbol resolution),
// with each object dynamic symbol table and relocation references parsed.
#[cfg(target_os = "linux")]
fn build_symbol_scope(deptree: &DepTree) -> Vec<(String, symbols::ObjectSymbols)> {
    use std::collections::{HashSet, VecDeque};

    let mut scope = Vec::new();
    let mut seen = HashSet::new();

    let mut queue = VecDeque::from([0usize]);
    while let Some(idx) = queue.pop_front() {
        let node = &deptree.arena[idx];
        queue.extend(node.children.iter());

        // Skip unresolved dependencies and the duplicated entries printed by the
        // --all option.
        if node.val.mode == DepMode::NotFound || node.val.found {
            continue;
        }
        let path = match deptree_node_path(&node.val) {
            Some(path) => path,
            None => continue,
        };
        if !seen.insert(path.clone()) {
            continue;
        }
        if let Some(obj) = symbols::parse(&path) {
            scope.push((path, obj));
        }
    }
    scope
}

// Reparse the root object, used to obtain the PT_INTERP and DT_NEEDED values.
#[cfg(target_os = "linux")]
fn open_root_elf(deptree: &DepTree) -> Option<ElfInfo> {
    let root = deptree.arena.first()?;
    let path = deptree_node_path(&root.val)?;
    open_elf_file(&path, None, None, None, false).ok()
}

// The dynamic loader is part of the global scope (libc binds to symbols the
// loader provides, like _rtld_global), however it might not be present in the
// dependency tree if no object lists it as an explicit dependency.
#[cfg(target_os = "linux")]
fn append_interp_to_scope(scope: &mut Vec<(String, symbols::ObjectSymbols)>, elc: &ElfInfo) {
    if let Some(interp) = &elc.interp {
        let name = pathutils::get_name(&Path::new(interp));
        if scope
            .iter()
            .any(|(path, _)| pathutils::get_name(&Path::new(path)) == name)
        {
            return;
        }
        if let Some(obj) = symbols::parse(interp) {
            scope.push((interp.to_string(), obj));
        }
    }
}

// Mimic the loader relocation processing and version checking, used to
// implement the ldd like --data-relocs, --function-relocs, and --unused
// options:
// - version_errors: version definitions required by some object that the
//   dependency providing them does not define (always computed).
// - undefined: non weak undefined symbol references that no object in the
//   global scope satisfies.  If PROCESS_PLT is false the DT_JMPREL function
//   relocations are only processed for bind-now objects, as the loader does
//   in LD_WARN mode.
// - unused: the executable DT_NEEDED entries that provide no symbol used by
//   the executable own relocations (computed iff CHECK_UNUSED is set).
#[cfg(target_os = "linux")]
pub fn check_relocations(
    deptree: &DepTree,
    process_plt: bool,
    check_unused: bool,
) -> RelocCheckResult {
    use std::collections::{HashMap, HashSet};

    let mut r = RelocCheckResult::default();

    let root_elc = open_root_elf(deptree);

    let mut scope = build_symbol_scope(deptree);
    if let Some(root_elc) = &root_elc {
        append_interp_to_scope(&mut scope, root_elc);
    }

    // Whether the OBJ object provides a definition satisfying the REF
    // reference, following the loader lookup rules: a versioned reference is
    // satisfied by a matching version definition or by any definition from an
    // object without version information.
    fn satisfies(obj: &symbols::ObjectSymbols, sref: &symbols::SymbolRef) -> bool {
        match &sref.version {
            Some(version) => {
                obj.defined_versioned
                    .contains(&(sref.name.clone(), version.clone()))
                    || (!obj.has_verdef && obj.defined.contains(&sref.name))
            }
            None => obj.defined.contains(&sref.name),
        }
    }

    // The loader version check (mimicking _dl_check_all_versions): for each
    // required version, check whether the object providing it (matched by file
    // name) actually defines it.
    for (opath, obj) in &scope {
        for need in &obj.verneeded {
            if need.weak {
                continue;
            }
            if let Some((dpath, dobj)) = scope
                .iter()
                .find(|(path, _)| pathutils::get_name(&Path::new(path)) == need.file)
            {
                if !dobj.verdef_names.contains(&need.version) {
                    r.version_errors.push(VersionError {
                        object: dpath.clone(),
                        version: need.version.clone(),
                        required_by: opath.clone(),
                    });
                }
            }
        }
    }

    // The loader relocates the objects in the inverse scope order, with the
    // executable itself being the last one.
    for (idx, (path, obj)) in scope.iter().enumerate().rev() {
        for sref in &obj.references {
            if sref.weak || (sref.plt && !process_plt && !obj.bind_now) {
                continue;
            }
            // A COPY relocation lookup skips the referencing object own definition).
            if !scope
                .iter()
                .enumerate()
                .any(|(i, (_, o))| (!sref.copy || i != idx) && satisfies(o, sref))
            {
                r.undefined.push(UndefinedSymbol {
                    name: sref.name.clone(),
                    version: sref.version.clone(),
                    object: path.clone(),
                });
            }
        }
    }

    if !check_unused {
        return r;
    }
    let Some(root_elc) = root_elc else {
        return r;
    };

    // Only the executable own references mark the dependencies as used (the
    // loader with LD_DEBUG=unused only relocates the main executable), with
    // the first object satisfying the reference in the scope order being the
    // one marked.
    let mut used = vec![false; scope.len()];
    if let Some((_, robj)) = scope.first() {
        for sref in &robj.references {
            // A COPY relocation lookup skips the referencing object own definition).
            let skip = if sref.copy { 1 } else { 0 };
            if let Some(p) = scope
                .iter()
                .skip(skip)
                .position(|(_, o)| satisfies(o, sref))
            {
                used[p + skip] = true;
            }
        }
    }

    let scope_index: HashMap<&str, usize> = scope
        .iter()
        .enumerate()
        .map(|(i, (path, _))| (path.as_str(), i))
        .collect();

    let mut reported = HashSet::new();
    for dtneeded in &root_elc.deps {
        let node = match deptree.get(dtneeded) {
            Some(node) => node,
            None => continue,
        };
        if node.mode == DepMode::NotFound {
            // The loader creates a faked entry for a missing dependency, which
            // can never have a symbol bound to it.
            if reported.insert(dtneeded.clone()) {
                r.unused.push(dtneeded.clone());
            }
            continue;
        }
        let path = match node.path {
            Some(ref path) => Path::new(path)
                .join(&node.name)
                .to_string_lossy()
                .into_owned(),
            None => continue,
        };
        if let Some(&i) = scope_index.get(path.as_str()) {
            if !used[i] && reported.insert(path.clone()) {
                r.unused.push(path);
            }
        }
    }
    r
}
