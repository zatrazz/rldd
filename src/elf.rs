use std::borrow::Cow;
use std::io::Error;
use std::path::Path;
use std::rc::Rc;
use std::{fs, str};

use object::elf::*;
use object::read::elf::*;
use object::read::StringTable;
use object::Endianness;

use crate::deptree::*;
mod platform;
use crate::pathutils;
use crate::search_path;

mod system_dirs;

// The ld.config.txt parsing does not depend on the device beyond the system
// properties, so it is also built for the unit tests on a Linux host, where
// nothing else uses it.
#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
mod android;
#[cfg(target_os = "linux")]
mod interp;
#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
mod ld_config_txt;
// The BSD configuration file parsers are also built for the Linux tests, so
// their unit tests run where CI does.
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    all(test, target_os = "linux")
))]
mod ld_hints;
#[cfg(any(target_os = "freebsd", all(test, target_os = "linux")))]
mod ld_hints_freebsd;
#[cfg(any(target_os = "openbsd", all(test, target_os = "linux")))]
mod ld_hints_openbsd;
#[cfg(any(target_os = "freebsd", all(test, target_os = "linux")))]
mod ld_libmap_freebsd;
#[cfg(target_os = "linux")]
mod ld_preload;
#[cfg(target_os = "linux")]
mod ld_so_cache;
#[cfg(any(target_os = "netbsd", all(test, target_os = "linux")))]
mod ld_so_conf_netbsd;
mod loader;
#[cfg(target_os = "linux")]
mod symbols;
use loader::{Loader, Rejection, Rtld, SearchCache};

type LoaderCache = <Rtld as Loader>::Cache;
type ObjectNamespace = <LoaderCache as SearchCache>::Namespace;

type DepsVec = Vec<String>;

// A parsed ELF object with the relevant informations:
// - ei_class/ei_data/ei_osabi: ElfXX_Ehdr fields used in system library paths resolution,
// - soname: DT_SONAME, if present.
// - rpath: DT_RPATH search list paths, if present.
// - runpatch: DT_RUNPATH search list paths, if present.
// - nodeflibs: set if DF_1_NODEFLIB from DT_FLAGS_1 is set.
//
// The dynamic string tokens depend on the loader of the object, so the
// search lists and the dependencies are only filled from the entries as
// written (dt_rpath, dt_runpath, and needed) once it is known: when the
// object is opened for a dependency, or by the caller for the input object.
#[derive(Debug)]
struct ElfInfo {
    ei_class: FileClass,
    ei_data: DataEncoding,
    // Not checked on NetBSD, whose loader ignores the OS ABI.
    #[cfg_attr(target_os = "netbsd", allow(dead_code))]
    ei_osabi: OsAbi,
    #[allow(dead_code)]
    ei_abiver: u8,
    e_machine: Machine,
    #[allow(dead_code)]
    e_flags: FileFlags,

    interp: Option<String>,
    // Read by the glibc and the FreeBSD rules only.
    #[cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), allow(dead_code))]
    soname: Option<String>,
    dt_rpath: Option<String>,
    dt_runpath: Option<String>,
    // The DT_NEEDED, DT_AUXILIARY and DT_FILTER entries, along with whether
    // each one is a filter.  A name that is not valid UTF-8 is kept with the
    // invalid sequences replaced, so it is reported as not found.
    needed: Vec<(String, bool)>,
    rpath: search_path::SearchPathVec,
    runpath: search_path::SearchPathVec,
    // Whether DT_RUNPATH is present.  It can not be derived from the runpath field,
    // since non existent directories are filtered out while the loader semantics
    // (ignoring DT_RPATH) only depend on the tag presence.
    has_runpath: bool,
    // Whether the last of the DT_RPATH and DT_RUNPATH entries is a DT_RUNPATH
    // one, for the loaders where the last entry of either wins (NetBSD).
    #[allow(dead_code)]
    runpath_last: bool,
    // Whether the object has any DT_NEEDED entry.
    has_needed: bool,
    // DT_AUXILIARY and DT_FILTER entries.
    filters: DepsVec,
    nodeflibs: bool,
    is_musl: bool,
    // The $LIB expansion of the glibc loader resolving the input object,
    // handed down to every object it loads.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    dst_lib: Option<String>,
    // The platform the glibc loader resolving the input object sets over the
    // kernel one (GLRO(dl_platform)), if any, handed down to every object it
    // loads.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    loader_platform: Option<&'static str>,
    // The ELF header flags of the input object, which the ABI of its loader
    // follows, handed down to every object it loads.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    loader_flags: FileFlags,
    // Whether DF_1_PIE is set.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pie: bool,
    // The subdirectories the loader of the input object tries first in each
    // directory it searches, best first (the glibc hwcaps ones), handed down
    // to every object it loads.
    search_subdirs: Rc<Vec<String>>,
    // The $ORIGIN expansion, None when the directory is not valid UTF-8.
    origin: Option<String>,
    // The search list entries and the dependencies dropped because of a
    // dynamic string token without a value, shown on the search path
    // information.
    unexpanded: Vec<String>,

    deps: DepsVec,
}

#[cfg(test)]
impl ElfInfo {
    // A 64-bit little-endian object of the E_MACHINE machine and E_FLAGS
    // flags, without any dynamic entry, with its origin in /o.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn for_test(e_machine: Machine, e_flags: FileFlags) -> Self {
        ElfInfo {
            ei_class: ELFCLASS64,
            ei_data: ELFDATA2LSB,
            ei_osabi: ELFOSABI_SYSV,
            ei_abiver: 0,
            e_machine,
            e_flags,
            interp: None,
            soname: None,
            dt_rpath: None,
            dt_runpath: None,
            needed: Vec::new(),
            rpath: search_path::SearchPathVec::new(),
            runpath: search_path::SearchPathVec::new(),
            has_runpath: false,
            runpath_last: false,
            has_needed: false,
            filters: DepsVec::new(),
            nodeflibs: false,
            is_musl: false,
            dst_lib: Some("lib64".to_string()),
            loader_platform: None,
            loader_flags: e_flags,
            pie: false,
            search_subdirs: Rc::default(),
            origin: Some("/o".to_string()),
            unexpanded: Vec::new(),
            deps: DepsVec::new(),
        }
    }
}

// ELF Parsing routines.

fn parse_object(data: &[u8]) -> Result<ElfInfo, &'static str> {
    match object::FileKind::parse(data).map_err(|_| "Failed to parse file")? {
        object::FileKind::Elf32 => {
            let elf =
                FileHeader32::<Endianness>::parse(data).map_err(|_| "Invalid ELF32 object")?;
            parse_elf(elf, data)
        }
        object::FileKind::Elf64 => {
            let elf =
                FileHeader64::<Endianness>::parse(data).map_err(|_| "Invalid ELF64 object")?;
            parse_elf(elf, data)
        }
        _ => Err("Invalid object"),
    }
}

fn parse_elf<Elf: FileHeader<Endian = Endianness>>(
    elf: &Elf,
    data: &[u8],
) -> Result<ElfInfo, &'static str> {
    let endian = elf.endian().map_err(|_| "invalid endianess")?;
    match elf.e_type(endian) {
        ET_EXEC | ET_DYN => {}
        _ => return Err("Invalid ELF file"),
    }
    let segments = elf
        .program_headers(endian, data)
        .map_err(|_| "invalid segment")?;
    parse_elf_program_headers(endian, data, elf, segments)
}

#[cfg(target_os = "linux")]
fn is_musl_system() -> bool {
    use std::sync::OnceLock;
    static MUSL_SYSTEM: OnceLock<bool> = OnceLock::new();
    *MUSL_SYSTEM
        .get_or_init(|| !Path::new("/etc/ld.so.cache").exists() && find_musl_loader().is_some())
}

fn parse_elf_program_headers<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    headers: &[Elf::ProgramHeader],
) -> Result<ElfInfo, &'static str> {
    let mut elc = parse_elf_dynamic_program_header(endian, data, elf, headers)?;
    elc.interp = parse_elf_interp::<Elf>(endian, data, headers);
    Ok(elc)
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
) -> Result<ElfInfo, &'static str> {
    match headers
        .iter()
        .find(|&&hdr| hdr.p_type(endian) == PT_DYNAMIC)
    {
        Some(hdr) => parse_elf_segment_dynamic(endian, data, elf, headers, hdr),
        None => Err("No dynamic segments found"),
    }
}

fn parse_elf_segment_dynamic<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segments: &[Elf::ProgramHeader],
    segment: &Elf::ProgramHeader,
) -> Result<ElfInfo, &'static str> {
    if let Some(dynamic) = dynamic_entries::<Elf>(endian, data, segment) {
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
        for d in dynamic {
            let tag = d.d_tag(endian);
            if tag == DT_NULL {
                break;
            } else if tag == DT_STRTAB {
                strtab = d.d_val(endian).into();
            } else if tag == DT_STRSZ {
                strsz = d.d_val(endian).into();
            }
        }

        let dynstr = match parse_elf_stringtable::<Elf>(endian, data, segments, strtab, strsz) {
            Some(dynstr) => dynstr,
            None => return Err("Failure to parse the string table"),
        };

        let tags = DynamicTags::parse::<Elf>(endian, dynamic, dynstr);
        let nodeflibs = DynamicFlags1(tags.flags_1).contains(DF_1_NODEFLIB);

        let (needed, has_needed) = parse_elf_dtneeded::<Elf>(endian, dynamic, dynstr);
        return Ok(ElfInfo {
            ei_class: elf.e_ident().class,
            ei_data: elf.e_ident().data,
            ei_osabi: elf.e_ident().os_abi,
            ei_abiver: elf.e_ident().abi_version,
            e_machine: elf.e_machine(endian),
            e_flags: elf.e_flags(endian),
            interp: None,
            dt_rpath: tags.rpath,
            dt_runpath: tags.runpath,
            needed,
            rpath: search_path::SearchPathVec::new(),
            runpath: search_path::SearchPathVec::new(),
            has_runpath: tags.has_runpath,
            runpath_last: tags.runpath_last,
            soname: tags.soname,
            nodeflibs,
            deps: DepsVec::new(),
            has_needed,
            filters: DepsVec::new(),
            is_musl: false,
            dst_lib: None,
            loader_platform: None,
            loader_flags: elf.e_flags(endian),
            pie: DynamicFlags1(tags.flags_1).contains(DF_1_PIE),
            search_subdirs: Rc::default(),
            origin: None,
            unexpanded: Vec::new(),
        });
    }
    Err("Failure to parse dynamic segment")
}

// The entries of the PT_DYNAMIC SEGMENT.
fn dynamic_entries<'data, Elf: FileHeader>(
    endian: Elf::Endian,
    data: &'data [u8],
    segment: &Elf::ProgramHeader,
) -> Option<&'data [Elf::Dyn]> {
    match segment.dynamic(endian, data) {
        Ok(Some(dynamic)) => Some(dynamic),
        // A PT_DYNAMIC whose size is not a multiple of the entry size, the
        // the loader reads up to DT_NULL regardless.
        _ => segment.data(endian, data).ok().and_then(|bytes| {
            let count = bytes.len() / std::mem::size_of::<Elf::Dyn>();
            object::slice_from_bytes::<Elf::Dyn>(bytes, count)
                .ok()
                .map(|(dynamic, _)| dynamic)
        }),
    }
}

// The dynamic tags read up to DT_NULL, each one holding the value of its
// last entry, the way the loaders record them (elf_get_dynamic_info on
// glibc).
#[derive(Default)]
struct DynamicTags {
    soname: Option<String>,
    rpath: Option<String>,
    runpath: Option<String>,
    // Whether DT_RUNPATH is present, whatever its string.
    has_runpath: bool,
    // Whether the last of the DT_RPATH and DT_RUNPATH entries is a
    // DT_RUNPATH one.
    runpath_last: bool,
    flags_1: u64,
}

impl DynamicTags {
    fn parse<Elf: FileHeader>(
        endian: Elf::Endian,
        dynamic: &[Elf::Dyn],
        dynstr: StringTable,
    ) -> Self {
        let mut r = Self::default();
        for d in dynamic {
            let tag = d.d_tag(endian);
            if tag == DT_NULL {
                break;
            }
            if d.tag32(endian).is_none() {
                continue;
            }
            let field = match tag {
                DT_SONAME => &mut r.soname,
                DT_RPATH => {
                    r.runpath_last = false;
                    &mut r.rpath
                }
                DT_RUNPATH => {
                    r.has_runpath = true;
                    r.runpath_last = true;
                    &mut r.runpath
                }
                DT_FLAGS_1 => {
                    r.flags_1 = d.d_val(endian).into();
                    continue;
                }
                _ => continue,
            };
            *field = d
                .string(endian, dynstr)
                .ok()
                .and_then(|s| str::from_utf8(s).ok())
                .map(str::to_string);
        }
        r
    }
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

fn parse_elf_dtneeded<Elf: FileHeader>(
    endian: Elf::Endian,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
) -> (Vec<(String, bool)>, bool) {
    let mut needed = Vec::new();
    let mut has_needed = false;
    for d in dynamic {
        let tag = d.d_tag(endian);
        if tag == DT_NULL {
            break;
        }

        // Only the glibc loader loads a filtee.
        let filter = cfg!(target_os = "linux") && (tag == DT_AUXILIARY || tag == DT_FILTER);
        if d.tag32(endian).is_none() || !(tag == DT_NEEDED || filter) {
            continue;
        }
        has_needed |= tag == DT_NEEDED;

        if let Ok(s) = d.string(endian, dynstr) {
            needed.push((String::from_utf8_lossy(s).into_owned(), tag != DT_NEEDED));
        }
    }
    (needed, has_needed)
}

// Fill the ELC object search lists and dependencies, expanding the dynamic
// string tokens the way its loader does, and apply the loader rules to the
// search lists.
fn expand_object(elc: &mut ElfInfo, platform: Option<&String>) {
    use search_path::SearchPathVecExt;

    let mut unexpanded = Vec::new();
    let mut search_list = |list: &Option<String>| {
        let mut r = search_path::SearchPathVec::new();
        let entries = list
            .iter()
            .flat_map(|list| Rtld::search_list(list, TokenSite::SearchPath, elc, platform));
        for entry in entries {
            match entry {
                Ok(dir) => {
                    r.add_path(&dir);
                }
                Err(entry) => unexpanded.push(entry),
            }
        }
        r
    };
    let rpath = search_list(&elc.dt_rpath);
    let runpath = search_list(&elc.dt_runpath);

    // A dependency whose expansion fails is not loaded at all (the glibc
    // expand_dst in _dl_map_object_deps).
    let mut deps = DepsVec::new();
    let mut filters = DepsVec::new();
    for (name, filter) in &elc.needed {
        match Rtld::expand_tokens(name, TokenSite::Needed, elc, platform) {
            Some(name) => {
                if *filter {
                    filters.push(name.clone());
                }
                deps.push(name);
            }
            None => unexpanded.push(name.clone()),
        }
    }

    elc.rpath = rpath;
    elc.runpath = runpath;
    elc.deps = deps;
    elc.filters = filters;
    elc.unexpanded = unexpanded;
    Rtld::handle_search_paths(elc);
}

// Open FILENAME, the input object when MELC is None or a dependency of MELC
// otherwise.  The open error of the input object is returned as is.
fn open_elf_file<P: AsRef<Path>>(
    filename: &P,
    melc: Option<&ElfInfo>,
    platform: Option<&String>,
    _preload: bool,
) -> Result<ElfInfo, std::io::Error> {
    if let Some(melc) = melc {
        return open_dependency(filename, melc, platform).map_err(|e| match e {
            Rejection::Skip(e) | Rejection::Fatal(e) => Error::other(e),
        });
    }
    let file = fs::File::open(filename)?;
    let mmap = pathutils::map(&file)?;

    let mut elc = parse_object(&mmap).map_err(Error::other)?;
    elc.origin = Rtld::origin_directory(filename, None);
    // The tokens of the input object are expanded by the caller, once its
    // loader is known.
    Rtld::handle_loader(&mut elc, None);
    Ok(elc)
}

// Open FILENAME as a candidate for a dependency (or a preload entry) of the
// MELC object, following the loader checks.  The loaders do not check the
// DT_SONAME of the file they open against the name requested, only its ELF
// header against the loading object.
fn open_dependency<P: AsRef<Path>>(
    filename: &P,
    melc: &ElfInfo,
    platform: Option<&String>,
) -> Result<ElfInfo, Rejection> {
    // The loaders go on with the search on a file they can not open.
    let file = fs::File::open(filename).map_err(|e| {
        Rejection::Skip(format!(
            "cannot open shared object file: {}",
            io_error_description(&e)
        ))
    })?;
    // A file that can not be read (a directory) is checked as an empty one.
    let mmap = pathutils::map(&file).ok();
    let data: &[u8] = mmap.as_deref().unwrap_or_default();

    let parsed = parse_object(data);
    Rtld::check_candidate(data, &parsed, melc)?;
    let Ok(mut elc) = parsed else {
        return Err(Rejection::Skip("not a dynamic object".to_string()));
    };

    elc.origin = Rtld::origin_directory(filename, Some(melc));
    Rtld::handle_loader(&mut elc, Some(melc));
    expand_object(&mut elc, platform);
    Ok(elc)
}

// The description of the E error, without the code the Display adds.
fn io_error_description(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error") {
        Some(pos) => s[..pos].to_string(),
        None => s,
    }
}

// The resolution of a dependency: the object found, or the error the loader
// fails the load with.
type Resolution<'a> = Result<ResolvedDependency<'a>, String>;

fn match_elf_header(a1: &ElfInfo, a2: &ElfInfo) -> bool {
    a1.ei_class == a2.ei_class && a1.ei_data == a2.ei_data && a1.e_machine == a2.e_machine
}

// Global configuration used on program dynamic resolution:
// - ld_preload: Preload entries from --preload and ld.so.preload, either file
//   paths or names to be searched like a regular dependency.
// - ld_library_path: Search path parsed from --ld-library-path.
// - ld_so_conf: paths parsed from the ld.so.conf in the system.
// - system_dirs: system defaults deirectories based on binary architecture.
struct Config<'a> {
    ld_preload: &'a [String],
    ld_library_path: search_path::SearchPathVec,
    ld_cache: &'a Option<LoaderCache>,
    system_dirs: search_path::SearchPathVec,
    platform: Option<&'a String>,
    all: bool,
    // The FreeBSD libmap.conf, which rtld adds mappings to while it resolves.
    #[cfg(any(target_os = "freebsd", all(test, target_os = "linux")))]
    libmap: Option<std::cell::RefCell<ld_libmap_freebsd::LibMap>>,
}

fn push_searched(r: &mut Vec<String>, name: &str, searchpaths: &search_path::SearchPathVec) {
    if !searchpaths.is_empty() {
        r.push(format!("{name}: {}", search_path::format_list(searchpaths)));
    }
}

// Describe the locations searched while failing to resolve a dependency, shown
// on the not found diagnostics in verbose mode.
fn searched_locations(
    config: &Config,
    elc: &ElfInfo,
    dependency: &str,
    preload: bool,
) -> Vec<String> {
    let mut r = Vec::new();
    if Path::new(dependency).is_absolute() {
        r.push(dependency.to_string());
        return r;
    }
    for step in Rtld::search_order(elc, preload) {
        let rule = nodeflib_rule(*step, elc);
        // The locations outside the default paths.
        let outside = if rule == NodeflibRule::OutsideSystemDirs {
            " outside the default paths"
        } else {
            ""
        };
        match step {
            _ if rule == NodeflibRule::Skip => {}
            SearchStep::Rpath => {
                if Rtld::rpath_search(elc) {
                    push_searched(&mut r, "rpath", &elc.rpath);
                }
            }
            SearchStep::LibraryPath => {
                push_searched(&mut r, "library path", &config.ld_library_path)
            }
            SearchStep::Runpath => push_searched(&mut r, "runpath", &elc.runpath),
            SearchStep::Cache => {
                if config.ld_cache.is_some() {
                    r.push(format!("cache {}{outside}", DepMode::LdCache));
                }
            }
            SearchStep::SystemDirs => {
                push_searched(&mut r, "default paths", &config.system_dirs);
            }
        }
    }
    if !elc.search_subdirs.is_empty() {
        r.push(format!(
            "each directory under {} first",
            search_path::format_entries(elc.search_subdirs.iter().map(String::as_str))
        ));
    }
    r
}

// The search order for a dependency name, following each loader semantics.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
enum SearchStep {
    Rpath,
    LibraryPath,
    Runpath,
    Cache,
    SystemDirs,
}

// How DF_1_NODEFLIB on the object requesting a dependency restricts a search
// step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum NodeflibRule {
    // The step is searched as usual.
    Search,
    // The step is not searched.
    Skip,
    // Only an object outside the default directories is taken (a glibc
    // loader cache entry, see _dl_map_object).
    OutsideSystemDirs,
}

// The DF_1_NODEFLIB restriction of the STEP search for the ELC requesting
// object.
fn nodeflib_rule(step: SearchStep, elc: &ElfInfo) -> NodeflibRule {
    if elc.nodeflibs {
        Rtld::nodeflib_rule(step, elc)
    } else {
        NodeflibRule::Search
    }
}

// Whether the NAME object in DIR lies below one of the SYSTEM_DIRS, compared
// as path prefixes the way the glibc loader does.
fn in_system_dirs(system_dirs: &search_path::SearchPathVec, dir: &str, name: &str) -> bool {
    let path = pathutils::join(dir, name);
    system_dirs.iter().any(|sysdir| {
        let prefix = sysdir.path.trim_end_matches('/');
        path.strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
    })
}

// Where a dynamic string token is expanded, since the loaders expand them
// on different entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenSite {
    // A DT_RPATH or DT_RUNPATH entry.
    SearchPath,
    // A DT_NEEDED, DT_AUXILIARY or DT_FILTER entry.
    Needed,
    // A --library-path (LD_LIBRARY_PATH) entry, expanded for the input
    // object.
    LibraryPath,
    // A --preload (LD_PRELOAD) or ld.so.preload entry, expanded for the input
    // object.
    Preload,
}

fn print_search_path_information<P: AsRef<Path>>(filename: &P, config: &Config, elc: &ElfInfo) {
    outln!(
        "{}: search path information\n\
        \x20 rpath: {}\n\
        \x20 preload: {}\n\
        \x20 library path: {}\n\
        \x20 runpath: {}\n\
        \x20 cache ({}): {}\n\
        \x20 default paths: {}",
        filename.as_ref().display(),
        search_path::format_list(&elc.rpath),
        search_path::format_entries(config.ld_preload.iter().map(String::as_str)),
        search_path::format_list(&config.ld_library_path),
        search_path::format_list(&elc.runpath),
        DepMode::LdCache,
        config
            .ld_cache
            .as_ref()
            .map_or(search_path::EMPTY_LIST.to_string(), |cache| cache.summary()),
        search_path::format_list(&config.system_dirs),
    );
    // The subdirectories tried in each directory of the lists above (but the
    // cache) before the directory itself.
    if !elc.search_subdirs.is_empty() {
        outln!(
            "  subdirectories: {}",
            search_path::format_entries(elc.search_subdirs.iter().map(String::as_str))
        );
    }
    // The entries the loader drops because a token has no value (a $PLATFORM
    // the kernel does not provide, or a directory that is not valid UTF-8
    // for $ORIGIN).
    if !elc.unexpanded.is_empty() {
        outln!(
            "  unexpanded: {}",
            search_path::format_entries(elc.unexpanded.iter().map(String::as_str))
        );
    }
}

#[cfg(target_os = "linux")]
fn find_musl_loader() -> Option<String> {
    for entry in fs::read_dir("/lib").ok()?.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with("ld-musl-") && name.ends_with(".so.1") {
                return Some(format!("/lib/{name}"));
            }
        }
    }
    None
}

// The resolution context: the loader search cache along with the command line
// settings.  The --preload and --library-path lists are kept as given, since
// how the loader splits them and expands their tokens depends on the input
// object.
pub struct ElfContext {
    // Lazy loaded if the binary has a loader that actually supports it.
    ld_cache: Option<LoaderCache>,
    ld_preload: String,
    ld_library_path: String,
    platform: Option<String>,
    all: bool,
    verbose: bool,
}

pub fn create_context(opts: &crate::Options) -> Result<ElfContext, String> {
    Ok(ElfContext {
        ld_cache: None,
        ld_preload: opts.preload.clone(),
        ld_library_path: opts.library_path.clone(),
        platform: opts.platform.clone(),
        all: opts.all,
        verbose: opts.verbose,
    })
}

// The --library-path directories for the ELC input object, with the entries
// the token expansion drops recorded on it.
fn library_path_list(
    list: &str,
    elc: &mut ElfInfo,
    platform: Option<&String>,
) -> search_path::SearchPathVec {
    use search_path::SearchPathVecExt;

    let mut r = search_path::SearchPathVec::new();
    for entry in Rtld::search_list(list, TokenSite::LibraryPath, elc, platform) {
        match entry {
            Ok(dir) => {
                r.add_path(&dir);
            }
            Err(entry) => elc.unexpanded.push(entry),
        }
    }
    r
}

pub fn resolve_binary(ctx: &mut ElfContext, arg: &str) -> Result<DepTree, std::io::Error> {
    // On glibc/Linux the RTLD_DI_ORIGIN for the executable itself (used for $ORIGIN
    // expansion) is obtained by first following the '/proc/self/exe' symlink and if
    // it is not available the loader also checks the 'LD_ORIGIN_PATH' environment
    // variable.
    // The '/proc/self/exec' is an absolute path and to mimic loader behavior we first
    // try to canocalize the input filename to remove any symlinks.  There is not much
    // sense in trying LD_ORIGIN_PATH, since it is only checked by the loader if
    // the binary can not dereference the procfs entry.
    let filename = Path::new(arg).canonicalize()?;

    let elc = open_elf_file(&filename, None, ctx.platform.as_ref(), false)?;

    // The loader might inspect another file than the one given.
    let (filename, mut elc) = Rtld::redirect_root(filename, elc, ctx.platform.as_ref());
    elc.origin = Rtld::root_origin_directory(Path::new(arg), &filename, &elc);

    // The cache/hints/config file is usually an optional file and failing to open it
    // does not incur on a resolution failure.
    Rtld::load_so_cache(&mut ctx.ld_cache, &filename, &elc);

    #[cfg(target_os = "linux")]
    let loader = elc.interp.clone().or_else(|| {
        ctx.ld_cache.as_ref().and_then(|cache| {
            interp::glibc_names()
                .iter()
                .find_map(|name| cache.get(*name).map(|dir| format!("{dir}/{name}")))
        })
    });

    let system_dirs = if Rtld::load_system_dirs(&ctx.ld_cache) {
        #[cfg(target_os = "linux")]
        let dirs = system_dirs::get_system_dirs(loader.as_deref(), &elc)?;
        #[cfg(not(target_os = "linux"))]
        let dirs = system_dirs::get_system_dirs(&elc)?;
        dirs
    } else {
        search_path::SearchPathVec::new()
    };

    // The $LIB expansion and the hwcaps subdirectories are built into the
    // glibc loader.
    #[cfg(target_os = "linux")]
    if !elc.is_musl {
        elc.dst_lib = system_dirs::get_dst_lib(loader.as_deref(), &elc);
        elc.loader_platform = system_dirs::get_loader_platform(&elc);
        elc.search_subdirs = Rc::new(system_dirs::get_search_subdirs(
            loader.as_deref(),
            &elc,
            ctx.platform.as_deref(),
        ));
    }

    expand_object(&mut elc, ctx.platform.as_ref());
    let ld_library_path = library_path_list(&ctx.ld_library_path, &mut elc, ctx.platform.as_ref());

    // Same for glibc ld.so.preload file.
    let mut preload = Rtld::preload_list(&ctx.ld_preload, &elc);
    // glibc first parses LD_PRELOAD and then ld.so.preload.
    // We need a new vector for the case of binaries with different interpreters.
    preload.extend(Rtld::load_ld_so_preload(&elc.interp));

    // The trace reports an object without any DT_NEEDED entry as statically
    // linked, and does not list the filtees of the root object (it lists the ones of
    // a dependency).
    if !elc.has_needed {
        elc.deps.clear();
    } else if !elc.filters.is_empty() {
        // By name: the trace drops a filtee of the root object even when a
        // DT_NEEDED entry names it too.
        elc.deps.retain(|dep| !elc.filters.contains(dep));
    }

    // DT_RPATH is ignored if the object also defines DT_RUNPATH (the latter only
    // applies to the object own dependencies, so it is not propagated).
    if elc.has_runpath {
        elc.rpath.clear();
    }

    let config = Config {
        ld_preload: &preload,
        ld_library_path,
        ld_cache: &ctx.ld_cache,
        system_dirs,
        platform: ctx.platform.as_ref(),
        all: ctx.all,
        #[cfg(target_os = "freebsd")]
        libmap: ld_libmap_freebsd::parse_libmap(&ld_libmap_freebsd::libmap_path(elc.ei_class))
            .map(std::cell::RefCell::new),
        #[cfg(all(test, target_os = "linux"))]
        libmap: None,
    };

    if ctx.verbose {
        print_search_path_information(&filename, &config, &elc);
    }

    let mut deptree = DepTree::new();

    let depp = deptree.addroot(DepNode::from_path(&filename, DepMode::Executable));

    Rtld::resolve_binary_arch(&elc, &mut deptree, depp)?;

    let refpath = filename.to_string_lossy().into_owned();
    resolve_dependencies(&config, elc, refpath, &mut deptree, depp);

    Ok(deptree)
}

// Returned from resolve_dependency_1 with resolved information.
#[derive(Debug)]
struct ResolvedDependency<'a> {
    elc: ElfInfo,
    // The directory the object was found at, which a search subdirectory
    // makes another one than the search path entry, or the path of a
    // dependency naming one (owned when the loader maps it, like the FreeBSD
    // libmap).
    path: Cow<'a, str>,
    // The resolved file name, which might differ from the DT_NEEDED entry
    // (for instance on OpenBSD minor version matching).
    filename: String,
    mode: DepMode,
    // The namespace the object was loaded in, used to resolve its own
    // dependencies (Android only).
    namespace: ObjectNamespace,
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

// An object already loaded, used to resolve its own dependencies: its
// information (rpath chain), its path (the libmap reference path), and the
// namespace it was loaded in (Android only).
struct LoadedObject {
    elc: ElfInfo,
    refpath: String,
    namespace: ObjectNamespace,
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
    use std::collections::{HashMap, VecDeque};
    use std::os::unix::fs::MetadataExt;

    // The already loaded objects, the input one first.
    let mut parents: Vec<LoadedObject> = Vec::new();
    // The tree nodes of the objects found, looked up by name.
    #[cfg(not(target_os = "android"))]
    let mut found = FoundIndex::default();
    // The Android linker only looks up the objects its namespaces loaded,
    // where the input object is on all of them.
    #[cfg(target_os = "android")]
    let mut namespaces = android::LoadedObjects::default();
    #[cfg(target_os = "android")]
    namespaces.record(
        &None,
        true,
        root_elc.soname.as_deref(),
        fs::metadata(&root_refpath).ok().map(|m| (m.dev(), m.ino())),
        root_depp,
    );
    // The tree node of the first object loaded with each soname, and with
    // each device and inode.
    let mut sonames: HashMap<String, usize> = HashMap::new();
    let mut file_ids: HashMap<(u64, u64), usize> = HashMap::new();
    // The tree node of the object loaded for each name requested.
    let mut requested: HashMap<String, usize> = HashMap::new();

    let mut queue = VecDeque::new();
    // The glibc loader trace prints 'statically linked' for an object without
    // any DT_NEEDED entry, whatever else was preloaded, so the preload
    // entries are only tracked for objects with dependencies.  The musl
    // loader always loads the preloaded objects.
    if root_elc.is_musl || !root_elc.deps.is_empty() {
        for name in config.ld_preload {
            queue.push_back(WorkItem {
                dependency: name.clone(),
                parent: 0,
                depp: root_depp,
                preload: true,
            });
        }
    }
    for dep in &root_elc.deps {
        queue.push_back(WorkItem {
            dependency: dep.clone(),
            parent: 0,
            depp: root_depp,
            preload: false,
        });
    }

    #[cfg(target_os = "linux")]
    let musl_loader = if root_elc.is_musl {
        musl_loader_path(&root_elc)
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let mut musl_reported = [false; interp::MUSL_RESERVED_COUNT];

    // The OpenBSD loader can not load two libc versions in a single process,
    // so use the first one.
    #[cfg(target_os = "openbsd")]
    let mut openbsd_libc: Option<String> = None;

    parents.push(LoadedObject {
        elc: root_elc,
        refpath: root_refpath,
        namespace: Default::default(),
    });

    while let Some(item) = queue.pop_front() {
        let LoadedObject {
            elc,
            refpath,
            namespace,
            ..
        } = &parents[item.parent];
        let root_elc = &parents[0].elc;

        // The tokens of a preload entry are expanded for the main object, and
        // an entry whose expansion fails is not loaded.
        let dependency = if item.preload {
            match Rtld::expand_tokens(
                &item.dependency,
                TokenSite::Preload,
                root_elc,
                config.platform,
            ) {
                Some(dependency) => dependency,
                None => {
                    deptree.addnode(
                        DepNode::not_found(item.dependency.clone(), Vec::new()),
                        item.depp,
                    );
                    continue;
                }
            }
        } else {
            item.dependency.clone()
        };

        #[cfg(target_os = "openbsd")]
        let dependency = match &openbsd_libc {
            Some(libc) if dependency.starts_with("libc.so.") => libc.clone(),
            _ => {
                if dependency.starts_with("libc.so.") {
                    openbsd_libc = Some(dependency.clone());
                }
                dependency
            }
        };
        let dependency = &dependency;

        #[cfg(target_os = "linux")]
        if let Some(loader) = &musl_loader {
            let loader_path = Path::new(loader);
            let is_self = pathutils::get_name(&loader_path) == *dependency;
            match interp::musl_reserved_name(dependency) {
                Some(slot) if !musl_reported[slot] => {
                    musl_reported[slot] = true;
                    deptree.addnode(
                        DepNode::from_path(&loader_path, DepMode::SystemDirs)
                            .with_alias(Some(dependency.clone())),
                        item.depp,
                    );
                    continue;
                }
                Some(_) => continue,
                None if is_self => {
                    // The loader own name is also blocked from reloading,
                    // without any report.  Record it as an already resolved
                    // entry so the symbol scope knows the libc is linked.
                    deptree.addnode(
                        DepNode::from_path(&loader_path, DepMode::SystemDirs)
                            .already_found()
                            .with_alias(Some(dependency.clone())),
                        item.depp,
                    );
                    continue;
                }
                None => {}
            }
        }

        // The glibc and FreeBSD loaders also match a name against the main
        // object DT_SONAME.
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        if !elc.is_musl && root_elc.soname.as_deref() == Some(dependency.as_str()) {
            continue;
        }

        // The vDSO the kernel maps is on the loaded list of the bionic and
        // the glibc loaders under its soname, so a DT_NEEDED naming it is
        // already loaded (musl does not match it).
        #[cfg(any(target_os = "android", target_os = "linux"))]
        if !elc.is_musl
            && matches!(
                dependency.as_str(),
                "linux-vdso.so.1" | "linux-gate.so.1" | "linux-vdso32.so.1" | "linux-vdso64.so.1"
            )
        {
            continue;
        }

        // The loaders match a name against the objects already loaded before
        // any search, so DF_1_NODEFLIB does not apply there (only to the
        // search itself).  The glibc loader also matches a name against the
        // DT_SONAME of the objects already loaded, so a library loaded through
        // a symlink named otherwise is not loaded again under its soname.
        // A name not found is searched again for each object requesting
        // it, with the search paths of that object.  The loader skips the
        // faked entries of its trace when matching the names, so a name a
        // module fails on resolves for a library with the run path.
        // A dependency referring back to the root object by its path is
        // resolved too, since the loader records the name on it and the
        // trace lists it once.  The names are matched as requested, before
        // the loader maps them (the FreeBSD libmap), since they are the ones
        // it records.
        #[cfg(not(target_os = "android"))]
        let loaded = found
            .find(deptree, dependency)
            .or_else(|| requested.get(dependency.as_str()).copied());
        #[cfg(target_os = "linux")]
        let loaded = loaded.or_else(|| {
            if elc.is_musl {
                return None;
            }
            sonames.get(dependency.as_str()).copied()
        });
        // The Android linker is on every namespace under its own soname.
        #[cfg(target_os = "android")]
        if let Some(node) = Rtld::linker_dependency(dependency, root_elc) {
            deptree.add_repeated(config.all, node, item.depp);
            continue;
        }
        // The Android linker looks the objects up and searches the name on
        // the namespaces the requesting object sees (loader/android.rs).
        #[cfg(target_os = "android")]
        let (loaded, resolved) =
            match Rtld::find_library(config, &namespaces, elc, refpath, namespace, dependency) {
                loader::Lookup::Loaded(node) => (Some(node), None),
                loader::Lookup::Search(resolved) => (None, *resolved),
            };
        if let Some(node) = loaded {
            let entry = deptree.arena[node].val.clone();
            deptree.add_repeated(
                config.all,
                DepNode::repeat_of(&entry, pathutils::get_name(&Path::new(dependency))),
                item.depp,
            );
            continue;
        }

        // A dependency naming the program interpreter resolves to the already
        // loaded loader object. The glibc loader matches the DT_NEEDED entry
        // against its own soname without any search, so the PT_INTERP path is
        // used whatever the object search paths say.
        #[cfg(target_os = "linux")]
        if !item.preload && interp::is_glibc_name(dependency) {
            if let Some(interp) = &root_elc.interp {
                let path = Path::new(interp);
                if pathutils::get_name(&path) == *dependency && path.exists() {
                    deptree.addnode(DepNode::from_path(&path, DepMode::Direct), item.depp);
                    continue;
                }
            }
        }

        // A shared library naming the loader resolves through the cache and the
        // system directories.
        #[cfg(target_os = "linux")]
        let resolved =
            if !item.preload && interp::is_glibc_name(dependency) && root_elc.interp.is_none() {
                resolve_loader(config, elc, dependency)
            } else {
                Rtld::resolve_dependency(dependency, config, elc, refpath, namespace, item.preload)
            };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let resolved =
            Rtld::resolve_dependency(dependency, config, elc, refpath, namespace, item.preload);
        let mut dep = match resolved {
            Some(Ok(dep)) => dep,
            // The loader fails the load on the file it found (it is not an
            // object it loads), which the verbose mode shows along with the
            // error.
            Some(Err(error)) => {
                deptree.addnode(
                    DepNode::not_found(dependency.clone(), vec![error]),
                    item.depp,
                );
                continue;
            }
            None => {
                let searched = searched_locations(config, elc, dependency, item.preload);
                deptree.addnode(DepNode::not_found(dependency.clone(), searched), item.depp);
                continue;
            }
        };
        // The preload entries are always shown with the preload mode,
        // wherever the search resolved them.
        if item.preload {
            dep.mode = DepMode::Preload;
        }
        let r = if dep.mode == DepMode::Direct
            || (item.preload && dependency.contains(std::path::MAIN_SEPARATOR))
        {
            // Decompose the direct object path in path and filename so when
            // print the dependencies only the file name is showed in
            // default mode.  The preload entries given as a file path are
            // resolved with the full path, so they are decomposed the same
            // way.
            let p = Path::new(dep.path.as_ref());
            (pathutils::get_path(&p), pathutils::get_name(&p))
        } else {
            (Some(dep.path.to_string()), dep.filename.clone())
        };
        // The resolved path of this dependency, used as the reference path
        // for its own dependencies resolution.
        let depref = match &r.0 {
            Some(path) => pathutils::join(path, &r.1),
            None => r.1.clone(),
        };
        // The loaders recognize a file already loaded under another name
        // (through a symlink) by its device and inode, and record the new
        // name on the loaded object instead of loading it again.  The input
        // object is not recorded (the glibc loader has no file identity for
        // the executable it runs).  The Android linker only looks them up on
        // the namespaces (Android::find_library).
        let file_id = fs::metadata(&depref).ok().map(|m| (m.dev(), m.ino()));
        #[cfg(not(target_os = "android"))]
        if let Some(&node) = file_id.and_then(|id| file_ids.get(&id)) {
            let entry = deptree.arena[node].val.clone();
            deptree.add_repeated(
                config.all,
                DepNode::repeat_of(&entry, pathutils::get_name(&Path::new(dependency))),
                item.depp,
            );
            requested.entry(dependency.clone()).or_insert(node);
            continue;
        }
        let c = deptree.addnode(Rtld::loaded_node(r.0, r.1, dep.mode, dependency), item.depp);
        if let Some(id) = file_id {
            file_ids.entry(id).or_insert(c);
        }
        requested.entry(dependency.clone()).or_insert(c);
        if let Some(soname) = &dep.elc.soname {
            sonames.entry(soname.clone()).or_insert(c);
        }
        // The linker adds the preloaded objects to every namespace.
        #[cfg(target_os = "android")]
        namespaces.record(
            &dep.namespace,
            item.preload && item.parent == 0,
            dep.elc.soname.as_deref(),
            file_id,
            c,
        );

        // The DT_RPATH scope used for the indirect dependencies is system
        // specific: the glibc loader searches the object own DT_RPATH and
        // then walks up the chain of loading objects (up to the
        // executable), the FreeBSD and OpenBSD loaders search the object
        // own DT_RPATH and then the main object one (neither when the
        // object has DT_RUNPATH), while the NetBSD loader only searches the
        // requesting object DT_RPATH.  In all cases an object DT_RPATH is
        // ignored if the object also defines DT_RUNPATH, without affecting
        // the inherited part
        if dep.elc.has_runpath {
            dep.elc.rpath.clear();
        }
        #[cfg(target_os = "linux")]
        dep.elc.rpath.extend(elc.rpath.clone());
        #[cfg(target_os = "freebsd")]
        if !dep.elc.has_runpath && root_elc.interp.is_some() {
            dep.elc.rpath.extend(root_elc.rpath.clone());
        }
        #[cfg(target_os = "openbsd")]
        if root_elc.interp.is_some() {
            dep.elc.rpath.extend(root_elc.rpath.clone());
        }

        let parent = parents.len();
        for sdep in &dep.elc.deps {
            queue.push_back(WorkItem {
                dependency: sdep.clone(),
                parent,
                depp: c,
                preload: item.preload,
            });
        }
        parents.push(LoadedObject {
            elc: dep.elc,
            refpath: depref,
            namespace: dep.namespace,
        });
    }

    Rtld::add_loader_dependency(config, &parents[0].elc, deptree, root_depp);
}

// The loader is not subject to the dependency search, and only the soname
// matching the object architecture resolves.
#[cfg(target_os = "linux")]
fn resolve_loader<'a>(
    config: &'a Config,
    elc: &'a ElfInfo,
    dtneeded: &str,
) -> Option<Resolution<'a>> {
    if let Some(ld_cache) = config.ld_cache {
        if let Some(dep) = ld_cache.resolve(dtneeded, config.platform, elc, &Default::default()) {
            return Some(dep);
        }
    }
    search_dirs(
        &config.system_dirs,
        dtneeded,
        elc,
        config.platform,
        DepMode::SystemDirs,
        &Default::default(),
    )
}

// Try DTNEEDED on the DIR directory, returning it when the object there
// matches the requesting ELC one, or the error when the loader fails the
// load on it.
fn search_dir<'a>(
    dir: impl Into<Cow<'a, str>>,
    dtneeded: &str,
    elc: &ElfInfo,
    platform: Option<&String>,
    mode: DepMode,
    namespace: &ObjectNamespace,
) -> Option<Resolution<'a>> {
    let dir = dir.into();
    let path = Rtld::dependency_path(&dir, dtneeded);
    match open_dependency(&path, elc, platform) {
        Ok(elc) => Some(Ok(ResolvedDependency {
            elc,
            path: dir,
            filename: pathutils::get_name(&path),
            mode,
            namespace: namespace.clone(),
        })),
        Err(Rejection::Skip(_)) => None,
        Err(Rejection::Fatal(e)) => Some(Err(format!("{}: {e}", path.display()))),
    }
}

// Search DTNEEDED on each of the SEARCHPATHS in order, returning the first
// directory with a matching object (or where the loader fails).  The search
// subdirectories of each directory, if any, are tried before it (the glibc
// open_path, with the capability subdirectories of each r_search_path
// entry).
fn search_dirs<'a>(
    searchpaths: &'a search_path::SearchPathVec,
    dtneeded: &str,
    elc: &ElfInfo,
    platform: Option<&String>,
    mode: DepMode,
    namespace: &ObjectNamespace,
) -> Option<Resolution<'a>> {
    searchpaths.iter().find_map(|searchpath| {
        let dir = &searchpath.path;
        elc.search_subdirs
            .iter()
            .find_map(|subdir| {
                search_dir(
                    subdir_path(dir, subdir),
                    dtneeded,
                    elc,
                    platform,
                    mode,
                    namespace,
                )
            })
            .or_else(|| search_dir(dir.as_str(), dtneeded, elc, platform, mode, namespace))
    })
}

// The SUBDIR subdirectory of the DIR search directory.
fn subdir_path(dir: &str, subdir: &str) -> String {
    format!("{}/{subdir}", dir.strip_suffix('/').unwrap_or(dir))
}

// Open the NAME file path, relative to the current directory when it is not
// absolute, as a dependency (or a preload entry) of ELC: it is not searched.
fn open_path_dependency<'a>(
    name: Cow<'a, str>,
    config: &Config,
    elc: &ElfInfo,
    namespace: &ObjectNamespace,
    preload: bool,
) -> Resolution<'a> {
    let path = Path::new(name.as_ref());
    // The preload entries go through the same checks.
    match open_dependency(&path, elc, config.platform) {
        Ok(elc) => Ok(ResolvedDependency {
            elc,
            filename: pathutils::get_name(&path),
            path: name,
            mode: if preload {
                DepMode::Preload
            } else {
                DepMode::Direct
            },
            namespace: namespace.clone(),
        }),
        Err(Rejection::Skip(e) | Rejection::Fatal(e)) => Err(format!("{name}: {e}")),
    }
}

// The Android dependencies are searched on the linker namespaces instead
// (Android::find_library).
#[cfg_attr(target_os = "android", allow(dead_code))]
fn resolve_dependency_1<'a>(
    dtneeded: &'a String,
    config: &'a Config,
    elc: &'a ElfInfo,
    // Android only: the namespace of the object requesting the dependency.
    namespace: &ObjectNamespace,
    preload: bool,
) -> Option<Resolution<'a>> {
    // A name containing a slash is a file path, which is not searched. The
    // glibc loader only search the bare names, for the dependencies as for
    // the preload entries.
    // The NetBSD loader opens every preload entry as a file path.
    let is_path =
        dtneeded.contains(std::path::MAIN_SEPARATOR) || (preload && cfg!(target_os = "netbsd"));
    if is_path {
        return Some(open_path_dependency(
            dtneeded.into(),
            config,
            elc,
            namespace,
            preload,
        ));
    }

    let search = |searchpaths: &'a search_path::SearchPathVec, mode: DepMode| {
        search_dirs(searchpaths, dtneeded, elc, config.platform, mode, namespace)
    };

    for step in Rtld::search_order(elc, preload) {
        let rule = nodeflib_rule(*step, elc);
        let dep = match step {
            _ if rule == NodeflibRule::Skip => None,
            // The rpath field holds the object own DT_RPATH along with any
            // inherited part.  The glibc loader skips the whole search
            // (including the inherited chain) if the object issuing the load
            // has a DT_RUNPATH, and so do the FreeBSD and OpenBSD loaders
            // for the main program DT_RPATH they add (find_library,
            // _dl_load_shlib).
            SearchStep::Rpath if Rtld::rpath_search(elc) => search(&elc.rpath, DepMode::DtRpath),
            SearchStep::Rpath => None,
            SearchStep::LibraryPath => search(&config.ld_library_path, DepMode::LdLibraryPath),
            SearchStep::Runpath => search(&elc.runpath, DepMode::DtRunpath),
            SearchStep::Cache => config
                .ld_cache
                .as_ref()
                .and_then(|ld_cache| ld_cache.resolve(dtneeded, config.platform, elc, namespace)),
            SearchStep::SystemDirs => search(&config.system_dirs, DepMode::SystemDirs),
        };
        let dep = dep.filter(|dep| match dep {
            Ok(dep) => {
                rule != NodeflibRule::OutsideSystemDirs
                    || !in_system_dirs(&config.system_dirs, &dep.path, &dep.filename)
            }
            Err(_) => true,
        });
        if dep.is_some() {
            return dep;
        }
    }

    None
}

// Symbol resolution mimicking, used to implement the ldd like --data-relocs,
// --function-relocs, and --unused options.  The checks mimic the glibc loader
// and are only enabled on Linux; on Android the linker provides the loader
// symbols with mangled names, while the BSD run-time linkers were not verified.

// A version definition required by some object that the dependency providing
// it does not define, reported by the loader version check
// (_dl_check_map_versions).
#[cfg(target_os = "linux")]
pub struct VersionError {
    // Full path of the object that should provide the version.
    pub object: String,
    pub version: String,
    // Full path of the object requiring the version.
    pub required_by: String,
    pub kind: VersionErrorKind,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionErrorKind {
    // The version is not defined, which fails the load.
    NotFound,
    // A weak version (VER_FLG_WEAK) is not defined, which is only a warning.
    WeakNotFound,
    // The object defines no version at all, which is only a warning.
    NoVersionInformation,
}

// The loader diagnostic, after the name of the object that should provide the
// version (match_symbol).
#[cfg(target_os = "linux")]
impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.kind {
            VersionErrorKind::NotFound => write!(
                f,
                "{}: version `{}' not found (required by {})",
                self.object, self.version, self.required_by
            ),
            VersionErrorKind::WeakNotFound => write!(
                f,
                "{}: weak version `{}' not found (required by {})",
                self.object, self.version, self.required_by
            ),
            VersionErrorKind::NoVersionInformation => write!(
                f,
                "{}: no version information available (required by {})",
                self.object, self.required_by
            ),
        }
    }
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

// The parsing of the objects of the scope: symbols::parse, or
// symbols::parse_versions for the version check alone.
#[cfg(target_os = "linux")]
type SymbolParser = fn(&String) -> Option<symbols::ObjectSymbols>;

// Build the loader global search scope: the resolved objects from the dependency
// tree in breadth-first order (the order the loader uses for symbol resolution),
// with each object dynamic symbol table and relocation references parsed by
// PARSE.
#[cfg(target_os = "linux")]
fn build_symbol_scope(
    deptree: &DepTree,
    parse: SymbolParser,
) -> Vec<(String, symbols::ObjectSymbols)> {
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
        if let Some(obj) = parse(&path) {
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
    let mut elc = open_elf_file(&path, None, None, false).ok()?;
    elc.dst_lib = system_dirs::get_dst_lib(elc.interp.as_deref(), &elc);
    elc.loader_platform = system_dirs::get_loader_platform(&elc);
    expand_object(&mut elc, None);
    Some(elc)
}

// The dynamic loader is part of the global scope (libc binds to symbols the
// loader provides, like _rtld_global), however it might not be present in the
// dependency tree if no object lists it as an explicit dependency.
#[cfg(target_os = "linux")]
fn append_interp_to_scope(
    scope: &mut Vec<(String, symbols::ObjectSymbols)>,
    elc: &ElfInfo,
    parse: SymbolParser,
) {
    if let Some(interp) = &elc.interp {
        let name = pathutils::get_name(&Path::new(interp));
        if scope
            .iter()
            .any(|(path, _)| pathutils::get_name(&Path::new(path)) == name)
        {
            return;
        }
        if let Some(obj) = parse(interp) {
            scope.push((interp.to_string(), obj));
        }
    }
}

// The loader version check of the objects of SCOPE (mimicking
// _dl_check_all_versions): for each required version, check whether the
// object providing it (matched by file name) actually defines it.  The
// loader reports a missing weak version, and an object without any version
// definition, as warnings (it always checks the versions in verbose mode,
// even for a plain trace).
#[cfg(target_os = "linux")]
fn check_version_needs(scope: &[(String, symbols::ObjectSymbols)]) -> Vec<VersionError> {
    let mut r = Vec::new();
    for (opath, obj) in scope {
        for need in &obj.verneeded {
            let Some((dpath, dobj)) = scope
                .iter()
                .find(|(path, _)| pathutils::get_name(&Path::new(path)) == need.file)
            else {
                continue;
            };
            let kind = if !dobj.has_verdef {
                VersionErrorKind::NoVersionInformation
            } else if dobj.verdef_names.contains(&need.version) {
                continue;
            } else if need.weak {
                VersionErrorKind::WeakNotFound
            } else {
                VersionErrorKind::NotFound
            };
            r.push(VersionError {
                object: dpath.clone(),
                version: need.version.clone(),
                required_by: opath.clone(),
                kind,
            });
        }
    }
    r
}

// The loader version check alone, which the glibc loader makes whenever it
// loads a program, before the relocations (dl_main), so ldd reports the
// failures before any listing.  The musl loader has none.
#[cfg(target_os = "linux")]
pub fn check_versions(deptree: &DepTree) -> Vec<VersionError> {
    let Some(root_elc) = open_root_elf(deptree) else {
        return Vec::new();
    };
    if root_elc.is_musl {
        return Vec::new();
    }
    let mut scope = build_symbol_scope(deptree, symbols::parse_versions);
    append_interp_to_scope(&mut scope, &root_elc, symbols::parse_versions);
    check_version_needs(&scope)
}

// Mimic the musl loader relocation processing, which the musl ldd always
// performs: musl has no lazy binding, so all the relocations (data and
// DT_JMPREL) are processed eagerly, and the symbol versioning is ignored on
// the load time resolution, besides the hidden versions which never bind
// (find_sym2).  The unresolved references are reported as
// 'Error relocating OBJECT: SYMBOL: symbol not found' and the loader exits
// with status 127.  Returns None when the object is not a musl one.
#[cfg(target_os = "linux")]
pub fn check_musl_relocations(deptree: &DepTree) -> Option<Vec<UndefinedSymbol>> {
    let root_elc = open_root_elf(deptree)?;
    if !root_elc.is_musl {
        return None;
    }

    let mut scope = build_symbol_scope(deptree, symbols::parse);

    let libc_linked = deptree.arena.iter().any(|n| n.val.alias.is_some());
    if libc_linked {
        append_interp_to_scope(&mut scope, &root_elc, symbols::parse);
    } else if let Some(loader) = musl_loader_path(&root_elc) {
        scope.retain(|(path, _)| *path != loader);
    }

    let mut undefined = Vec::new();
    for (idx, (path, obj)) in scope.iter().enumerate().rev() {
        for sref in &obj.references {
            if sref.weak {
                continue;
            }
            let defines = |o: &symbols::ObjectSymbols| {
                o.defined
                    .get(&sref.name)
                    .is_some_and(|defs| defs.iter().any(|def| !def.hidden))
            };
            if !scope
                .iter()
                .enumerate()
                .any(|(i, (_, o))| (!sref.copy || i != idx) && defines(o))
            {
                undefined.push(UndefinedSymbol {
                    name: sref.name.clone(),
                    object: path.clone(),
                    version: None,
                    from: None,
                });
            }
        }
    }
    Some(undefined)
}

#[cfg(target_os = "linux")]
fn musl_loader_path(elc: &ElfInfo) -> Option<String> {
    match &elc.interp {
        Some(interp) => Some(interp.clone()),
        None => find_musl_loader(),
    }
}

// Whether the OBJ object provides a definition satisfying the SREF reference,
// following the glibc lookup rules (check_match and do_lookup_x): any
// definition of an object without symbol versions does.  Otherwise a
// versioned reference is satisfied by a definition of the same version, or
// by an unversioned one when neither of them is hidden, while an unversioned
// reference is satisfied by an unversioned definition or one of the first
// version the object defines (index 2), or else by the single non hidden
// definition of a later version.
#[cfg(target_os = "linux")]
fn satisfies(obj: &symbols::ObjectSymbols, sref: &symbols::SymbolRef) -> bool {
    let Some(defs) = obj.defined.get(&sref.name) else {
        return false;
    };
    if !obj.has_versym {
        return true;
    }
    match &sref.version {
        Some(version) => defs.iter().any(|def| {
            def.version.as_ref() == Some(version)
                || (def.version.is_none() && !def.hidden && !sref.hidden)
        }),
        None => {
            defs.iter().any(|def| def.index < 3)
                || defs
                    .iter()
                    .filter(|def| def.index >= 3 && !def.hidden)
                    .count()
                    == 1
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

    let mut scope = build_symbol_scope(deptree, symbols::parse);
    if let Some(root_elc) = &root_elc {
        append_interp_to_scope(&mut scope, root_elc, symbols::parse);
    }

    // The musl loader has no version check.
    if !root_elc.as_ref().is_some_and(|elc| elc.is_musl) {
        r.version_errors = check_version_needs(&scope);
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
                    object: path.clone(),
                    version: sref.version.clone(),
                    from: None,
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

    // The preloaded objects are inserted right after the main map on the
    // loader search list, so an unused one is reported as a direct
    // dependency (and before the DT_NEEDED entries).
    if let Some(root) = deptree.arena.first() {
        for c in &root.children {
            let node = &deptree.arena[*c].val;
            if node.mode != DepMode::Preload {
                continue;
            }
            let Some(path) = deptree_node_path(node) else {
                continue;
            };
            if let Some(&i) = scope_index.get(path.as_str()) {
                if !used[i] && reported.insert(path.clone()) {
                    r.unused.push(path);
                }
            }
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    // A dynamic section of TAGS, whose string values index STRINGS.
    fn dynamic_tags(tags: &[(DynamicTag, u64)], strings: &[u8]) -> DynamicTags {
        let endian = Endianness::Little;
        let dynamic: Vec<Dyn64<Endianness>> = tags
            .iter()
            .map(|&(tag, val)| Dyn64 {
                d_tag: object::I64::new(endian, tag),
                d_val: object::U64::new(endian, val),
            })
            .collect();
        let dynstr = StringTable::new(strings, 0, strings.len() as u64);
        DynamicTags::parse::<FileHeader64<Endianness>>(endian, &dynamic, dynstr)
    }

    // The glibc symbol lookup version rules.
    #[cfg(target_os = "linux")]
    #[test]
    fn symbol_version_match() {
        use symbols::{ObjectSymbols, SymbolDef, SymbolRef};

        let def = |index, hidden, version: Option<&str>| SymbolDef {
            index,
            hidden,
            version: version.map(str::to_string),
        };
        let object = |defs: Vec<SymbolDef>, has_versym| ObjectSymbols {
            defined: [("foo".to_string(), defs)].into(),
            has_versym,
            ..Default::default()
        };
        let reference = |version: Option<&str>, hidden| SymbolRef {
            name: "foo".to_string(),
            version: version.map(str::to_string),
            hidden,
            weak: false,
            plt: false,
            copy: false,
        };
        let unversioned = reference(None, false);
        let v2 = reference(Some("V2"), false);

        // Without symbol versions any definition matches.
        assert!(satisfies(&object(vec![def(0, false, None)], false), &v2));
        // A versioned reference: the same version, or an unversioned
        // definition, unless one of them is hidden.
        assert!(satisfies(
            &object(vec![def(3, true, Some("V2"))], true),
            &v2
        ));
        assert!(!satisfies(
            &object(vec![def(2, false, Some("V1"))], true),
            &v2
        ));
        assert!(satisfies(&object(vec![def(1, false, None)], true), &v2));
        assert!(!satisfies(&object(vec![def(1, true, None)], true), &v2));
        assert!(!satisfies(
            &object(vec![def(1, false, None)], true),
            &reference(Some("V2"), true)
        ));
        // An unversioned reference: an unversioned definition or one of the
        // first version, even hidden, or else the single non hidden one.
        assert!(satisfies(
            &object(vec![def(1, false, None)], true),
            &unversioned
        ));
        assert!(satisfies(
            &object(vec![def(2, true, Some("V1"))], true),
            &unversioned
        ));
        assert!(!satisfies(
            &object(vec![def(3, true, Some("V2"))], true),
            &unversioned
        ));
        assert!(satisfies(
            &object(vec![def(3, false, Some("V2"))], true),
            &unversioned
        ));
        assert!(!satisfies(
            &object(
                vec![def(3, false, Some("V2")), def(4, false, Some("V3"))],
                true
            ),
            &unversioned
        ));
        assert!(satisfies(
            &object(
                vec![def(3, true, Some("V2")), def(4, false, Some("V3"))],
                true
            ),
            &unversioned
        ));
        assert!(!satisfies(&ObjectSymbols::default(), &unversioned));
    }

    #[test]
    fn search_subdirectory() {
        assert_eq!(
            subdir_path("/usr/lib", "glibc-hwcaps/x86-64-v3"),
            "/usr/lib/glibc-hwcaps/x86-64-v3"
        );
        assert_eq!(subdir_path("/", "tls"), "/tls");
        assert_eq!(subdir_path(".", "tls"), "./tls");
    }

    #[test]
    fn nodeflib_system_dirs_prefix() {
        let dirs = vec![
            search_path::SearchPath::fixed("/lib/x86_64-linux-gnu"),
            search_path::SearchPath::fixed("/usr/lib"),
        ];
        assert!(in_system_dirs(&dirs, "/lib/x86_64-linux-gnu", "libz.so.1"));
        // A subdirectory is below the prefix too.
        assert!(in_system_dirs(
            &dirs,
            "/usr/lib/x86_64-linux-gnu",
            "libz.so.1"
        ));
        assert!(!in_system_dirs(&dirs, "/usr/local/lib", "libz.so.1"));
        assert!(!in_system_dirs(&dirs, "/usr/lib64", "libz.so.1"));
        assert!(in_system_dirs(
            &vec![search_path::SearchPath::fixed("/")],
            "/opt",
            "libz.so.1"
        ));
    }

    #[test]
    fn dynamic_tags_last_entry_wins() {
        let strings = b"\0/a\0/b\0liba.so\0libb.so\0";
        let tags = dynamic_tags(
            &[
                (DT_SONAME, 7),
                (DT_RPATH, 1),
                (DT_RUNPATH, 1),
                (DT_FLAGS_1, DF_1_NODEFLIB.0),
                (DT_RPATH, 4),
                (DT_SONAME, 15),
                (DT_FLAGS_1, 0),
                (DT_NULL, 0),
                (DT_SONAME, 7),
            ],
            strings,
        );
        assert_eq!(tags.soname.as_deref(), Some("libb.so"));
        assert_eq!(tags.rpath.as_deref(), Some("/b"));
        assert_eq!(tags.runpath.as_deref(), Some("/a"));
        assert!(tags.has_runpath);
        assert!(!tags.runpath_last);
        assert_eq!(tags.flags_1, 0);

        let tags = dynamic_tags(&[(DT_RPATH, 1), (DT_RUNPATH, 4)], strings);
        assert!(tags.runpath_last);
        // The tag presence does not depend on its string.
        let tags = dynamic_tags(&[(DT_RUNPATH, 100)], strings);
        assert!(tags.has_runpath);
        assert_eq!(tags.runpath, None);
    }
}
