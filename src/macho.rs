use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::{fmt, fs, str};

use object::macho::*;
use object::read::macho::*;
use object::Endianness;

use crate::deptree::*;
use crate::pathutils;
use crate::search_path;
use crate::search_path::SearchPathVecExt;

static MACOS_BIG_SUR_CACHE_PATH_ARM64: &str =
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e";
static MACOS_BIG_SUR_CACHE_PATH_X86_64: &str =
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64";

pub type DyldCache = HashSet<String>;

// macOS starting with BigSur only provides a generated cache of all built in dynamic
// libraries, so file does not exist in the file system it is then checked against the
// cache.
pub fn create_context() -> DyldCache {
    let path = match std::env::consts::ARCH {
        "aarch64" => MACOS_BIG_SUR_CACHE_PATH_ARM64,
        "x86_64" => MACOS_BIG_SUR_CACHE_PATH_X86_64,
        _ => return DyldCache::new(),
    };

    if let Ok(elc) = open_macho_file(&Path::new(path), &String::new()) {
        if let Some(cache) = elc.cache {
            return cache;
        }
    }

    DyldCache::new()
}

pub fn resolve_binary(
    cache: &HashSet<String>,
    _ld_preload: &search_path::SearchPathVec,
    _ld_library_path: &search_path::SearchPathVec,
    _platform: Option<&String>,
    all: bool,
    arg: &str,
) -> Result<DepTree, std::io::Error> {
    let filename = Path::new(arg).canonicalize()?;

    let executable_path = pathutils::get_path(&filename).unwrap();

    let elc = open_macho_file(&filename, &executable_path)?;

    let mut deptree = DepTree::new();
    let depp = deptree.addroot(DepNode {
        path: Some(executable_path.clone()),
        name: pathutils::get_name(&filename),
        mode: DepMode::Executable,
        found: false,
    });

    for dep in &elc.deps {
        resolve_dependency(
            cache,
            &executable_path,
            &executable_path,
            &elc.rpath,
            &dep,
            &mut deptree,
            depp,
            all,
        );
    }

    Ok(deptree)
}

#[derive(Debug)]
struct MachOInfo {
    rpath: search_path::SearchPathVec,
    deps: DepsVec,
    cache: Option<DyldCache>,
}
type DepsVec = Vec<String>;

fn resolve_dependency(
    cache: &HashSet<String>,
    executable_path: &String,
    loader_path: &String,
    rpaths: &search_path::SearchPathVec,
    dependency: &String,
    deptree: &mut DepTree,
    depp: usize,
    all: bool,
) {
    let mut dependency = dependency.replace("@executable_path", executable_path);
    dependency = dependency.replace("@loader_path", loader_path);

    if dependency.contains("@rpath") {
        for rpath in rpaths {
            let mut newdependency = dependency.replace("@rpath", rpath.path.as_str());
            if resolve_dependency_1(
                cache,
                executable_path,
                &mut newdependency,
                true,
                deptree,
                depp,
                all,
            ) {
                return;
            }
        }
        return;
    }

    resolve_dependency_1(
        cache,
        executable_path,
        &mut dependency,
        false,
        deptree,
        depp,
        all,
    );
}

fn resolve_dependency_1(
    cache: &HashSet<String>,
    executable_path: &String,
    dependency: &mut String,
    rpath: bool,
    deptree: &mut DepTree,
    depp: usize,
    all: bool,
) -> bool {
    let elc = resolve_dependency_2(
        cache,
        executable_path,
        dependency,
        rpath,
        deptree,
        depp,
        all,
    );
    if let Some((elc, name)) = elc {
        let path = pathutils::get_path(&dependency).unwrap_or(String::new());

        let c = deptree.addnode(
            DepNode {
                path: Some(path.clone()),
                name: name,
                mode: DepMode::Direct,
                found: false,
            },
            depp,
        );

        for dep in &elc.deps {
            resolve_dependency(
                cache,
                executable_path,
                &path,
                &elc.rpath,
                &dep,
                deptree,
                c,
                all,
            );
        }
        true
    } else {
        false
    }
}

fn resolve_dependency_2(
    cache: &HashSet<String>,
    executable_path: &String,
    dependency: &mut String,
    rpath: bool,
    deptree: &mut DepTree,
    depp: usize,
    all: bool,
) -> Option<(MachOInfo, String)> {
    // Try to read the library file contents.
    let path = Path::new(&dependency);
    let elc = if path.is_absolute() {
        open_macho_file(&path, executable_path).handle_err()
    } else {
        None
    };

    // The dependency library does not exist on filesystem, check the dydl cache.
    let path = if elc.is_none() {
        if !rpath {
            let mode = if !cache.contains(dependency) {
                DepMode::NotFound
            } else {
                // Check if dependency is already found.
                if resolve_dependency_check_found(dependency, deptree, depp, all) {
                    return None;
                }
                DepMode::LdSoConf
            };
            deptree.addnode(
                DepNode {
                    path: pathutils::get_path(&path),
                    name: pathutils::get_name(&path),
                    mode: mode,
                    found: false,
                },
                depp,
            );
        }
        return None;
    } else {
        path.canonicalize().unwrap()
    };

    let name = pathutils::get_name(&path);
    *dependency = path.to_string_lossy().to_string();

    // Check if dependency is already found.
    if resolve_dependency_check_found(dependency, deptree, depp, all) {
        return None;
    }

    Some((elc.unwrap(), name))
}

fn resolve_dependency_check_found(
    dependency: &String,
    deptree: &mut DepTree,
    depp: usize,
    all: bool,
) -> bool {
    if let Some(entry) = deptree.get(&dependency) {
        if all {
            deptree.addnode(
                DepNode {
                    path: entry.path,
                    name: entry.name,
                    mode: entry.mode.clone(),
                    found: true,
                },
                depp,
            );
        }
        true
    } else {
        false
    }
}

fn open_macho_file<'a, P: AsRef<Path>>(
    filename: &P,
    executable_path: &String,
) -> Result<MachOInfo, std::io::Error> {
    let file = match fs::File::open(&filename) {
        Ok(file) => file,
        Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to open file")),
    };

    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to map file")),
    };

    match parse_object(&*mmap, executable_path) {
        Ok(elc) => Ok(elc),
        Err(e) => return Err(Error::new(ErrorKind::Other, e)),
    }
}

fn parse_object(data: &[u8], executable_path: &String) -> Result<MachOInfo, &'static str> {
    let kind = match object::FileKind::parse(data) {
        Ok(file) => file,
        Err(_err) => return Err("Failed to parse file"),
    };

    match kind {
        object::FileKind::MachO32 => parse_macho32(data, executable_path),
        object::FileKind::MachO64 => parse_macho64(data, executable_path),
        object::FileKind::MachOFat32 => parse_macho_fat32(data, executable_path),
        object::FileKind::MachOFat64 => parse_macho_fat64(data, executable_path),
        object::FileKind::DyldCache => parse_dyld_cache(data),
        _ => Err("Invalid object"),
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

fn parse_macho32(data: &[u8], executable_path: &String) -> Result<MachOInfo, &'static str> {
    if let Some(macho) = MachHeader32::parse(data, 0).handle_err() {
        return parse_macho(macho, data, executable_path);
    }
    Err("Invalid Mach-O 32 object")
}

fn parse_macho64(data: &[u8], executable_path: &String) -> Result<MachOInfo, &'static str> {
    if let Some(macho) = MachHeader64::parse(data, 0).handle_err() {
        return parse_macho(macho, data, executable_path);
    }
    Err("Invalid Mach-O 64 object")
}

fn parse_macho_fat32(data: &[u8], executable_path: &String) -> Result<MachOInfo, &'static str> {
    if let Some(arches) = FatHeader::parse_arch32(data).handle_err() {
        return parse_macho_fat(data, arches, executable_path);
    }
    Err("Invalid FAT Mach-O 32 object")
}

fn parse_macho_fat64(data: &[u8], executable_path: &String) -> Result<MachOInfo, &'static str> {
    if let Some(arches) = FatHeader::parse_arch64(data).handle_err() {
        return parse_macho_fat(data, arches, executable_path);
    }
    Err("Invalid FAT Mach-O 64 object")
}

fn check_current_arch(arch: object::Architecture) -> bool {
    std::env::consts::ARCH
        == match arch {
            object::Architecture::Aarch64 => "aarch64",
            object::Architecture::Arm => "arm",
            object::Architecture::X86_64 => "x86_64",
            object::Architecture::I386 => "x86",
            object::Architecture::PowerPc64 => "powerpc64",
            object::Architecture::PowerPc => "powerpc",
            _ => "",
        }
}

fn parse_macho_fat<FatArch: object::read::macho::FatArch>(
    data: &[u8],
    arches: &[FatArch],
    executable_path: &String,
) -> Result<MachOInfo, &'static str> {
    for arch in arches {
        if check_current_arch(arch.architecture()) {
            if let Some(fatdata) = arch.data(data).handle_err() {
                return parse_object(fatdata, executable_path);
            }
        }
    }
    Err("Invalid FAT Mach-O architecture")
}

fn parse_macho<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    data: &[u8],
    executable_path: &String,
) -> Result<MachOInfo, &'static str> {
    let mut deps = DepsVec::new();
    let mut rpaths = search_path::SearchPathVec::new();

    if let Ok(endian) = header.endian() {
        if let Ok(mut commands) = header.load_commands(endian, data, 0) {
            while let Ok(Some(command)) = commands.next() {
                match parse_load_command::<Mach>(endian, command) {
                    Some((LoadCommand::DYLIB, dylib)) => deps.push(dylib),
                    Some((LoadCommand::RPATH, rpath)) => {
                        let rpath = rpath.replace("@executable_path", executable_path);
                        rpaths.add_path(rpath.as_str());
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(MachOInfo {
        rpath: rpaths,
        deps: deps,
        cache: None,
    })
}

fn parse_dyld_cache(data: &[u8]) -> Result<MachOInfo, &'static str> {
    let mut cache = DyldCache::new();

    if let Some(header) = DyldCacheHeader::<Endianness>::parse(data).handle_err() {
        if let Some((_, endian)) = header.parse_magic().handle_err() {
            if let Some(images) = header.images(endian, data).handle_err() {
                for image in images {
                    let path = image
                        .path(endian, data)
                        .ok()
                        .and_then(|s| str::from_utf8(s).ok().and_then(|s| Some(s.to_string())));
                    if let Some(path) = path {
                        cache.insert(path);
                    }
                }
            }
        }
    }

    Ok(MachOInfo {
        rpath: search_path::SearchPathVec::new(),
        deps: DepsVec::new(),
        cache: Some(cache),
    })
}

enum LoadCommand {
    DYLIB,
    RPATH,
}

fn parse_string<'data>(data: Option<&'data [u8]>) -> Option<String> {
    data.and_then(|s| str::from_utf8(s).ok().and_then(|s| Some(s.to_string())))
}

fn parse_load_command<Mach: MachHeader>(
    endian: Mach::Endian,
    command: LoadCommandData<Mach::Endian>,
    //) -> Option<String> {
) -> Option<(LoadCommand, String)> {
    if let Ok(variant) = command.variant() {
        match variant {
            LoadCommandVariant::Dylib(x) | LoadCommandVariant::IdDylib(x) => {
                if let Some(dylib) = parse_string(command.string(endian, x.dylib.name).ok()) {
                    return Some((LoadCommand::DYLIB, dylib));
                };
                None
            }
            LoadCommandVariant::Rpath(x) => {
                if let Some(rpath) = parse_string(command.string(endian, x.path).ok()) {
                    return Some((LoadCommand::RPATH, rpath));
                };
                None
            }
            _ => None,
        }
    } else {
        None
    }
}
