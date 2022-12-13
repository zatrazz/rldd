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

    if let Ok(elc) = open_macho_file(&Path::new(path)) {
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
    let executable_path: String = filename
        .parent()
        .and_then(|s| s.to_str())
        .and_then(|s| Some(s.to_string()))
        .unwrap_or(String::new());

    let elc = open_macho_file(&filename)?;

    let mut deptree = DepTree::new();

    let depp = deptree.addroot(DepNode {
        path: Some(executable_path.clone()),
        name: filename
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string(),
        mode: DepMode::Executable,
        found: false,
    });

    for dep in &elc.deps {
        resolve_dependency(cache, &executable_path, &dep, &mut deptree, depp, all);
    }

    Ok(deptree)
}

#[derive(Debug)]
struct MachOInfo {
    deps: DepsVec,
    cache: Option<DyldCache>,
}
type DepsVec = Vec<String>;

fn resolve_dependency(
    cache: &HashSet<String>,
    executable_path: &String,
    dependency: &String,
    deptree: &mut DepTree,
    depp: usize,
    all: bool,
) {
    let dependency = dependency.replace("@executable_path", executable_path);
    // TODO: @loader_path/
    // TODO: @rpath/

    // Try to read the library file contents.
    let path = Path::new(&dependency);
    let elc = if path.is_absolute() {
        open_macho_file(&path).handle_err()
    } else {
        None
    };

    // The dependency library does not exist on filesystem, check the dydl cache.
    let dependency = if elc.is_none() {
        let mode = if !cache.contains(&dependency) {
            DepMode::NotFound
        } else {
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
        return;
    } else {
        path.canonicalize().unwrap()
    };

    let name = pathutils::get_name(&dependency);

    // Check if dependency is already found.
    if let Some(entry) = deptree.get(&dependency.to_string_lossy().to_string()) {
        if all {
            deptree.addnode(
                DepNode {
                    path: entry.path,
                    name: name,
                    mode: entry.mode.clone(),
                    found: true,
                },
                depp,
            );
        }
        return;
    }

    let c = deptree.addnode(
        DepNode {
            path: pathutils::get_path(&dependency),
            name: name,
            mode: DepMode::Direct,
            found: false,
        },
        depp,
    );

    for dep in &elc.unwrap().deps {
        resolve_dependency(cache, executable_path, &dep, deptree, c, all);
    }
}

fn open_macho_file<'a, P: AsRef<Path>>(filename: &P) -> Result<MachOInfo, std::io::Error> {
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

    match parse_object(&*mmap, parent) {
        Ok(elc) => Ok(elc),
        Err(e) => return Err(Error::new(ErrorKind::Other, e)),
    }
}

fn parse_object(data: &[u8], _origin: &str) -> Result<MachOInfo, &'static str> {
    let kind = match object::FileKind::parse(data) {
        Ok(file) => file,
        Err(_err) => return Err("Failed to parse file"),
    };

    match kind {
        object::FileKind::MachO32 => parse_macho32(data),
        object::FileKind::MachO64 => parse_macho64(data),
        object::FileKind::MachOFat32 => parse_macho_fat32(data),
        object::FileKind::MachOFat64 => parse_macho_fat64(data),
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

fn parse_macho32(data: &[u8]) -> Result<MachOInfo, &'static str> {
    if let Some(macho) = MachHeader32::parse(data, 0).handle_err() {
        return parse_macho(macho, data);
    }
    Err("Invalid Mach-O 32 object")
}

fn parse_macho64(data: &[u8]) -> Result<MachOInfo, &'static str> {
    if let Some(macho) = MachHeader64::parse(data, 0).handle_err() {
        return parse_macho(macho, data);
    }
    Err("Invalid Mach-O 64 object")
}

fn parse_macho_fat32(data: &[u8]) -> Result<MachOInfo, &'static str> {
    if let Some(arches) = FatHeader::parse_arch32(data).handle_err() {
        return parse_macho_fat(data, arches);
    }
    Err("Invalid FAT Mach-O 32 object")
}

fn parse_macho_fat64(data: &[u8]) -> Result<MachOInfo, &'static str> {
    if let Some(arches) = FatHeader::parse_arch64(data).handle_err() {
        return parse_macho_fat(data, arches);
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
) -> Result<MachOInfo, &'static str> {
    for arch in arches {
        if check_current_arch(arch.architecture()) {
            if let Some(fatdata) = arch.data(data).handle_err() {
                return parse_object(fatdata, "");
            }
        }
    }
    Err("Invalid FAT Mach-O architecture")
}

fn parse_macho<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    data: &[u8],
) -> Result<MachOInfo, &'static str> {
    let mut deps = DepsVec::new();

    if let Ok(endian) = header.endian() {
        if let Ok(mut commands) = header.load_commands(endian, data, 0) {
            while let Ok(Some(command)) = commands.next() {
                if let Some(dep) = parse_load_command::<Mach>(endian, command) {
                    deps.push(dep);
                }
            }
        }
    }

    Ok(MachOInfo {
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
        deps: DepsVec::new(),
        cache: Some(cache),
    })
}

fn parse_load_command<Mach: MachHeader>(
    endian: Mach::Endian,
    command: LoadCommandData<Mach::Endian>,
) -> Option<String> {
    if let Ok(variant) = command.variant() {
        match variant {
            LoadCommandVariant::Dylib(x) | LoadCommandVariant::IdDylib(x) => {
                return command
                    .string(endian, x.dylib.name)
                    .ok()
                    .and_then(|s| str::from_utf8(s).ok().and_then(|s| Some(s.to_string())))
            }
            _ => {}
        }
    }
    None
}