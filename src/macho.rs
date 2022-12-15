use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::{fmt, fs, str};

use memmap2::Mmap;

use object::macho::*;
use object::read::macho::*;
use object::Endianness;

use crate::deptree::*;
use crate::pathutils;
use crate::search_path;
use crate::search_path::*;

mod dydlcache;

type ImagesMap = HashMap<String, Option<u64>>;

#[derive(Default)]
pub struct DyldCache {
    images: ImagesMap,
    mmap: Option<Mmap>,
}

type MachObj = MachOInfo;
type DepsVec = Vec<String>;

#[derive(Default)]
struct MachOInfo {
    rpath: search_path::SearchPathVec,
    deps: DepsVec,
}

// Return type for the parse_* functions.
enum ParseObjectResult {
    Object(MachObj),
    Cache(ImagesMap),
}

// Return type for the open_macho_file.
enum OpenMachOFileResult {
    Object(MachObj),
    Cache(DyldCache),
}

impl DyldCache {
    // Retrieve a dynamic object information from the dyld system cache.
    fn get(&self, name: &String, executable_path: &String) -> Option<MachOInfo> {
        if let (Some(mmap), Some(offset)) = (self.mmap.as_ref(), self.images.get(name)) {
            if let Some(offset) = offset {
                return match parse_object(&*mmap, *offset, executable_path) {
                    Ok(ParseObjectResult::Object(obj)) => Some(obj),
                    _ => None,
                };
            } else {
                // For object with invalid offset, return an default object without any
                // dependencies.
                return Some(MachOInfo::default());
            }
        };
        None
    }
}

// macOS starting with BigSur only provides a generated cache of all built in dynamic
// libraries, so file does not exist in the file system it is then checked against the
// cache.
pub fn create_context() -> DyldCache {
    if let Some(path) = dydlcache::path() {
        if let Ok(cache) = open_macho_file(&Path::new(path), &String::new()) {
            if let OpenMachOFileResult::Cache(cache) = cache {
                return cache;
            }
        }
    }

    DyldCache::default()
}

pub fn resolve_binary(
    cache: &DyldCache,
    _ld_preload: &search_path::SearchPathVec,
    _ld_library_path: &search_path::SearchPathVec,
    _platform: Option<&String>,
    all: bool,
    arg: &str,
) -> Result<DepTree, std::io::Error> {
    let filename = Path::new(arg).canonicalize()?;

    let executable_path = pathutils::get_path(&filename).unwrap();

    let omf = match open_macho_file(&filename, &executable_path)? {
        OpenMachOFileResult::Object(obj) => obj,
        _ => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Invalid MachO file: {}", arg),
            ))
        }
    };

    let mut deptree = DepTree::new();
    let depp = deptree.addroot(DepNode {
        path: Some(executable_path.clone()),
        name: pathutils::get_name(&filename),
        mode: DepMode::Executable,
        found: false,
    });

    for dep in &omf.deps {
        resolve_dependency(
            cache,
            &executable_path,
            &executable_path,
            &omf.rpath,
            &dep,
            &mut deptree,
            depp,
            all,
        );
    }

    Ok(deptree)
}

fn resolve_dependency(
    cache: &DyldCache,
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
    cache: &DyldCache,
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
    if let Some((elc, depd)) = elc {
        let path = pathutils::get_path(&dependency).unwrap_or(String::new());
        for dep in &elc.deps {
            resolve_dependency(
                cache,
                executable_path,
                &path,
                &elc.rpath,
                &dep,
                deptree,
                depd,
                all,
            );
        }
        true
    } else {
        false
    }
}

fn resolve_dependency_2(
    cache: &DyldCache,
    executable_path: &String,
    dependency: &mut String,
    rpath: bool,
    deptree: &mut DepTree,
    depp: usize,
    all: bool,
) -> Option<(MachOInfo, usize)> {
    // To avoid circular dependencies, check if deptree already containts the dependency.
    if deptree.contains(dependency) {
        return None;
    }

    let path = Path::new(&dependency);

    // First try the dyld system cache, if existente.
    if let Some(elc) = cache.get(dependency, executable_path) {
        if resolve_dependency_check_found(dependency, deptree, depp, all) {
            return None;
        }
        let name = pathutils::get_name(&path);
        let depd = deptree.addnode(
            DepNode {
                path: pathutils::get_path(&path),
                name: name.to_string(),
                mode: DepMode::LdSoConf,
                found: false,
            },
            depp,
        );
        return Some((elc, depd));
    }

    // The try filesystem.
    let elc = if path.is_absolute() {
        match open_macho_file(&path, executable_path).ok() {
            Some(OpenMachOFileResult::Object(obj)) => Some(obj),
            _ => None,
        }
    } else {
        None
    };

    let path = if elc.is_none() {
        // The dependency library does not exist.
        if !rpath {
            deptree.addnode(
                DepNode {
                    path: pathutils::get_path(&path),
                    name: pathutils::get_name(&path),
                    mode: DepMode::NotFound,
                    found: false,
                },
                depp,
            );
        }
        return None;
    } else {
        path.canonicalize().unwrap()
    };

    // Update the dependency path for the case of rpath substitution.
    *dependency = path.to_string_lossy().to_string();

    let depd = deptree.addnode(
        DepNode {
            path: pathutils::get_path(&path),
            name: pathutils::get_name(&path),
            mode: DepMode::Direct,
            found: false,
        },
        depp,
    );

    Some((elc.unwrap(), depd))
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
) -> Result<OpenMachOFileResult, std::io::Error> {
    let file = match fs::File::open(&filename) {
        Ok(file) => file,
        Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to open file")),
    };

    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to map file")),
    };

    match parse_object(&*mmap, 0, executable_path) {
        Ok(ParseObjectResult::Object(omf)) => Ok(OpenMachOFileResult::Object(omf)),
        Ok(ParseObjectResult::Cache(images)) => Ok(OpenMachOFileResult::Cache(DyldCache {
            images: images,
            mmap: Some(mmap),
        })),
        Err(e) => return Err(Error::new(ErrorKind::Other, e)),
    }
}

fn parse_object(
    data: &[u8],
    offset: u64,
    executable_path: &String,
) -> Result<ParseObjectResult, &'static str> {
    let kind = match object::FileKind::parse_at(&*data, offset) {
        Ok(file) => file,
        Err(_err) => return Err("Failed to parse file"),
    };

    match kind {
        object::FileKind::MachO32 => parse_macho32(data, offset, executable_path),
        object::FileKind::MachO64 => parse_macho64(data, offset, executable_path),
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

fn parse_macho32(
    data: &[u8],
    offset: u64,
    executable_path: &String,
) -> Result<ParseObjectResult, &'static str> {
    if let Some(macho) = MachHeader32::parse(data, offset).handle_err() {
        return parse_macho(macho, data, offset, executable_path);
    }
    Err("Invalid Mach-O 32 object")
}

fn parse_macho64(
    data: &[u8],
    offset: u64,
    executable_path: &String,
) -> Result<ParseObjectResult, &'static str> {
    if let Some(macho) = MachHeader64::parse(data, offset).handle_err() {
        return parse_macho(macho, data, offset, executable_path);
    }
    Err("Invalid Mach-O 64 object")
}

fn parse_macho_fat32(
    data: &[u8],
    executable_path: &String,
) -> Result<ParseObjectResult, &'static str> {
    if let Some(arches) = FatHeader::parse_arch32(data).handle_err() {
        return parse_macho_fat(data, arches, executable_path);
    }
    Err("Invalid FAT Mach-O 32 object")
}

fn parse_macho_fat64(
    data: &[u8],
    executable_path: &String,
) -> Result<ParseObjectResult, &'static str> {
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
) -> Result<ParseObjectResult, &'static str> {
    for arch in arches {
        if check_current_arch(arch.architecture()) {
            if let Some(fatdata) = arch.data(data).handle_err() {
                return parse_object(fatdata, 0, executable_path);
            }
        }
    }
    Err("Invalid FAT Mach-O architecture")
}

fn parse_macho<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    data: &[u8],
    offset: u64,
    executable_path: &String,
) -> Result<ParseObjectResult, &'static str> {
    let mut deps = DepsVec::new();
    let mut rpaths = search_path::SearchPathVec::new();

    if let Ok(endian) = header.endian() {
        if let Ok(mut commands) = header.load_commands(endian, data, offset) {
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

    Ok(ParseObjectResult::Object(MachOInfo {
        rpath: rpaths,
        deps: deps,
    }))
}

fn parse_dyld_cache(data: &[u8]) -> Result<ParseObjectResult, &'static str> {
    if let Some(header) = DyldCacheHeader::<Endianness>::parse(data).handle_err() {
        if let Some((_, endian)) = header.parse_magic().handle_err() {
            if let Some(images) = header.images(endian, data).handle_err() {
                let mappings = header.mappings(endian, data).handle_err();
                return parse_dyld_cache_images(endian, data, mappings, images);
            }
        }
    }

    Err("Invalid dyld cache")
}

fn parse_dyld_cache_images(
    endian: Endianness,
    data: &[u8],
    mappings: Option<&[DyldCacheMappingInfo<Endianness>]>,
    images: &[DyldCacheImageInfo<Endianness>],
) -> Result<ParseObjectResult, &'static str> {
    let mut cache = ImagesMap::new();

    for image in images {
        let path = image
            .path(endian, data)
            .ok()
            .and_then(|s| str::from_utf8(s).ok().and_then(|s| Some(s.to_string())));
        let offset = mappings.and_then(|mappings| image.file_offset(endian, mappings).ok());
        if let Some(path) = path {
            cache.insert(path, offset);
        }
    }

    Ok(ParseObjectResult::Cache(cache))
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
