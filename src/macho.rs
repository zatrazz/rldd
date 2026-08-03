use std::io::Error;
use std::path::Path;
use std::{fs, str};

use object::macho::*;
use object::read::macho::*;
use object::Endianness;

use crate::deptree::*;
use crate::pathutils;
use crate::search_path;
use crate::search_path::*;

mod dyldcache;
pub use dyldcache::DyldCache;

type DepsVec = Vec<String>;

#[derive(Default, Debug)]
struct MachOInfo {
    rpath: search_path::SearchPathVec,
    deps: DepsVec,
}

impl DyldCache {
    // Retrieve a dynamic object information from the dyld system cache.
    fn get(&self, name: &str, executable_path: &str) -> Option<MachOInfo> {
        match self.image(name)? {
            Some((data, offset)) => {
                let loader_path = pathutils::get_path(&Path::new(name)).unwrap_or_default();
                parse_object(data, offset, executable_path, &loader_path).ok()
            }
            // For images not covered by any cache mapping, return a default
            // object without any dependencies.
            None => Some(MachOInfo::default()),
        }
    }
}

pub fn create_context() -> DyldCache {
    dyldcache::load()
}

// The dyld builtin fallback paths used when the environment variables are not
// set (the DYLD_FALLBACK_FRAMEWORK_PATH and DYLD_FALLBACK_LIBRARY_PATH
// defaults from dyld4).
const DEFAULT_FALLBACK_FRAMEWORK_PATH: &str = "/System/Library/Frameworks";
const DEFAULT_FALLBACK_LIBRARY_PATH: &str = "/usr/local/lib:/usr/lib";

#[allow(clippy::too_many_arguments)]
pub fn resolve_binary(
    cache: &mut DyldCache,
    preload: &search_path::SearchPathVec,
    library_path: &search_path::SearchPathVec,
    framework_path: &search_path::SearchPathVec,
    fallback_framework_path: &Option<String>,
    fallback_library_path: &Option<String>,
    all: bool,
    verbose: bool,
    arg: &str,
) -> Result<DepTree, std::io::Error> {
    let filename = Path::new(arg).canonicalize()?;

    let executable_path = pathutils::get_path(&filename).ok_or(std::io::Error::other(format!(
        "failed to get path of input file {arg}"
    )))?;

    let omf = open_macho_file(&filename, &executable_path)?;

    let fallback_framework_path = search_path::from_string(
        fallback_framework_path
            .as_deref()
            .unwrap_or(DEFAULT_FALLBACK_FRAMEWORK_PATH),
        &[':'],
    );
    let fallback_library_path = search_path::from_string(
        fallback_library_path
            .as_deref()
            .unwrap_or(DEFAULT_FALLBACK_LIBRARY_PATH),
        &[':'],
    );

    if verbose {
        println!(
            "{}: search path information\n\
            \x20 rpath: {}\n\
            \x20 library path: {}\n\
            \x20 framework path: {}\n\
            \x20 fallback framework path: {}\n\
            \x20 fallback library path: {}\n\
            \x20 dyld cache: {}",
            filename.display(),
            search_path::format_list(&omf.rpath),
            search_path::format_list(library_path),
            search_path::format_list(framework_path),
            search_path::format_list(&fallback_framework_path),
            search_path::format_list(&fallback_library_path),
            if cache.is_empty() {
                "not found".to_string()
            } else {
                format!("{} images", cache.len())
            },
        );
    }

    let mut deptree = DepTree::new();
    let depp = deptree.addroot(DepNode {
        path: Some(executable_path.clone()),
        name: pathutils::get_name(&filename),
        mode: DepMode::Executable,
        found: false,
        searched: Vec::new(),
    });

    let config = Config {
        cache,
        library_path,
        framework_path,
        fallback_framework_path,
        fallback_library_path,
        executable_path: &executable_path,
        all,
    };

    for pload in preload {
        resolve_dependency(
            &config,
            &executable_path,
            &omf.rpath,
            &pload.path,
            &mut deptree,
            depp,
            true,
        );
    }

    for dep in &omf.deps {
        resolve_dependency(
            &config,
            &executable_path,
            &omf.rpath,
            dep,
            &mut deptree,
            depp,
            false,
        );
    }

    Ok(deptree)
}

struct Config<'a> {
    cache: &'a DyldCache,
    library_path: &'a search_path::SearchPathVec,
    framework_path: &'a search_path::SearchPathVec,
    fallback_framework_path: search_path::SearchPathVec,
    fallback_library_path: search_path::SearchPathVec,
    executable_path: &'a str,
    all: bool,
}

// Return the framework partial path (Name.framework/Name or
// Name.framework/Versions/X/Name) if the install path looks like a framework,
// mimicking the dyld getFrameworkPartialPath check.
fn framework_partial_path(dependency: &str) -> Option<&str> {
    let leaf = dependency.rsplit('/').next()?;
    let marker = ".framework/";
    let idx = dependency.rfind(marker)?;
    let start = dependency[..idx].rfind('/').map(|i| i + 1).unwrap_or(0);
    let name = &dependency[start..idx];
    let rest = &dependency[idx + marker.len()..];
    let valid = rest == leaf
        || rest
            .strip_prefix("Versions/")
            .and_then(|version| version.split_once('/'))
            .is_some_and(|(_, l)| l == leaf);
    if valid && name == leaf {
        Some(&dependency[start..])
    } else {
        None
    }
}

fn resolve_dependency(
    config: &Config,
    loader_path: &str,
    rpaths: &search_path::SearchPathVec,
    dependency: &str,
    deptree: &mut DepTree,
    depp: usize,
    preload: bool,
) {
    let dependency = dependency
        .replace("@executable_path", config.executable_path)
        .replace("@loader_path", loader_path);

    // To avoid circular dependencies, check if deptree already contains the
    // dependency.
    if check_already_resolved(config, &dependency, deptree, depp) {
        return;
    }

    if let Some((elc, depd, path)) = find_dependency(config, rpaths, &dependency, deptree, depp, preload)
    {
        // The run-path list for the object own dependencies: the object
        // LC_RPATH entries followed by the ones inherited from the loading
        // chain, mimicking the dyld run-path stack.
        let mut newrpaths = elc.rpath.clone();
        for rpath in rpaths {
            if !newrpaths.contains(rpath) {
                newrpaths.push(rpath.clone());
            }
        }
        for dep in &elc.deps {
            resolve_dependency(config, &path, &newrpaths, dep, deptree, depd, preload);
        }
    }
}

// Check if the dependency was already resolved, adding an already found
// node when the -a option is used.
fn check_already_resolved(
    config: &Config,
    dependency: &str,
    deptree: &mut DepTree,
    depp: usize,
) -> bool {
    if let Some(entry) = deptree.get(dependency) {
        if config.all {
            deptree.addnode(
                DepNode {
                    path: entry.path,
                    name: entry.name,
                    mode: entry.mode,
                    found: true,
                    searched: Vec::new(),
                },
                depp,
            );
        }
        return true;
    }
    false
}

// Resolve DEPENDENCY following the dyld search order:
//
// 1. The environment path overrides;
// 2. The install name itself (with @rpath expanded against the run-path list
//    when present.
// 3. The fallback paths.
fn find_dependency(
    config: &Config,
    rpaths: &search_path::SearchPathVec,
    dependency: &str,
    deptree: &mut DepTree,
    depp: usize,
    preload: bool,
) -> Option<(MachOInfo, usize, String)> {
    // DYLD_FRAMEWORK_PATH with the framework partial path and then
    // DYLD_LIBRARY_PATH with the leaf name.
    let partial = framework_partial_path(dependency);
    if let Some(partial) = partial {
        if let Some(r) = resolve_search_paths(
            config,
            config.framework_path,
            partial,
            DepMode::DyldFrameworkPath,
            deptree,
            depp,
        ) {
            return Some(r);
        }
    }
    let leaf = pathutils::get_name(&Path::new(dependency));
    if let Some(r) = resolve_search_paths(
        config,
        config.library_path,
        &leaf,
        DepMode::LdLibraryPath,
        deptree,
        depp,
    ) {
        return Some(r);
    }

    // Then the install name, either literally or through the run-path list.
    if dependency.contains("@rpath") {
        for rpath in rpaths {
            let expanded = dependency.replace("@rpath", rpath.path.as_str());
            match resolve_path(config, &expanded, DepMode::DtRpath, deptree, depp) {
                ResolveResult::Found(r) => return Some(r),
                ResolveResult::Skip => return None,
                ResolveResult::Miss => {}
            }
        }
    } else {
        let mode = if preload {
            DepMode::Preload
        } else {
            DepMode::Direct
        };
        match resolve_path(config, dependency, mode, deptree, depp) {
            ResolveResult::Found(r) => return Some(r),
            ResolveResult::Skip => return None,
            ResolveResult::Miss => {}
        }
    }

    // Now the fallback paths.
    if let Some(partial) = partial {
        if let Some(r) = resolve_search_paths(
            config,
            &config.fallback_framework_path,
            partial,
            DepMode::DyldFallbackFrameworkPath,
            deptree,
            depp,
        ) {
            return Some(r);
        }
    }
    if let Some(r) = resolve_search_paths(
        config,
        &config.fallback_library_path,
        &leaf,
        DepMode::DyldFallbackLibraryPath,
        deptree,
        depp,
    ) {
        return Some(r);
    }

    let path = Path::new(dependency);
    deptree.addnode(
        DepNode {
            path: pathutils::get_path(&path),
            name: pathutils::get_name(&path),
            mode: DepMode::NotFound,
            found: false,
            searched: searched_locations(config, rpaths, dependency),
        },
        depp,
    );
    None
}

// The locations searched for a not found dependency, printed in verbose mode.
fn searched_locations(
    config: &Config,
    rpaths: &search_path::SearchPathVec,
    dependency: &str,
) -> Vec<String> {
    let framework = framework_partial_path(dependency).is_some();

    let mut searched = Vec::new();
    if framework && !config.framework_path.is_empty() {
        searched.push(format!(
            "framework path: {}",
            search_path::format_list(config.framework_path)
        ));
    }
    if !config.library_path.is_empty() {
        searched.push(format!(
            "library path: {}",
            search_path::format_list(config.library_path)
        ));
    }
    if dependency.contains("@rpath") && !rpaths.is_empty() {
        for rpath in rpaths {
            searched.push(dependency.replace("@rpath", rpath.path.as_str()));
        }
    } else {
        searched.push(dependency.to_string());
    }
    searched.push(
        if config.cache.is_empty() {
            "dyld cache (not loaded)"
        } else {
            "dyld cache"
        }
        .to_string(),
    );
    if framework && !config.fallback_framework_path.is_empty() {
        searched.push(format!(
            "fallback framework path: {}",
            search_path::format_list(&config.fallback_framework_path)
        ));
    }
    if !config.fallback_library_path.is_empty() {
        searched.push(format!(
            "fallback library path: {}",
            search_path::format_list(&config.fallback_library_path)
        ));
    }
    searched
}

enum ResolveResult {
    // Found and added to the dependency tree.
    Found((MachOInfo, usize, String)),
    // Already present in the dependency tree.
    Skip,
    // Not found through this candidate path.
    Miss,
}

// Try to resolve a candidate path against the dyld cache and then the filesystem,
// adding a node to the dependency tree when found.
fn resolve_path(
    config: &Config,
    dependency: &str,
    mode: DepMode,
    deptree: &mut DepTree,
    depp: usize,
) -> ResolveResult {
    // The expanded @rpath candidates require their own check against the
    // dependency tree, since the recorded nodes hold the resolved path.
    if check_already_resolved(config, dependency, deptree, depp) {
        return ResolveResult::Skip;
    }

    // Try the dyld system cache, if existent.
    if let Some(elc) = config.cache.get(dependency, config.executable_path) {
        let path = Path::new(dependency);
        let dir = pathutils::get_path(&path);
        let depd = deptree.addnode(
            DepNode {
                path: dir.clone(),
                name: pathutils::get_name(&path),
                mode: DepMode::LdCache,
                found: false,
                searched: Vec::new(),
            },
            depp,
        );
        return ResolveResult::Found((elc, depd, dir.unwrap_or_default()));
    }

    // Then the filesystem, only for absolute paths.
    let path = Path::new(dependency);
    if !path.is_absolute() {
        return ResolveResult::Miss;
    }
    // The canonicalization also checks the file existence.
    let Ok(path) = path.canonicalize() else {
        return ResolveResult::Miss;
    };
    if check_already_resolved(config, &path.to_string_lossy(), deptree, depp) {
        return ResolveResult::Skip;
    }
    let Ok(elc) = open_macho_file(&path, config.executable_path) else {
        return ResolveResult::Miss;
    };
    let dir = pathutils::get_path(&path);
    let depd = deptree.addnode(
        DepNode {
            path: dir.clone(),
            name: pathutils::get_name(&path),
            mode,
            found: false,
            searched: Vec::new(),
        },
        depp,
    );
    ResolveResult::Found((elc, depd, dir.unwrap_or_default()))
}

// Search NAME (either a leaf name or a framework partial path) on the
// SEARCHPATHS directories, checking both the dyld cache and the filesystem.
fn resolve_search_paths(
    config: &Config,
    searchpaths: &search_path::SearchPathVec,
    name: &str,
    mode: DepMode,
    deptree: &mut DepTree,
    depp: usize,
) -> Option<(MachOInfo, usize, String)> {
    for searchpath in searchpaths {
        let newpath = Path::new(&searchpath.path).join(name);
        let elc = match config
            .cache
            .get(&newpath.to_string_lossy(), config.executable_path)
        {
            Some(elc) => Some(elc),
            None => open_macho_file(&newpath, config.executable_path).ok(),
        };
        if let Some(elc) = elc {
            let dir = pathutils::get_path(&newpath);
            let depd = deptree.addnode(
                DepNode {
                    path: dir.clone(),
                    name: pathutils::get_name(&newpath),
                    mode,
                    found: false,
                    searched: Vec::new(),
                },
                depp,
            );
            return Some((elc, depd, dir.unwrap_or_default()));
        }
    }
    None
}

fn open_macho_file<P: AsRef<Path>>(
    filename: &P,
    executable_path: &str,
) -> Result<MachOInfo, std::io::Error> {
    let file = fs::File::open(filename)?;

    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return Err(Error::other("Failed to map file")),
    };

    let loader_path = pathutils::get_path(filename).unwrap_or_default();
    parse_object(&mmap, 0, executable_path, &loader_path).map_err(Error::other)
}

fn parse_object(
    data: &[u8],
    offset: u64,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, &'static str> {
    let kind = match object::FileKind::parse_at(data, offset) {
        Ok(file) => file,
        Err(_err) => return Err("Failed to parse file"),
    };

    match kind {
        object::FileKind::MachO32 => parse_macho32(data, offset, executable_path, loader_path),
        object::FileKind::MachO64 => parse_macho64(data, offset, executable_path, loader_path),
        object::FileKind::MachOFat32 => parse_macho_fat32(data, executable_path, loader_path),
        object::FileKind::MachOFat64 => parse_macho_fat64(data, executable_path, loader_path),
        _ => Err("Invalid object"),
    }
}

fn parse_macho32(
    data: &[u8],
    offset: u64,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, &'static str> {
    if let Ok(macho) = MachHeader32::parse(data, offset) {
        return parse_macho(macho, data, offset, executable_path, loader_path);
    }
    Err("Invalid Mach-O 32 object")
}

fn parse_macho64(
    data: &[u8],
    offset: u64,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, &'static str> {
    if let Ok(macho) = MachHeader64::parse(data, offset) {
        return parse_macho(macho, data, offset, executable_path, loader_path);
    }
    Err("Invalid Mach-O 64 object")
}

fn parse_macho_fat32(
    data: &[u8],
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, &'static str> {
    if let Ok(fat) = MachOFatFile32::parse(data) {
        return parse_macho_fat(data, fat.arches(), executable_path, loader_path);
    }
    Err("Invalid FAT Mach-O 32 object")
}

fn parse_macho_fat64(
    data: &[u8],
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, &'static str> {
    if let Ok(fat) = MachOFatFile64::parse(data) {
        return parse_macho_fat(data, fat.arches(), executable_path, loader_path);
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
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, &'static str> {
    for arch in arches {
        if check_current_arch(arch.architecture()) {
            if let Ok(fatdata) = arch.data(data) {
                return parse_object(fatdata, 0, executable_path, loader_path);
            }
        }
    }
    Err("Invalid FAT Mach-O architecture")
}

fn parse_macho<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    data: &[u8],
    offset: u64,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, &'static str> {
    let mut deps = DepsVec::new();
    let mut rpath = search_path::SearchPathVec::new();

    if let Ok(endian) = header.endian() {
        if let Ok(mut commands) = header.load_commands(endian, data, offset) {
            while let Ok(Some(command)) = commands.next() {
                match parse_load_command::<Mach>(endian, command) {
                    Some((LoadCommand::Dylib, dylib)) => deps.push(dylib),
                    Some((LoadCommand::Rpath, path)) => {
                        let path = path
                            .replace("@executable_path", executable_path)
                            .replace("@loader_path", loader_path);
                        rpath.add_path(path.as_str());
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(MachOInfo { rpath, deps })
}

enum LoadCommand {
    Dylib,
    Rpath,
}

fn parse_string(data: Option<&[u8]>) -> Option<String> {
    data.and_then(|s| str::from_utf8(s).ok().map(|s| s.to_string()))
}

fn parse_load_command<Mach: MachHeader>(
    endian: Mach::Endian,
    command: LoadCommandData<Mach::Endian>,
) -> Option<(LoadCommand, String)> {
    if let Ok(variant) = command.variant() {
        match variant {
            LoadCommandVariant::Dylib(x) => {
                if let Some(dylib) = parse_string(command.string(endian, x.dylib.name).ok()) {
                    return Some((LoadCommand::Dylib, dylib));
                };
                None
            }
            LoadCommandVariant::Rpath(x) => {
                if let Some(rpath) = parse_string(command.string(endian, x.path).ok()) {
                    return Some((LoadCommand::Rpath, rpath));
                };
                None
            }
            _ => None,
        }
    } else {
        None
    }
}
