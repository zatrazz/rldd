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

// A dependency recorded on a dylib load command: the load path (install
// name) along with the attributes reported by dyld_info -dependents.
#[derive(Debug)]
struct MachODep {
    name: String,
    attrs: Vec<&'static str>,
}

type DepsVec = Vec<MachODep>;

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

pub fn resolve_binary(
    cache: &mut DyldCache,
    preload: &search_path::SearchPathVec,
    all: bool,
    verbose: bool,
    depth: usize,
    ignore_prefix: &[String],
    arg: &str,
) -> Result<DepTree, std::io::Error> {
    // Mach-O images may exist only inside the dyld shared cache (macOS 11+),
    // so fall back to a cache lookup by the install name when the file is not
    // present.
    let (filename, omf) = match Path::new(arg).canonicalize() {
        Ok(filename) => {
            let executable_path =
                pathutils::get_path(&filename).ok_or(std::io::Error::other(format!(
                    "failed to get path of input file {arg}"
                )))?;
            let omf = open_macho_file(&filename, &executable_path)?;
            (filename, omf)
        }
        Err(err) => match cache.get(arg, &pathutils::get_path(&Path::new(arg)).unwrap_or_default())
        {
            Some(omf) => (Path::new(arg).to_path_buf(), omf),
            None => return Err(err),
        },
    };

    let executable_path = pathutils::get_path(&filename).ok_or(std::io::Error::other(format!(
        "failed to get path of input file {arg}"
    )))?;

    if verbose {
        println!(
            "{}: search path information\n\
            \x20 rpath: {}\n\
            \x20 dyld cache: {}",
            filename.display(),
            search_path::format_list(&omf.rpath),
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
        attrs: Vec::new(),
        searched: Vec::new(),
    });

    let config = Config {
        cache,
        executable_path: &executable_path,
        all,
        depth,
        ignore_prefix,
    };

    for pload in preload {
        let dep = MachODep {
            name: pload.path.clone(),
            attrs: Vec::new(),
        };
        resolve_dependency(
            &config,
            &executable_path,
            &omf.rpath,
            &dep,
            &mut deptree,
            depp,
            true,
            1,
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
            1,
        );
    }

    Ok(deptree)
}

struct Config<'a> {
    cache: &'a DyldCache,
    executable_path: &'a str,
    all: bool,
    // Limit the dependency tree to DEPTH levels, mimicking dylibtree, with
    // 0 meaning no limit.
    depth: usize,
    // Prune dependencies whose load path starts with any of the prefixes,
    // mimicking dylibtree.
    ignore_prefix: &'a [String],
}

#[allow(clippy::too_many_arguments)]
fn resolve_dependency(
    config: &Config,
    loader_path: &str,
    rpaths: &search_path::SearchPathVec,
    dep: &MachODep,
    deptree: &mut DepTree,
    depp: usize,
    preload: bool,
    level: usize,
) {
    let dependency = dep
        .name
        .replace("@executable_path", config.executable_path)
        .replace("@loader_path", loader_path);

    if config
        .ignore_prefix
        .iter()
        .any(|prefix| dependency.starts_with(prefix.as_str()))
    {
        return;
    }

    // To avoid circular dependencies, check if deptree already contains the
    // dependency.
    if check_already_resolved(config, &dependency, &dep.attrs, deptree, depp) {
        return;
    }

    if let Some((elc, depd, path)) =
        find_dependency(config, rpaths, &dependency, &dep.attrs, deptree, depp, preload)
    {
        // Stop descending once the depth limit is reached.
        if config.depth != 0 && level >= config.depth {
            return;
        }
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
            resolve_dependency(
                config,
                &path,
                &newrpaths,
                dep,
                deptree,
                depd,
                preload,
                level + 1,
            );
        }
    }
}

// Check if the dependency was already resolved, adding an already found
// node when the -a option is used.
fn check_already_resolved(
    config: &Config,
    dependency: &str,
    attrs: &[&'static str],
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
                    attrs: attrs.to_vec(),
                    searched: Vec::new(),
                },
                depp,
            );
        }
        return true;
    }
    false
}

// Resolve DEPENDENCY the way dyld_info/otool, the recorded load path is taken
// verbatim (with @rpath expanded against the run-path list when present) and
// checked against the dyld cache and the filesystem.
// When found a node is added to the dependency tree and the parsed object, the
// node index, and the directory of the resolved path (the @loader_path for the
// object own dependencies) are returned.
fn find_dependency(
    config: &Config,
    rpaths: &search_path::SearchPathVec,
    dependency: &str,
    attrs: &[&'static str],
    deptree: &mut DepTree,
    depp: usize,
    preload: bool,
) -> Option<(MachOInfo, usize, String)> {
    if dependency.contains("@rpath") {
        for rpath in rpaths {
            let expanded = dependency.replace("@rpath", rpath.path.as_str());
            match resolve_path(config, &expanded, attrs, DepMode::DtRpath, deptree, depp) {
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
        match resolve_path(config, dependency, attrs, mode, deptree, depp) {
            ResolveResult::Found(r) => return Some(r),
            ResolveResult::Skip => return None,
            ResolveResult::Miss => {}
        }
    }

    // The dependency was not found: record the load path itself so the
    // report shows the name the binary links against.
    deptree.addnode(
        DepNode {
            path: None,
            name: dependency.to_string(),
            mode: DepMode::NotFound,
            found: false,
            attrs: attrs.to_vec(),
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
    let mut searched = Vec::new();
    if dependency.contains("@rpath") {
        if rpaths.is_empty() {
            searched.push(format!("{dependency} (empty run-path list)"));
        }
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
    searched
}

// The result of a single candidate path resolution.
enum ResolveResult {
    // Found and added to the dependency tree.
    Found((MachOInfo, usize, String)),
    // Already present in the dependency tree.
    Skip,
    // Not found through this candidate path.
    Miss,
}

// Try to resolve a candidate path against the dyld cache and then the
// filesystem, adding a node to the dependency tree when found.
fn resolve_path(
    config: &Config,
    dependency: &str,
    attrs: &[&'static str],
    mode: DepMode,
    deptree: &mut DepTree,
    depp: usize,
) -> ResolveResult {
    // The expanded @rpath candidates require their own check against the
    // dependency tree, since the recorded nodes hold the resolved path.
    if check_already_resolved(config, dependency, attrs, deptree, depp) {
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
                attrs: attrs.to_vec(),
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
    if check_already_resolved(config, &path.to_string_lossy(), attrs, deptree, depp) {
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
            attrs: attrs.to_vec(),
            searched: Vec::new(),
        },
        depp,
    );
    ResolveResult::Found((elc, depd, dir.unwrap_or_default()))
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
                    Some(LoadCommand::Dylib(dep)) => deps.push(dep),
                    Some(LoadCommand::Rpath(path)) => {
                        let path = path
                            .replace("@executable_path", executable_path)
                            .replace("@loader_path", loader_path);
                        rpath.add_path(path.as_str());
                    }
                    None => {}
                }
            }
        }
    }

    Ok(MachOInfo { rpath, deps })
}

enum LoadCommand {
    Dylib(MachODep),
    Rpath(String),
}

fn parse_string(data: Option<&[u8]>) -> Option<String> {
    data.and_then(|s| str::from_utf8(s).ok().map(|s| s.to_string()))
}

fn dylib_attributes<Mach: MachHeader>(
    endian: Mach::Endian,
    command: &LoadCommandData<Mach::Endian>,
    dylib: &DylibCommand<Mach::Endian>,
) -> Vec<&'static str> {
    let mut flags = match command.cmd() {
        LC_LOAD_WEAK_DYLIB => DYLIB_USE_WEAK_LINK.0,
        LC_REEXPORT_DYLIB => DYLIB_USE_REEXPORT.0,
        LC_LOAD_UPWARD_DYLIB => DYLIB_USE_UPWARD.0,
        _ => 0,
    };
    // The dylib_use_command alternate encoding (macOS 15) records the attributes
    // as flags, with a marker on the old timestamp field.
    if dylib.dylib.timestamp.get(endian) == DYLIB_USE_MARKER {
        if let Ok(command) = command.data::<DylibUseCommand<Mach::Endian>>() {
            flags |= command.flags.get(endian).0;
        }
    }

    let mut attrs = Vec::new();
    if flags & DYLIB_USE_WEAK_LINK.0 != 0 {
        attrs.push("weak-link");
    }
    if flags & DYLIB_USE_REEXPORT.0 != 0 {
        attrs.push("re-export");
    }
    if flags & DYLIB_USE_UPWARD.0 != 0 {
        attrs.push("upward");
    }
    if flags & DYLIB_USE_DELAYED_INIT.0 != 0 {
        attrs.push("delay-init");
    }
    attrs
}

fn parse_load_command<Mach: MachHeader>(
    endian: Mach::Endian,
    command: LoadCommandData<Mach::Endian>,
) -> Option<LoadCommand> {
    match command.variant().ok()? {
        LoadCommandVariant::Dylib(x) => {
            let name = parse_string(command.string(endian, x.dylib.name).ok())?;
            Some(LoadCommand::Dylib(MachODep {
                name,
                attrs: dylib_attributes::<Mach>(endian, &command, x),
            }))
        }
        LoadCommandVariant::Rpath(x) => {
            let path = parse_string(command.string(endian, x.path).ok())?;
            Some(LoadCommand::Rpath(path))
        }
        _ => None,
    }
}
