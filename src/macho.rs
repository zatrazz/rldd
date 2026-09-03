use std::io::Error;
use std::path::{Path, PathBuf};
use std::{fs, str};

use object::macho::*;
use object::read::macho::*;
use object::Endianness;

use crate::deptree::*;
use crate::pathutils;
use crate::search_path;
use crate::search_path::*;

mod arch;
mod dyldcache;
pub use arch::Arch;
pub use dyldcache::DyldCache;

// A dependency recorded on a dylib load command: the load path (install
// name) along with the attributes reported by dyld_info -dependents and
// the versions reported by otool -L.
#[derive(Debug)]
struct MachODep {
    name: String,
    attrs: Vec<&'static str>,
    version: Option<String>,
}

type DepsVec = Vec<MachODep>;

#[derive(Default, Debug)]
struct MachOInfo {
    rpath: search_path::SearchPathVec,
    deps: DepsVec,
    // The LC_ID_DYLIB install name.
    id: Option<String>,
    // The LC_BUILD_VERSION/LC_VERSION_MIN_* information.
    platform: Option<String>,
    // The LC_UUID value.
    uuid: Option<String>,
}

// The DYLD_* environment search paths and image suffix, mimicked with
// command line options like the ELF backend does for LD_LIBRARY_PATH.
pub struct DyldEnv {
    pub library_path: search_path::SearchPathVec,
    pub framework_path: search_path::SearchPathVec,
    pub fallback_library_path: search_path::SearchPathVec,
    pub fallback_framework_path: search_path::SearchPathVec,
    pub image_suffix: Option<String>,
}

// The resolution context: the dyld shared cache along with the architecture
// used to select Mach-O slices and the cache flavor.
pub struct MachOContext {
    cache: DyldCache,
    arch: Arch,
}

impl MachOContext {
    // Retrieve a dynamic object information from the dyld system cache.
    fn get(&self, name: &str, executable_path: &str) -> Option<MachOInfo> {
        match self.cache.image(name)? {
            Some((data, offset)) => {
                let loader_path = pathutils::get_path(&Path::new(name)).unwrap_or_default();
                parse_object(data, offset, &self.arch, executable_path, &loader_path).ok()
            }
            None => Some(MachOInfo::default()),
        }
    }
}

pub fn create_context(arch: Option<&str>) -> Result<MachOContext, String> {
    let arch = Arch::new(arch)?;
    let cache = dyldcache::load(arch.cache_names());
    Ok(MachOContext { cache, arch })
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_binary(
    ctx: &mut MachOContext,
    preload: &[String],
    env: &DyldEnv,
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
            let executable_path = pathutils::get_path(&filename).ok_or(std::io::Error::other(
                format!("failed to get path of input file {arg}"),
            ))?;
            let omf = open_macho_file(&filename, &ctx.arch, &executable_path)?;
            (filename, omf)
        }
        Err(err) => match ctx.get(
            arg,
            &pathutils::get_path(&Path::new(arg)).unwrap_or_default(),
        ) {
            Some(omf) => (Path::new(arg).to_path_buf(), omf),
            None => return Err(err),
        },
    };

    let executable_path = pathutils::get_path(&filename).ok_or(std::io::Error::other(format!(
        "failed to get path of input file {arg}"
    )))?;

    if verbose {
        print_object_information(ctx, env, &filename, &omf);
    }

    let mut deptree = DepTree::new();
    let depp = deptree.addroot(DepNode {
        path: Some(executable_path.clone()),
        name: pathutils::get_name(&filename),
        mode: DepMode::Executable,
        found: false,
        alias: None,
        attrs: Vec::new(),
        version: None,
        searched: Vec::new(),
    });

    let config = Config {
        ctx,
        executable_path: &executable_path,
        env,
        all,
        depth,
        ignore_prefix,
    };

    for pload in preload {
        let dep = MachODep {
            name: pload.clone(),
            attrs: Vec::new(),
            version: None,
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

// The verbose object information: the object metadata from the load
// commands along with the search path lists used for the resolution.
fn print_object_information(ctx: &MachOContext, env: &DyldEnv, filename: &Path, omf: &MachOInfo) {
    let mut lines = vec![format!("{}: object information", filename.display())];
    lines.push(format!("  arch: {}", ctx.arch.name()));
    if let Some(id) = &omf.id {
        lines.push(format!("  install name: {id}"));
    }
    if let Some(platform) = &omf.platform {
        lines.push(format!("  platform: {platform}"));
    }
    if let Some(uuid) = &omf.uuid {
        lines.push(format!("  uuid: {uuid}"));
    }
    lines.push(format!("  rpath: {}", search_path::format_list(&omf.rpath)));
    for (name, list) in [
        ("library path", &env.library_path),
        ("framework path", &env.framework_path),
        ("fallback library path", &env.fallback_library_path),
        ("fallback framework path", &env.fallback_framework_path),
    ] {
        if !list.is_empty() {
            lines.push(format!("  {name}: {}", search_path::format_list(list)));
        }
    }
    if let Some(suffix) = &env.image_suffix {
        lines.push(format!("  image suffix: {suffix}"));
    }
    lines.push(format!(
        "  dyld cache: {}",
        if ctx.cache.is_empty() {
            "not found".to_string()
        } else {
            format!("{} images", ctx.cache.len())
        }
    ));
    println!("{}", lines.join("\n"));
}

struct Config<'a> {
    ctx: &'a MachOContext,
    executable_path: &'a str,
    env: &'a DyldEnv,
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
    if check_already_resolved(config, &dependency, dep, deptree, depp) {
        return;
    }

    if let Some((elc, depd, path)) =
        find_dependency(config, rpaths, &dependency, dep, deptree, depp, preload)
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
    dep: &MachODep,
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
                    alias: None,
                    attrs: dep.attrs.clone(),
                    version: dep.version.clone(),
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
// verbatim (with @executable_path, @loader_path, and @rpath expanded) and
// checked against the dyld cache and the filesystem, with the DYLD_*
// environment search paths applied in the dyld order.
// When found a node is added to the dependency tree and the parsed object, the
// node index, and the directory of the resolved path (the @loader_path for the
// object own dependencies) are returned.
fn find_dependency(
    config: &Config,
    rpaths: &search_path::SearchPathVec,
    dependency: &str,
    dep: &MachODep,
    deptree: &mut DepTree,
    depp: usize,
    preload: bool,
) -> Option<(MachOInfo, usize, String)> {
    for (candidate, mode) in candidate_paths(config, rpaths, dependency, preload) {
        for candidate in suffix_variants(config, &candidate) {
            match resolve_path(config, &candidate, dep, mode, deptree, depp) {
                ResolveResult::Found(r) => return Some(r),
                ResolveResult::Skip => return None,
                ResolveResult::Miss => {}
            }
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
            alias: None,
            attrs: dep.attrs.clone(),
            version: dep.version.clone(),
            searched: searched_locations(config, rpaths, dependency, preload),
        },
        depp,
    );
    None
}

// The candidate locations for a load path, in the order dyld searches them:
// 1. The DYLD_FRAMEWORK_PATH directories (for framework load paths),
// 2. DYLD_LIBRARY_PATH directories (by leaf name),
// 3. The load path itself (with @rpath expanded against the run-path list),
// 4. And at last the DYLD_FALLBACK_FRAMEWORK_PATH or DYLD_FALLBACK_LIBRARY_PATH
//    directories.
fn candidate_paths(
    config: &Config,
    rpaths: &search_path::SearchPathVec,
    dependency: &str,
    preload: bool,
) -> Vec<(String, DepMode)> {
    let mut candidates = Vec::new();

    let partial = framework_partial_path(dependency);
    if let Some(partial) = partial {
        for dir in &config.env.framework_path {
            candidates.push((format!("{}/{partial}", dir.path), DepMode::LdFrameworkPath));
        }
    }
    let leaf = pathutils::get_name(&Path::new(dependency));
    for dir in &config.env.library_path {
        candidates.push((format!("{}/{leaf}", dir.path), DepMode::LdLibraryPath));
    }

    if dependency.contains("@rpath") {
        for rpath in rpaths {
            candidates.push((expand_rpath(dependency, &rpath.path), DepMode::DtRpath));
        }
    } else {
        let mode = if preload {
            DepMode::Preload
        } else {
            DepMode::Direct
        };
        candidates.push((dependency.to_string(), mode));
    }

    // Like dyld, the fallback framework and library lists are mutually
    // exclusive.  Frameworks use the former, plain dylibs the latter.
    if let Some(partial) = partial {
        for dir in &config.env.fallback_framework_path {
            candidates.push((
                format!("{}/{partial}", dir.path),
                DepMode::LdFallbackFrameworkPath,
            ));
        }
    } else {
        for dir in &config.env.fallback_library_path {
            candidates.push((
                format!("{}/{leaf}", dir.path),
                DepMode::LdFallbackLibraryPath,
            ));
        }
    }

    candidates
}

fn expand_rpath(dependency: &str, rpath: &str) -> String {
    dependency.replace("@rpath", rpath.strip_suffix('/').unwrap_or(rpath))
}

const CRYPTEX_OS_PATH: &str = "/System/Volumes/Preboot/Cryptexes/OS";

// The candidate path below the OS cryptex mount.
fn cryptex_path(path: &Path) -> Option<PathBuf> {
    path.strip_prefix("/")
        .ok()
        .map(|rest| Path::new(CRYPTEX_OS_PATH).join(rest))
}

// The realpath(3) of an absolute path whose leaf may not exist (the macOS
// semantics, which resolve the symlinks of the directory components).
fn realpath_leaf(path: &Path) -> Option<String> {
    let parent = path.parent()?.canonicalize().ok()?;
    Some(
        parent
            .join(path.file_name()?)
            .to_string_lossy()
            .into_owned(),
    )
}

// The framework partial path (Foo.framework/Versions/A/Foo) of a load path
// whose leaf name matches the framework name, mimicking the dyld
// getFrameworkPartialPath check used for the framework search paths.
fn framework_partial_path(path: &str) -> Option<&str> {
    let idx = path.rfind(".framework/")?;
    let start = path[..idx].rfind('/').map(|i| i + 1).unwrap_or(0);
    let leaf = path.rsplit('/').next()?;
    if &path[start..idx] == leaf {
        Some(&path[start..])
    } else {
        None
    }
}

// The DYLD_IMAGE_SUFFIX variants of a candidate path: the suffixed name
// first (inserted before the .dylib extension, appended otherwise) and then
// the plain one.
fn suffix_variants(config: &Config, path: &str) -> Vec<String> {
    let mut variants = Vec::new();
    if let Some(suffix) = &config.env.image_suffix {
        variants.push(match path.strip_suffix(".dylib") {
            Some(stem) => format!("{stem}{suffix}.dylib"),
            None => format!("{path}{suffix}"),
        });
    }
    variants.push(path.to_string());
    variants
}

// The locations searched for a not found dependency, printed in verbose mode.
fn searched_locations(
    config: &Config,
    rpaths: &search_path::SearchPathVec,
    dependency: &str,
    preload: bool,
) -> Vec<String> {
    let mut searched = Vec::new();
    if dependency.contains("@rpath") && rpaths.is_empty() {
        searched.push(format!("{dependency} (empty run-path list)"));
    }
    for (candidate, _) in candidate_paths(config, rpaths, dependency, preload) {
        for variant in suffix_variants(config, &candidate) {
            let cryptex = cryptex_path(Path::new(&variant));
            searched.push(variant);
            if let Some(cryptex) = cryptex {
                searched.push(cryptex.to_string_lossy().into_owned());
            }
        }
    }
    searched.push(
        if config.ctx.cache.is_empty() {
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
// filesystem, adding a node to the dependency tree when found.  An
// absolute path not found on the root filesystem is retried below the OS
// cryptex mount.
fn resolve_path(
    config: &Config,
    dependency: &str,
    dep: &MachODep,
    mode: DepMode,
    deptree: &mut DepTree,
    depp: usize,
) -> ResolveResult {
    match resolve_cache(config, dependency, dep, deptree, depp) {
        ResolveResult::Miss => {}
        result => return result,
    }

    // Then the filesystem, only for absolute paths.
    let path = Path::new(dependency);
    if !path.is_absolute() {
        return ResolveResult::Miss;
    }
    match resolve_file(config, path, dep, mode, deptree, depp) {
        ResolveResult::Miss => {}
        result => return result,
    }
    if let Some(cryptex) = cryptex_path(path) {
        match resolve_file(config, &cryptex, dep, mode, deptree, depp) {
            ResolveResult::Miss => {}
            result => return result,
        }
    }

    if matches!(mode, DepMode::Direct | DepMode::Preload) {
        if let Some(real) = realpath_leaf(path).filter(|real| real != dependency) {
            return resolve_cache(config, &real, dep, deptree, depp);
        }
    }
    ResolveResult::Miss
}

// Try NAME against the dyld cache, if existent.
fn resolve_cache(
    config: &Config,
    name: &str,
    dep: &MachODep,
    deptree: &mut DepTree,
    depp: usize,
) -> ResolveResult {
    // The expanded candidates require their own check against the
    // dependency tree, since the recorded nodes hold the resolved path.
    if check_already_resolved(config, name, dep, deptree, depp) {
        return ResolveResult::Skip;
    }
    let Some(elc) = config.ctx.get(name, config.executable_path) else {
        return ResolveResult::Miss;
    };
    let path = Path::new(name);
    let dir = pathutils::get_path(&path);
    let depd = deptree.addnode(
        DepNode {
            path: dir.clone(),
            name: pathutils::get_name(&path),
            mode: DepMode::LdCache,
            found: false,
            alias: None,
            attrs: dep.attrs.clone(),
            version: dep.version.clone(),
            searched: Vec::new(),
        },
        depp,
    );
    ResolveResult::Found((elc, depd, dir.unwrap_or_default()))
}

fn resolve_file(
    config: &Config,
    path: &Path,
    dep: &MachODep,
    mode: DepMode,
    deptree: &mut DepTree,
    depp: usize,
) -> ResolveResult {
    // The canonicalization also checks the file existence.
    let Ok(path) = path.canonicalize() else {
        return ResolveResult::Miss;
    };
    if check_already_resolved(config, &path.to_string_lossy(), dep, deptree, depp) {
        return ResolveResult::Skip;
    }
    let Ok(elc) = open_macho_file(&path, &config.ctx.arch, config.executable_path) else {
        return ResolveResult::Miss;
    };
    let dir = pathutils::get_path(&path);
    let depd = deptree.addnode(
        DepNode {
            path: dir.clone(),
            name: pathutils::get_name(&path),
            mode,
            found: false,
            alias: None,
            attrs: dep.attrs.clone(),
            version: dep.version.clone(),
            searched: Vec::new(),
        },
        depp,
    );
    ResolveResult::Found((elc, depd, dir.unwrap_or_default()))
}

fn open_macho_file<P: AsRef<Path>>(
    filename: &P,
    arch: &Arch,
    executable_path: &str,
) -> Result<MachOInfo, std::io::Error> {
    let file = fs::File::open(filename)?;

    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return Err(Error::other("Failed to map file")),
    };

    let loader_path = pathutils::get_path(filename).unwrap_or_default();
    parse_object(&mmap, 0, arch, executable_path, &loader_path).map_err(Error::other)
}

fn parse_object(
    data: &[u8],
    offset: u64,
    arch: &Arch,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    let kind = match object::FileKind::parse_at(data, offset) {
        Ok(file) => file,
        Err(_err) => return Err("Failed to parse file".to_string()),
    };

    match kind {
        object::FileKind::MachO32 => {
            parse_macho32(data, offset, arch, executable_path, loader_path)
        }
        object::FileKind::MachO64 => {
            parse_macho64(data, offset, arch, executable_path, loader_path)
        }
        object::FileKind::MachOFat32 => parse_macho_fat32(data, arch, executable_path, loader_path),
        object::FileKind::MachOFat64 => parse_macho_fat64(data, arch, executable_path, loader_path),
        _ => Err("Invalid object".to_string()),
    }
}

fn parse_macho32(
    data: &[u8],
    offset: u64,
    arch: &Arch,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    if let Ok(macho) = MachHeader32::parse(data, offset) {
        return parse_macho(macho, data, offset, arch, executable_path, loader_path);
    }
    Err("Invalid Mach-O 32 object".to_string())
}

fn parse_macho64(
    data: &[u8],
    offset: u64,
    arch: &Arch,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    if let Ok(macho) = MachHeader64::parse(data, offset) {
        return parse_macho(macho, data, offset, arch, executable_path, loader_path);
    }
    Err("Invalid Mach-O 64 object".to_string())
}

fn parse_macho_fat32(
    data: &[u8],
    arch: &Arch,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    if let Ok(fat) = MachOFatFile32::parse(data) {
        return parse_macho_fat(data, fat.arches(), arch, executable_path, loader_path);
    }
    Err("Invalid FAT Mach-O 32 object".to_string())
}

fn parse_macho_fat64(
    data: &[u8],
    arch: &Arch,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    if let Ok(fat) = MachOFatFile64::parse(data) {
        return parse_macho_fat(data, fat.arches(), arch, executable_path, loader_path);
    }
    Err("Invalid FAT Mach-O 64 object".to_string())
}

fn parse_macho_fat<FatArch: object::read::macho::FatArch>(
    data: &[u8],
    arches: &[FatArch],
    arch: &Arch,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    // Prefer the slice with the exact requested subtype, then any slice with
    // a matching cpu type (a lenient version of the dyld slice grading).
    for exact in [true, false] {
        for slice in arches {
            if arch.matches_slice(slice.cputype(), slice.cpusubtype(), exact) {
                if let Ok(fatdata) = slice.data(data) {
                    return parse_object(fatdata, 0, arch, executable_path, loader_path);
                }
            }
        }
    }
    // Like the thin objects, a FAT file without a host architecture slice is
    // still inspected when the architecture was not explicitly requested.
    if !arch.explicit() {
        let fallback = arches
            .iter()
            .find(|slice| arch.translated_cputype(slice.cputype()))
            .or_else(|| arches.first());
        if let Some(slice) = fallback {
            if let Ok(fatdata) = slice.data(data) {
                return parse_object(fatdata, 0, arch, executable_path, loader_path);
            }
        }
    }
    Err(format!(
        "file does not contain architecture {}",
        arch.name()
    ))
}

fn parse_macho<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    data: &[u8],
    offset: u64,
    arch: &Arch,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    let mut info = MachOInfo::default();
    let mut platforms = Vec::new();

    if let Ok(endian) = header.endian() {
        // Thin objects are only checked when the architecture was explicitly
        // requested, so foreign binaries (e.g. x86_64 ones under Rosetta)
        // can still be inspected without the --arch option.
        if arch.explicit() && !arch.matches_cputype(header.cputype(endian)) {
            return Err(format!(
                "file does not contain architecture {}",
                arch.name()
            ));
        }
        if let Ok(mut commands) = header.load_commands(endian, data, offset) {
            while let Ok(Some(command)) = commands.next() {
                match parse_load_command::<Mach>(endian, command) {
                    Some(LoadCommand::Dylib(dep)) => info.deps.push(dep),
                    Some(LoadCommand::Rpath(path)) => {
                        let path = path
                            .replace("@executable_path", executable_path)
                            .replace("@loader_path", loader_path);
                        info.rpath.add_path(path.as_str());
                    }
                    Some(LoadCommand::Id(name)) => info.id = Some(name),
                    Some(LoadCommand::Platform(platform)) => platforms.push(platform),
                    Some(LoadCommand::Uuid(uuid)) => info.uuid = Some(uuid),
                    None => {}
                }
            }
        }
    }

    info.platform = format_platforms(platforms);
    Ok(info)
}

// Format the LC_BUILD_VERSION/LC_VERSION_MIN_* list, printing the dual
// macOS/Catalyst build versions as zippered the way dyld_info does.
fn format_platforms(platforms: Vec<PlatformInfo>) -> Option<String> {
    let zippered =
        |a: &PlatformInfo, b: &PlatformInfo| a.name == "macOS" && b.name == "Mac Catalyst";
    match platforms.as_slice() {
        [] => None,
        [a, b] if zippered(a, b) || zippered(b, a) => Some(format!(
            "zippered(macOS/Catalyst) (min {}, sdk {})",
            a.min, a.sdk
        )),
        entries => Some(
            entries
                .iter()
                .map(|p| format!("{} (min {}, sdk {})", p.name, p.min, p.sdk))
                .collect::<Vec<String>>()
                .join(", "),
        ),
    }
}

// A build platform recorded on a LC_BUILD_VERSION or LC_VERSION_MIN_*
// load command.
struct PlatformInfo {
    name: String,
    min: String,
    sdk: String,
}

enum LoadCommand {
    Dylib(MachODep),
    Rpath(String),
    Id(String),
    Platform(PlatformInfo),
    Uuid(String),
}

fn parse_string(data: Option<&[u8]>) -> Option<String> {
    data.and_then(|s| str::from_utf8(s).ok().map(|s| s.to_string()))
}

// Format a Mach-O version number the way otool -L does (X.Y.Z).
fn format_version(version: Version) -> String {
    format!(
        "{}.{}.{}",
        version.major(),
        version.minor(),
        version.update()
    )
}

// Format an OS version the way dyld_info -platform does (X.Y, with the
// update number only when set).
fn format_os_version(version: Version) -> String {
    let mut formatted = format!("{}.{}", version.major(), version.minor());
    if version.update() != 0 {
        formatted.push_str(&format!(".{}", version.update()));
    }
    formatted
}

fn platform_name(platform: Platform) -> String {
    match platform {
        PLATFORM_MACOS => "macOS".to_string(),
        PLATFORM_IOS => "iOS".to_string(),
        PLATFORM_TVOS => "tvOS".to_string(),
        PLATFORM_WATCHOS => "watchOS".to_string(),
        PLATFORM_BRIDGEOS => "bridgeOS".to_string(),
        PLATFORM_MACCATALYST => "Mac Catalyst".to_string(),
        PLATFORM_IOSSIMULATOR => "iOS simulator".to_string(),
        PLATFORM_TVOSSIMULATOR => "tvOS simulator".to_string(),
        PLATFORM_WATCHOSSIMULATOR => "watchOS simulator".to_string(),
        PLATFORM_DRIVERKIT => "DriverKit".to_string(),
        PLATFORM_VISIONOS => "visionOS".to_string(),
        PLATFORM_VISIONOSSIMULATOR => "visionOS simulator".to_string(),
        _ => format!("platform {}", platform.0),
    }
}

fn format_uuid(uuid: &[u8; 16]) -> String {
    let hex: String = uuid.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
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
                version: Some(format!(
                    "compatibility version {}, current version {}",
                    format_version(x.dylib.compatibility_version.get(endian)),
                    format_version(x.dylib.current_version.get(endian))
                )),
            }))
        }
        LoadCommandVariant::IdDylib(x) => {
            let name = parse_string(command.string(endian, x.dylib.name).ok())?;
            Some(LoadCommand::Id(name))
        }
        LoadCommandVariant::Rpath(x) => {
            let path = parse_string(command.string(endian, x.path).ok())?;
            Some(LoadCommand::Rpath(path))
        }
        LoadCommandVariant::BuildVersion(x, _) => Some(LoadCommand::Platform(PlatformInfo {
            name: platform_name(x.platform.get(endian)),
            min: format_os_version(x.minos.get(endian)),
            sdk: format_os_version(x.sdk.get(endian)),
        })),
        LoadCommandVariant::VersionMin(x) => {
            let platform = match command.cmd() {
                LC_VERSION_MIN_MACOSX => "macOS",
                LC_VERSION_MIN_IPHONEOS => "iOS",
                LC_VERSION_MIN_TVOS => "tvOS",
                LC_VERSION_MIN_WATCHOS => "watchOS",
                _ => "unknown",
            };
            Some(LoadCommand::Platform(PlatformInfo {
                name: platform.to_string(),
                min: format_os_version(x.version.get(endian)),
                sdk: format_os_version(x.sdk.get(endian)),
            }))
        }
        LoadCommandVariant::Uuid(x) => Some(LoadCommand::Uuid(format_uuid(&x.uuid))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpath_expansion_trailing_slash() {
        assert_eq!(
            expand_rpath(
                "@rpath/Foo.framework/Foo",
                "/System/Library/PrivateFrameworks"
            ),
            "/System/Library/PrivateFrameworks/Foo.framework/Foo"
        );
        assert_eq!(
            expand_rpath(
                "@rpath/Foo.framework/Foo",
                "/System/Library/PrivateFrameworks/"
            ),
            "/System/Library/PrivateFrameworks/Foo.framework/Foo"
        );
        assert_eq!(
            expand_rpath("@rpath/libfoo.dylib", "/usr/lib//"),
            "/usr/lib//libfoo.dylib"
        );
        assert_eq!(
            expand_rpath("@rpath/libfoo.dylib", "@loader_path/../lib"),
            "@loader_path/../lib/libfoo.dylib"
        );
    }
}
