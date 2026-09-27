use std::io::Error;
use std::path::{Path, PathBuf};

use object::macho::*;
use object::read::macho::*;
use object::Endianness;

use crate::deptree::*;
use crate::pathutils;
use crate::search_path;

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
    // The LC_RPATH entries, with @executable_path and @loader_path expanded.
    // Like dyld, an entry is kept whether or not its directory exists on
    // the root filesystem, since the candidates it leads to may still be
    // found in the dyld cache or below the OS cryptex mount.
    rpath: Vec<String>,
    deps: DepsVec,
    // The LC_ID_DYLIB install name.
    id: Option<String>,
    // The LC_BUILD_VERSION/LC_VERSION_MIN_* information, and the platforms
    // in the load command order.
    platform: Option<String>,
    platforms: Vec<Platform>,
    // The LC_UUID value.
    uuid: Option<String>,
    // The Mach-O header architecture and file type.
    cputype: CpuType,
    cpusubtype: CpuSubtype,
    filetype: FileType,
}

// The DYLD_* environment search paths and image suffix, mimicked with
// command line options like the ELF backend does for LD_LIBRARY_PATH.
struct DyldEnv {
    library_path: search_path::SearchPathVec,
    framework_path: search_path::SearchPathVec,
    fallback_library_path: search_path::SearchPathVec,
    fallback_framework_path: search_path::SearchPathVec,
    image_suffix: Option<String>,
}

// The resolution context: the architecture selecting the input slice (the
// one requested or the host one), the dyld shared caches, and the command
// line settings.
pub struct MachOContext {
    arch: Arch,
    // The dyld shared caches loaded so far, along with their names, since
    // each input selects the cache flavor of its architecture.
    caches: Vec<(&'static [&'static str], DyldCache)>,
    preload: Vec<String>,
    env: DyldEnv,
    all: bool,
    verbose: bool,
    depth: usize,
    ignore_prefix: Vec<String>,
}

impl MachOContext {
    // The index of the dyld shared cache with the NAMES flavor, loaded on
    // its first use.
    fn load_cache(&mut self, names: &'static [&'static str]) -> usize {
        match self.caches.iter().position(|(cached, _)| *cached == names) {
            Some(idx) => idx,
            None => {
                self.caches.push((names, dyldcache::load(names)));
                self.caches.len() - 1
            }
        }
    }
}

// Retrieve a dynamic object information from the dyld shared cache.
fn cache_image(cache: &DyldCache, name: &str, executable_path: &str) -> Option<MachOInfo> {
    match cache.image(name)? {
        Some((data, offset)) => {
            let loader_path = pathutils::get_path(&Path::new(name)).unwrap_or_default();
            parse_thin(data, offset, Check::Cache, executable_path, &loader_path).ok()
        }
        None => Some(MachOInfo::default()),
    }
}

pub fn create_context(opts: &crate::Options) -> Result<MachOContext, String> {
    let arch = Arch::new(opts.arch.as_deref())?;
    Ok(MachOContext {
        arch,
        caches: Vec::new(),
        preload: insert_libraries(&opts.preload),
        env: DyldEnv {
            library_path: search_path::from_string(&opts.library_path, &[':']),
            framework_path: search_path::from_string(&opts.framework_path, &[':']),
            fallback_library_path: search_path::from_string(&opts.fallback_library_path, &[':']),
            fallback_framework_path: search_path::from_string(
                &opts.fallback_framework_path,
                &[':'],
            ),
            image_suffix: opts.image_suffix.clone(),
        },
        all: opts.all,
        verbose: opts.verbose,
        depth: opts.depth,
        ignore_prefix: opts.ignore_prefix.clone(),
    })
}

// The DYLD_INSERT_LIBRARIES entries.  Unlike the ELF loaders, dyld splits
// the list on colons only (PathOverrides::forEachInColonList), so a path
// with spaces is a single entry.
fn insert_libraries(list: &str) -> Vec<String> {
    list.split(':')
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn resolve_binary(ctx: &mut MachOContext, arg: &str) -> Result<DepTree, std::io::Error> {
    // Mach-O images may exist only inside the dyld shared cache (macOS 11+),
    // so fall back to a cache lookup by the install name when the file is not
    // present, on the cache of the requested or the host architecture.
    let (filename, omf, from_cache) = match Path::new(arg).canonicalize() {
        Ok(filename) => {
            let executable_path = pathutils::get_path(&filename).ok_or(std::io::Error::other(
                format!("failed to get path of input file {arg}"),
            ))?;
            let omf = open_macho_file(&filename, Check::Input(&ctx.arch), &executable_path)?;
            (filename, omf, false)
        }
        Err(err) => {
            let cache = ctx.load_cache(ctx.arch.cache_names());
            match cache_image(
                &ctx.caches[cache].1,
                arg,
                &pathutils::get_path(&Path::new(arg)).unwrap_or_default(),
            ) {
                Some(omf) => (Path::new(arg).to_path_buf(), omf, true),
                None => return Err(err),
            }
        }
    };

    // Like dyld, which grades the dependency slices by the main executable
    // architecture, the input slice sets the process architecture every
    // dependency has to match, along with the dyld cache flavor.
    let arch = Arch::process(omf.cputype, omf.cpusubtype, omf.filetype);
    let cache = ctx.load_cache(arch.cache_names());
    let ctx: &MachOContext = ctx;
    let cache = &ctx.caches[cache].1;

    let executable_path = pathutils::get_path(&filename).ok_or(std::io::Error::other(format!(
        "failed to get path of input file {arg}"
    )))?;

    if ctx.verbose {
        print_object_information(&arch, cache, &ctx.env, &filename, &omf);
    }

    let mut tree = Tree::new();
    let path = filename.to_string_lossy().into_owned();
    let cache_image = cache.image_id(&path).filter(|_| from_cache);
    let depp = tree.add_image(
        DepNode::new(
            Some(executable_path.clone()),
            pathutils::get_name(&filename),
            DepMode::Executable,
        ),
        None,
        path,
        &omf,
        cache_image,
    );

    let config = Config {
        arch: &arch,
        macos: omf.filetype == MH_EXECUTE
            && built_for_macos(&omf)
            && !omf.platforms.contains(&PLATFORM_MACCATALYST),
        cache,
        executable_path: &executable_path,
        env: &ctx.env,
        all: ctx.all,
        depth: ctx.depth,
        ignore_prefix: &ctx.ignore_prefix,
    };

    for pload in &ctx.preload {
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
            &mut tree,
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
            &mut tree,
            depp,
            false,
            1,
        );
    }

    Ok(tree.deptree)
}

// An image loaded on the dependency tree.  Like dyld (Loader::matchesPath),
// a later load path or candidate names it when it is the path the image was
// loaded from, or its install name when that differs, and an alias of a
// dyld cache image names that image (representsCachedDylibIndex).
struct Image {
    path: String,
    install_name: Option<String>,
    cache_image: Option<(usize, u64)>,
    node: DepNode,
}

// The dependency tree along with the images loaded on it.  A dependency not
// found is not an image, the way dyld only records the images it loaded, so
// a later request searches for it again with its own run-path list and
// loader path.  Neither is an image matched by its leaf name: a candidate
// from the DYLD_* search paths is a full path, checked like any other.
struct Tree {
    deptree: DepTree,
    images: Vec<Image>,
}

impl Tree {
    fn new() -> Tree {
        Tree {
            deptree: DepTree::new(),
            images: Vec::new(),
        }
    }

    // Add the node of the image ELC loaded from PATH, below PARENT (or as the
    // root), returning the node index.
    fn add_image(
        &mut self,
        node: DepNode,
        parent: Option<usize>,
        path: String,
        elc: &MachOInfo,
        cache_image: Option<(usize, u64)>,
    ) -> usize {
        // Only a dylib is also matched by its install name.
        let install_name = elc.id.clone().filter(|_| elc.filetype == MH_DYLIB);
        self.images.push(Image {
            path,
            install_name,
            cache_image,
            node: node.clone(),
        });
        match parent {
            Some(parent) => self.deptree.addnode(node, parent),
            None => self.deptree.addroot(node),
        }
    }

    // The node of the image loaded from PATH, or whose install name is PATH.
    fn image(&self, path: &str) -> Option<DepNode> {
        self.find(|image| image.path == path || image.install_name.as_deref() == Some(path))
    }

    // The node of the image loaded from the file at the real PATH, which dyld
    // matches by the file identity instead.
    fn file_image(&self, path: &str) -> Option<DepNode> {
        self.find(|image| image.cache_image.is_none() && image.path == path)
    }

    // The node of the image loaded from the dyld cache image ID.
    fn cache_image(&self, id: Option<(usize, u64)>) -> Option<DepNode> {
        id.and_then(|id| self.find(|image| image.cache_image == Some(id)))
    }

    fn find(&self, matches: impl Fn(&Image) -> bool) -> Option<DepNode> {
        self.images
            .iter()
            .find(|image| matches(image))
            .map(|image| image.node.clone())
    }
}

// The verbose object information: the object metadata from the load
// commands along with the search path lists used for the resolution.
fn print_object_information(
    arch: &Arch,
    cache: &DyldCache,
    env: &DyldEnv,
    filename: &Path,
    omf: &MachOInfo,
) {
    let mut lines = vec![format!("{}: object information", filename.display())];
    lines.push(format!("  arch: {}", arch.name()));
    if let Some(id) = &omf.id {
        lines.push(format!("  install name: {id}"));
    }
    if let Some(platform) = &omf.platform {
        lines.push(format!("  platform: {platform}"));
    }
    if let Some(uuid) = &omf.uuid {
        lines.push(format!("  uuid: {uuid}"));
    }
    lines.push(format!(
        "  rpath: {}",
        search_path::format_entries(omf.rpath.iter().map(String::as_str))
    ));
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
        if cache.is_empty() {
            "not found".to_string()
        } else {
            format!("{} images", cache.len())
        }
    ));
    outln!("{}", lines.join("\n"));
}

struct Config<'a> {
    // The process architecture, which the dependencies have to match.
    arch: &'a Arch,
    // Whether the process runs a main executable built for macOS alone.
    // dyld only loads the images built for the process platform, the one of
    // the main executable (UnsafeHeader::loadableIntoProcess), which for
    // macOS are the macOS and the zippered images.  The other platforms have
    // more rules (an iOS or a Mac Catalyst app on a Mac also loads the macOS
    // images, for instance), and an input that is not a main executable may
    // be loaded by processes of several platforms, so they are not checked.
    macos: bool,
    cache: &'a DyldCache,
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
    rpaths: &[String],
    dep: &MachODep,
    tree: &mut Tree,
    depp: usize,
    preload: bool,
    level: usize,
) {
    let dependency = dep
        .name
        .replace("@executable_path", config.executable_path)
        .replace("@loader_path", loader_path);

    if pathutils::has_prefix(&dependency, config.ignore_prefix) {
        return;
    }

    // To avoid circular dependencies, check if the dependency names an image
    // already loaded.  An @rpath load path only names an image with that
    // install name (dyld checks it first, before expanding the run-path
    // list), and its expansions are checked like any other candidate.
    if check_already_resolved(config, tree.image(&dependency), dep, tree, depp) {
        return;
    }

    if let Some((elc, depd, path)) =
        find_dependency(config, rpaths, &dependency, dep, tree, depp, preload)
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
        // The dependencies of an inserted library are loaded like any other
        // (dyld only inserts the DYLD_INSERT_LIBRARIES entries themselves).
        for dep in &elc.deps {
            resolve_dependency(config, &path, &newrpaths, dep, tree, depd, false, level + 1);
        }
    }
}

// Check if the dependency names the image FOUND already loaded, adding an
// already found node when the -a option is used.
fn check_already_resolved(
    config: &Config,
    found: Option<DepNode>,
    dep: &MachODep,
    tree: &mut Tree,
    depp: usize,
) -> bool {
    let Some(entry) = found else {
        return false;
    };
    tree.deptree.add_repeated(
        config.all,
        DepNode::repeat_of(&entry, entry.name.clone())
            .with_attrs(dep.attrs.clone())
            .with_version(dep.version.clone()),
        depp,
    );
    true
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
    rpaths: &[String],
    dependency: &str,
    dep: &MachODep,
    tree: &mut Tree,
    depp: usize,
    preload: bool,
) -> Option<(MachOInfo, usize, String)> {
    for (candidate, mode) in candidate_paths(config, rpaths, dependency, preload) {
        for candidate in suffix_variants(config, &candidate) {
            match resolve_path(config, &candidate, dep, mode, tree, depp) {
                ResolveResult::Found(r) => return Some(r),
                ResolveResult::Skip => return None,
                ResolveResult::Miss => {}
            }
        }
    }

    // The dependency was not found: record the load path as the binary
    // links against it, before the @executable_path and @loader_path
    // expansion, like the ELF and PE names.
    tree.deptree.addnode(
        DepNode::not_found(
            dep.name.clone(),
            searched_locations(config, rpaths, dependency, preload),
        )
        .with_attrs(dep.attrs.clone())
        .with_version(dep.version.clone()),
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
    rpaths: &[String],
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
            candidates.push((expand_rpath(dependency, rpath), DepMode::DtRpath));
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
    rpaths: &[String],
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
// filesystem, adding a node to the dependency tree when found.  An
// absolute path not found on the root filesystem is retried below the OS
// cryptex mount.
fn resolve_path(
    config: &Config,
    dependency: &str,
    dep: &MachODep,
    mode: DepMode,
    tree: &mut Tree,
    depp: usize,
) -> ResolveResult {
    match resolve_cache(config, dependency, dep, tree, depp) {
        ResolveResult::Miss => {}
        result => return result,
    }

    // Then the filesystem, only for absolute paths.
    let path = Path::new(dependency);
    if !path.is_absolute() {
        return ResolveResult::Miss;
    }
    match resolve_file(config, path, dep, mode, tree, depp) {
        ResolveResult::Miss => {}
        result => return result,
    }
    if let Some(cryptex) = cryptex_path(path) {
        match resolve_file(config, &cryptex, dep, mode, tree, depp) {
            ResolveResult::Miss => {}
            result => return result,
        }
    }

    if matches!(mode, DepMode::Direct | DepMode::Preload) {
        if let Some(real) = realpath_leaf(path).filter(|real| real != dependency) {
            return resolve_cache(config, &real, dep, tree, depp);
        }
    }
    ResolveResult::Miss
}

// Try NAME against the dyld cache, if existent.
fn resolve_cache(
    config: &Config,
    name: &str,
    dep: &MachODep,
    tree: &mut Tree,
    depp: usize,
) -> ResolveResult {
    // Each candidate is checked against the images already loaded, by its
    // path and by the cache image an alias path leads to.
    let cache_image = config.cache.image_id(name);
    let found = tree.image(name).or_else(|| tree.cache_image(cache_image));
    if check_already_resolved(config, found, dep, tree, depp) {
        return ResolveResult::Skip;
    }
    let Some(elc) = self::cache_image(config.cache, name, config.executable_path)
        .filter(|elc| loads_platform(config, elc))
    else {
        return ResolveResult::Miss;
    };
    add_found(
        elc,
        Path::new(name),
        DepMode::LdCache,
        dep,
        tree,
        depp,
        cache_image,
    )
}

fn resolve_file(
    config: &Config,
    path: &Path,
    dep: &MachODep,
    mode: DepMode,
    tree: &mut Tree,
    depp: usize,
) -> ResolveResult {
    if check_already_resolved(config, tree.image(&path.to_string_lossy()), dep, tree, depp) {
        return ResolveResult::Skip;
    }
    // The canonicalization also checks the file existence, and gives the
    // path of an image already loaded through another path (dyld compares
    // the file identity).
    let Ok(path) = path.canonicalize() else {
        return ResolveResult::Miss;
    };
    if check_already_resolved(
        config,
        tree.file_image(&path.to_string_lossy()),
        dep,
        tree,
        depp,
    ) {
        return ResolveResult::Skip;
    }
    // dyld only links against a dylib: the dependencies and the inserted
    // libraries are loaded with the canBeDylib option alone, so a bundle or
    // an executable is refused (JustInTimeLoader::makeJustInTimeLoaderDisk)
    // and the search continues.
    let Some(elc) = open_macho_file(
        &path,
        Check::Dependency(config.arch),
        config.executable_path,
    )
    .ok()
    .filter(|elc| elc.filetype == MH_DYLIB && loads_platform(config, elc)) else {
        return ResolveResult::Miss;
    };
    add_found(elc, &path, mode, dep, tree, depp, None)
}

// Whether the process platform loads the image ELC, the images of another
// platform being rejected like the other architectures (see Config::macos).
// A cache image whose header is outside the cache mappings is taken as is.
fn loads_platform(config: &Config, elc: &MachOInfo) -> bool {
    !config.macos || elc.cputype == CpuType(0) || built_for_macos(elc)
}

// Add the object ELC found at PATH (or at the CACHE_IMAGE of the dyld cache)
// to the dependency tree, returning it along with the node index and its
// directory (the @loader_path for the object own dependencies).
fn add_found(
    elc: MachOInfo,
    path: &Path,
    mode: DepMode,
    dep: &MachODep,
    tree: &mut Tree,
    depp: usize,
    cache_image: Option<(usize, u64)>,
) -> ResolveResult {
    let dir = pathutils::get_path(&path);
    let depd = tree.add_image(
        DepNode::new(dir.clone(), pathutils::get_name(&path), mode)
            .with_attrs(dep.attrs.clone())
            .with_version(dep.version.clone()),
        Some(depp),
        path.to_string_lossy().into_owned(),
        &elc,
        cache_image,
    );
    ResolveResult::Found((elc, depd, dir.unwrap_or_default()))
}

// How the architecture of a Mach-O image is checked.
#[derive(Clone, Copy)]
enum Check<'a> {
    // The input file, whose slice the requested or the host architecture
    // selects (Arch::input_slice).
    Input(&'a Arch),
    // A dependency, which dyld only loads from a slice the process
    // architecture grades (MachOFile::compatibleSlice), so a candidate
    // without one is rejected and the search continues.
    Dependency(&'a Arch),
    // A dyld cache image, built for the cache architecture.
    Cache,
}

impl Check<'_> {
    // The index of the slice to parse, among the architectures of a
    // universal file or the only one of a thin file.
    fn slice(&self, slices: &[(CpuType, CpuSubtype)]) -> Result<usize, String> {
        match self {
            Check::Input(arch) => arch
                .input_slice(slices)
                .ok_or_else(|| format!("file does not contain architecture {}", arch.name())),
            Check::Dependency(arch) => arch
                .best_slice(slices)
                .ok_or_else(|| format!("incompatible architecture (need {})", arch.name())),
            Check::Cache => Ok(0),
        }
    }
}

fn open_macho_file<P: AsRef<Path>>(
    filename: &P,
    check: Check,
    executable_path: &str,
) -> Result<MachOInfo, std::io::Error> {
    let mmap = pathutils::map_file(filename)?;

    let loader_path = pathutils::get_path(filename).unwrap_or_default();
    parse_object(&mmap, check, executable_path, &loader_path).map_err(Error::other)
}

// Parse a Mach-O file, either a thin image or a universal (FAT) file whose
// selected slice is then parsed.
fn parse_object(
    data: &[u8],
    check: Check,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    match object::FileKind::parse(data).map_err(|_| "Failed to parse file".to_string())? {
        object::FileKind::MachOFat32 => {
            let fat = MachOFatFile32::parse(data)
                .map_err(|_| "Invalid FAT Mach-O 32 object".to_string())?;
            parse_macho_fat(data, fat.arches(), check, executable_path, loader_path)
        }
        object::FileKind::MachOFat64 => {
            let fat = MachOFatFile64::parse(data)
                .map_err(|_| "Invalid FAT Mach-O 64 object".to_string())?;
            parse_macho_fat(data, fat.arches(), check, executable_path, loader_path)
        }
        _ => parse_thin(data, 0, check, executable_path, loader_path),
    }
}

// Parse the thin Mach-O image at OFFSET: a file, the slice of a universal
// file, or an image of the dyld cache.  Like dyld (MachOFile::compatibleSlice
// only accepts a slice with the MH_MAGIC header) and lipo, a universal file
// is not accepted as a slice of another one, which would otherwise recurse
// without end on a slice covering the whole file.
fn parse_thin(
    data: &[u8],
    offset: u64,
    check: Check,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    match object::FileKind::parse_at(data, offset)
        .map_err(|_| "Failed to parse file".to_string())?
    {
        object::FileKind::MachO32 => {
            let header = MachHeader32::parse(data, offset)
                .map_err(|_| "Invalid Mach-O 32 object".to_string())?;
            parse_macho(header, data, offset, check, executable_path, loader_path)
        }
        object::FileKind::MachO64 => {
            let header = MachHeader64::parse(data, offset)
                .map_err(|_| "Invalid Mach-O 64 object".to_string())?;
            parse_macho(header, data, offset, check, executable_path, loader_path)
        }
        object::FileKind::MachOFat32 | object::FileKind::MachOFat64 => {
            Err("slice is not a valid Mach-O image".to_string())
        }
        _ => Err("Invalid object".to_string()),
    }
}

fn parse_macho_fat<FatArch: object::read::macho::FatArch>(
    data: &[u8],
    arches: &[FatArch],
    check: Check,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    // Like dyld (Universal::valid), a slice past the end of the file makes
    // the whole file invalid.
    let slices = arches
        .iter()
        .map(|slice| slice.data(data))
        .collect::<Result<Vec<&[u8]>, _>>()
        .map_err(|_| "slice extends beyond the end of the file".to_string())?;
    // The slice is selected by the architecture recorded on the FAT header,
    // where libtool leaves out the ABI version bits of an arm64e slice, which
    // dyld then takes as the versioned arm64e (Universal::forEachSlice).
    let archs: Vec<(CpuType, CpuSubtype)> = arches
        .iter()
        .map(|slice| match (slice.cputype(), slice.cpusubtype()) {
            (CPU_TYPE_ARM64, subtype) if subtype.0 == CPU_SUBTYPE_ARM64E.0 => (
                CPU_TYPE_ARM64,
                CpuSubtype(subtype.0 | CPU_SUBTYPE_PTRAUTH_ABI.0),
            ),
            arch => arch,
        })
        .collect();
    let idx = check.slice(&archs)?;
    parse_thin(slices[idx], 0, check, executable_path, loader_path)
}

fn parse_macho<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    data: &[u8],
    offset: u64,
    check: Check,
    executable_path: &str,
    loader_path: &str,
) -> Result<MachOInfo, String> {
    let mut info = MachOInfo::default();
    let mut platforms = Vec::new();

    let endian = header
        .endian()
        .map_err(|_| "Invalid Mach-O object".to_string())?;
    // The image architecture is checked as well, which for a slice is the
    // one recorded on its own header (dyld checks both).  Without the --arch
    // option, the input is inspected whatever its architecture, so a foreign
    // binary (an x86_64 one under Rosetta, for instance) can be listed.
    info.cputype = header.cputype(endian);
    info.cpusubtype = header.cpusubtype(endian);
    info.filetype = header.filetype(endian);
    check.slice(&[(info.cputype, info.cpusubtype)])?;
    // Like dyld (UnsafeHeader::validStructureLoadCommands), a load command
    // table past the end of the image, a command smaller than its header or
    // extending past the table, and a string outside its command make the
    // image invalid, instead of silently shortening the dependency list.
    let mut commands = header
        .load_commands(endian, data, offset)
        .map_err(|_| "load commands exceed the length of the file".to_string())?;
    while let Some(command) = commands
        .next()
        .map_err(|_| "malformed load command".to_string())?
    {
        match parse_load_command::<Mach>(endian, command)? {
            Some(LoadCommand::Dylib(dep)) => info.deps.push(dep),
            Some(LoadCommand::Rpath(path)) => {
                let path = path
                    .replace("@executable_path", executable_path)
                    .replace("@loader_path", loader_path);
                if !path.is_empty() && !info.rpath.contains(&path) {
                    info.rpath.push(path);
                }
            }
            Some(LoadCommand::Id(name)) => info.id = Some(name),
            Some(LoadCommand::Platform(platform)) => platforms.push(platform),
            Some(LoadCommand::Uuid(uuid)) => info.uuid = Some(uuid),
            None => {}
        }
    }

    info.platforms = platforms.iter().map(|platform| platform.id).collect();
    info.platform = format_platforms(platforms);
    Ok(info)
}

// Whether an image is built for macOS, the way dyld combines its platform
// load commands (PlatformAndVersions::zip): the first one sets the
// platform, which a macOS and a Mac Catalyst pair turns into a zippered
// image loadable in both, and any other platform after it is ignored.  An
// image without any is taken as a macOS one on the Intel and arm64
// architectures (UnsafeHeader::forEachPlatformLoadCommand).
fn built_for_macos(info: &MachOInfo) -> bool {
    match info.platforms.first() {
        None => matches!(
            info.cputype,
            CPU_TYPE_X86_64 | CPU_TYPE_X86 | CPU_TYPE_ARM64
        ),
        Some(&PLATFORM_MACOS) => true,
        Some(&PLATFORM_MACCATALYST) => info.platforms.contains(&PLATFORM_MACOS),
        Some(_) => false,
    }
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
    id: Platform,
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

// A load command string (a dependency, the install name, or a run-path
// entry).  An offset outside the command, or a string without its
// terminator, makes the image invalid (stringOverflow in dyld).  dyld takes
// any byte sequence as a path, so one that is not valid UTF-8 is kept with
// the invalid sequences replaced, rather than dropping the dependency.
fn parse_string<Mach: MachHeader>(
    endian: Mach::Endian,
    command: &LoadCommandData<Mach::Endian>,
    string: LcStr<Mach::Endian>,
) -> Result<String, String> {
    command
        .string(endian, string)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .map_err(|_| "load command string extends beyond the end of the command".to_string())
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

// Parse the load commands rldd reports.  A command too small for its
// structure makes the image invalid, like dyld does for the sizes it checks.
fn parse_load_command<Mach: MachHeader>(
    endian: Mach::Endian,
    command: LoadCommandData<Mach::Endian>,
) -> Result<Option<LoadCommand>, String> {
    let variant = command
        .variant()
        .map_err(|_| "malformed load command".to_string())?;
    Ok(match variant {
        LoadCommandVariant::Dylib(x) => {
            if command.cmd() == LC_LAZY_LOAD_DYLIB {
                return Ok(None);
            }
            let name = parse_string::<Mach>(endian, &command, x.dylib.name)?;
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
        LoadCommandVariant::IdDylib(x) => Some(LoadCommand::Id(parse_string::<Mach>(
            endian,
            &command,
            x.dylib.name,
        )?)),
        LoadCommandVariant::Rpath(x) => Some(LoadCommand::Rpath(parse_string::<Mach>(
            endian, &command, x.path,
        )?)),
        LoadCommandVariant::BuildVersion(x, _) => Some(LoadCommand::Platform(PlatformInfo {
            id: x.platform.get(endian),
            name: platform_name(x.platform.get(endian)),
            min: format_os_version(x.minos.get(endian)),
            sdk: format_os_version(x.sdk.get(endian)),
        })),
        LoadCommandVariant::VersionMin(x) => {
            // dyld takes the x86 iOS, tvOS and watchOS ones as the old
            // simulator binaries, which makes no difference to the macOS
            // check.
            let (id, platform) = match command.cmd() {
                LC_VERSION_MIN_MACOSX => (PLATFORM_MACOS, "macOS"),
                LC_VERSION_MIN_IPHONEOS => (PLATFORM_IOS, "iOS"),
                LC_VERSION_MIN_TVOS => (PLATFORM_TVOS, "tvOS"),
                LC_VERSION_MIN_WATCHOS => (PLATFORM_WATCHOS, "watchOS"),
                _ => (Platform(0), "unknown"),
            };
            Some(LoadCommand::Platform(PlatformInfo {
                id,
                name: platform.to_string(),
                min: format_os_version(x.version.get(endian)),
                sdk: format_os_version(x.sdk.get(endian)),
            }))
        }
        LoadCommandVariant::Uuid(x) => Some(LoadCommand::Uuid(format_uuid(&x.uuid))),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(fields: &[u32], big_endian: bool) -> Vec<u8> {
        fields
            .iter()
            .flat_map(|field| {
                if big_endian {
                    field.to_be_bytes()
                } else {
                    field.to_le_bytes()
                }
            })
            .collect()
    }

    // A thin 64-bit little endian Mach-O image with the CMDS load commands.
    fn macho(cputype: CpuType, cpusubtype: u32, filetype: FileType, cmds: &[Vec<u8>]) -> Vec<u8> {
        let sizeofcmds: usize = cmds.iter().map(Vec::len).sum();
        let mut image = words(
            &[
                MH_MAGIC_64,
                cputype.0,
                cpusubtype,
                filetype.0,
                cmds.len() as u32,
                sizeofcmds as u32,
                0,
                0,
            ],
            false,
        );
        cmds.iter().for_each(|cmd| image.extend_from_slice(cmd));
        image
    }

    // A load command with a string (a dylib name or a run-path entry) at the
    // end, padded to the 8 byte alignment.
    fn string_command(cmd: LoadCommandType, fields: &[u32], string: &str) -> Vec<u8> {
        let offset = 8 + 4 * (fields.len() as u32 + 1);
        let mut bytes = string.as_bytes().to_vec();
        bytes.push(0);
        bytes.resize(
            (offset as usize + bytes.len()).next_multiple_of(8) - offset as usize,
            0,
        );
        let mut command = words(&[cmd.0, offset + bytes.len() as u32, offset], false);
        command.extend(words(fields, false));
        command.extend(bytes);
        command
    }

    fn dylib_command(cmd: LoadCommandType, name: &str) -> Vec<u8> {
        string_command(cmd, &[2, 0x10000, 0x10000], name)
    }

    const PAGE: usize = 0x4000;

    // A universal file with the SLICES at page aligned offsets, recorded with
    // the 32 or 64-bit FAT header.
    fn fat(slices: &[(CpuType, u32, &[u8])], fat64: bool) -> Vec<u8> {
        let mut file = words(
            &[
                if fat64 { FAT_MAGIC_64 } else { FAT_MAGIC },
                slices.len() as u32,
            ],
            true,
        );
        for (i, (cputype, cpusubtype, image)) in slices.iter().enumerate() {
            let offset = PAGE * (i + 1);
            file.extend(words(&[cputype.0, *cpusubtype], true));
            if fat64 {
                file.extend((offset as u64).to_be_bytes());
                file.extend((image.len() as u64).to_be_bytes());
                file.extend(words(&[14, 0], true));
            } else {
                file.extend(words(&[offset as u32, image.len() as u32, 14], true));
            }
        }
        for (i, (_, _, image)) in slices.iter().enumerate() {
            file.resize(PAGE * (i + 1), 0);
            file.extend_from_slice(image);
        }
        file
    }

    fn parse(data: &[u8], arch: &Arch) -> Result<MachOInfo, String> {
        parse_object(data, Check::Input(arch), "/exe", "/loader")
    }

    fn dep_names(info: &MachOInfo) -> Vec<&str> {
        info.deps.iter().map(|dep| dep.name.as_str()).collect()
    }

    fn x86_64_dylib(cmds: &[Vec<u8>]) -> Vec<u8> {
        macho(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL.0, MH_DYLIB, cmds)
    }

    const ARM64E: u32 = CPU_SUBTYPE_PTRAUTH_ABI.0 | CPU_SUBTYPE_ARM64E.0;

    // A dylib linking against DEP.
    fn dylib(cputype: CpuType, cpusubtype: u32, dep: &str) -> Vec<u8> {
        macho(
            cputype,
            cpusubtype,
            MH_DYLIB,
            &[dylib_command(LC_LOAD_DYLIB, dep)],
        )
    }

    // A scratch directory for the files a test resolves, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir =
                std::env::temp_dir().join(format!("rldd-macho-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir.canonicalize().unwrap())
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }

        // Write the file NAME, returning its full path.
        fn write(&self, name: &str, data: &[u8]) -> String {
            let path = self.0.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, data).unwrap();
            self.path(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // A context resolving the whole tree, with the -a option, and with an
    // empty dyld cache so the host one is not loaded.
    fn context(arch: Option<&str>) -> MachOContext {
        let mut ctx = MachOContext {
            arch: Arch::new(arch).unwrap(),
            caches: Vec::new(),
            preload: Vec::new(),
            env: DyldEnv {
                library_path: Vec::new(),
                framework_path: Vec::new(),
                fallback_library_path: Vec::new(),
                fallback_framework_path: Vec::new(),
                image_suffix: None,
            },
            all: true,
            verbose: false,
            depth: 0,
            ignore_prefix: Vec::new(),
        };
        let archs = [
            Arch::process(CPU_TYPE_ARM64, CpuSubtype(0), MH_EXECUTE),
            Arch::process(CPU_TYPE_X86_64, CpuSubtype(3), MH_EXECUTE),
            Arch::process(CPU_TYPE_X86_64, CpuSubtype(8), MH_EXECUTE),
        ];
        for arch in archs.iter().chain([&ctx.arch]) {
            ctx.caches.push((arch.cache_names(), DyldCache::default()));
        }
        ctx
    }

    // The nodes below the root: the full path of a resolved one or the name
    // of one not found, its mode, and whether it repeats an earlier one.
    fn resolve(ctx: &mut MachOContext, input: &str) -> Vec<(String, DepMode, bool)> {
        let tree = resolve_binary(ctx, input).unwrap();
        tree.arena[1..]
            .iter()
            .map(|node| {
                let node = &node.val;
                let name = match &node.path {
                    Some(path) => pathutils::join(path, &node.name),
                    None => node.name.clone(),
                };
                (name, node.mode, node.found)
            })
            .collect()
    }

    fn node(name: &str, mode: DepMode) -> (String, DepMode, bool) {
        (name.to_string(), mode, false)
    }

    fn repeat(name: &str, mode: DepMode) -> (String, DepMode, bool) {
        (name.to_string(), mode, true)
    }

    fn load(path: &str) -> Vec<u8> {
        dylib_command(LC_LOAD_DYLIB, path)
    }

    fn x86_64_exe(cmds: &[Vec<u8>]) -> Vec<u8> {
        macho(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL.0, MH_EXECUTE, cmds)
    }

    #[test]
    fn rpath_searched_per_requester() {
        // libA and libB both link against @rpath/libX.dylib, and only libB
        // has a run-path entry leading to it.  libC has another libX on its
        // run-path, but the one already loaded has the @rpath install name.
        let dir = Scratch::new("rpath");
        let dep = load("@rpath/libX.dylib");
        let rpath = |dir: String| string_command(LC_RPATH, &[], &dir);
        let libx = dir.write(
            "x/libX.dylib",
            &x86_64_dylib(&[dylib_command(LC_ID_DYLIB, "@rpath/libX.dylib")]),
        );
        dir.write("y/libX.dylib", &x86_64_dylib(&[]));
        let lib_a = dir.write("a/libA.dylib", &x86_64_dylib(std::slice::from_ref(&dep)));
        let lib_b = dir.write(
            "b/libB.dylib",
            &x86_64_dylib(&[dep.clone(), rpath(dir.path("x"))]),
        );
        let lib_c = dir.write("c/libC.dylib", &x86_64_dylib(&[dep, rpath(dir.path("y"))]));
        let exe = dir.write(
            "bin/exe",
            &x86_64_exe(&[load(&lib_a), load(&lib_b), load(&lib_c)]),
        );
        let mut ctx = context(None);
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&lib_a, DepMode::Direct),
                node("@rpath/libX.dylib", DepMode::NotFound),
                node(&lib_b, DepMode::Direct),
                node(&libx, DepMode::DtRpath),
                node(&lib_c, DepMode::Direct),
                repeat(&libx, DepMode::DtRpath),
            ]
        );
    }

    #[test]
    fn fallback_path_image() {
        // The first dependency is only found on the fallback path, while the
        // second one with the same leaf name is found on its own path, and
        // is another image.
        let dir = Scratch::new("fallback");
        let fallback = dir.write("fb/libfoo.dylib", &x86_64_dylib(&[]));
        let local = dir.write("usr/local/lib/libfoo.dylib", &x86_64_dylib(&[]));
        let exe = dir.write(
            "bin/exe",
            &x86_64_exe(&[
                load(&dir.path("missing/libfoo.dylib")),
                load(&local),
                load(&dir.path("other/libfoo.dylib")),
            ]),
        );
        let mut ctx = context(None);
        ctx.env.fallback_library_path = search_path::from_string(dir.path("fb"), &[':']);
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&fallback, DepMode::LdFallbackLibraryPath),
                node(&local, DepMode::Direct),
                repeat(&fallback, DepMode::LdFallbackLibraryPath),
            ]
        );
    }

    #[test]
    fn library_path_image() {
        // Every dependency with the leaf name leads to the DYLD_LIBRARY_PATH
        // image first.
        let dir = Scratch::new("libpath");
        let lib = dir.write("lp/libz.dylib", &x86_64_dylib(&[]));
        let exe = dir.write(
            "bin/exe",
            &x86_64_exe(&[load("/a/libz.dylib"), load("/b/libz.dylib")]),
        );
        let mut ctx = context(None);
        ctx.env.library_path = search_path::from_string(dir.path("lp"), &[':']);
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&lib, DepMode::LdLibraryPath),
                repeat(&lib, DepMode::LdLibraryPath),
            ]
        );
    }

    #[test]
    fn dependency_file_type() {
        // A bundle or an executable on the recorded path is not linked
        // against, and the search continues.
        let dir = Scratch::new("filetype");
        let bundle = dir.write(
            "lib/libfoo.dylib",
            &macho(CPU_TYPE_X86_64, 3, MH_BUNDLE, &[]),
        );
        let exe_dep = dir.write("bin/tool", &x86_64_exe(&[]));
        let dylib = dir.write("fb/libfoo.dylib", &x86_64_dylib(&[]));
        let exe = dir.write("bin/exe", &x86_64_exe(&[load(&bundle), load(&exe_dep)]));
        let mut ctx = context(None);
        ctx.env.fallback_library_path = search_path::from_string(dir.path("fb"), &[':']);
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&dylib, DepMode::LdFallbackLibraryPath),
                node(&exe_dep, DepMode::NotFound),
            ]
        );
    }

    fn build_version(platform: Platform) -> Vec<u8> {
        let version = 14 << 16;
        words(
            &[LC_BUILD_VERSION.0, 24, platform.0, version, version, 0],
            false,
        )
    }

    #[test]
    fn macos_platform() {
        let info = |cputype, platforms: &[Platform]| MachOInfo {
            cputype,
            platforms: platforms.to_vec(),
            ..Default::default()
        };
        let (macos, catalyst, ios) = (PLATFORM_MACOS, PLATFORM_MACCATALYST, PLATFORM_IOS);
        for (image, expected) in [
            (info(CPU_TYPE_X86_64, &[]), true),
            (info(CPU_TYPE_ARM64, &[]), true),
            (info(CPU_TYPE_POWERPC, &[]), false),
            (info(CPU_TYPE_ARM64, &[macos]), true),
            (info(CPU_TYPE_ARM64, &[macos, ios]), true),
            (info(CPU_TYPE_ARM64, &[ios, macos]), false),
            (info(CPU_TYPE_ARM64, &[catalyst]), false),
            (info(CPU_TYPE_ARM64, &[catalyst, macos]), true),
            (info(CPU_TYPE_ARM64, &[catalyst, ios, macos]), true),
            (info(CPU_TYPE_ARM64, &[PLATFORM_DRIVERKIT]), false),
        ] {
            assert_eq!(built_for_macos(&image), expected, "{:?}", image.platforms);
        }
    }

    #[test]
    fn dependency_platform() {
        // A macOS executable does not load an iOS library, while it loads a
        // zippered one, and one without any platform.
        let dir = Scratch::new("platform");
        let ios = dir.write(
            "ios/libfoo.dylib",
            &x86_64_dylib(&[build_version(PLATFORM_IOS)]),
        );
        let zippered = dir.write(
            "fb/libfoo.dylib",
            &x86_64_dylib(&[
                build_version(PLATFORM_MACCATALYST),
                build_version(PLATFORM_MACOS),
            ]),
        );
        let plain = dir.write("lib/libbar.dylib", &x86_64_dylib(&[]));
        let exe = |platform: Option<Platform>| {
            let mut cmds: Vec<Vec<u8>> = platform.into_iter().map(build_version).collect();
            cmds.extend([load(&ios), load(&plain)]);
            x86_64_exe(&cmds)
        };
        let macos = dir.write("bin/macos", &exe(Some(PLATFORM_MACOS)));
        let implicit = dir.write("bin/implicit", &exe(None));
        let iphone = dir.write("bin/ios", &exe(Some(PLATFORM_IOS)));
        let mut ctx = context(None);
        ctx.env.fallback_library_path = search_path::from_string(dir.path("fb"), &[':']);
        for input in [macos, implicit] {
            assert_eq!(
                resolve(&mut ctx, &input),
                [
                    node(&zippered, DepMode::LdFallbackLibraryPath),
                    node(&plain, DepMode::Direct),
                ]
            );
        }
        // Only the macOS processes are checked.
        assert_eq!(
            resolve(&mut ctx, &iphone),
            [node(&ios, DepMode::Direct), node(&plain, DepMode::Direct)]
        );
    }

    #[test]
    fn inserted_library_dependencies() {
        // The dependency of an inserted library is loaded like any other,
        // and another file with its leaf name is another image.
        let dir = Scratch::new("preload");
        let dep = dir.write("lib/libdep.dylib", &x86_64_dylib(&[]));
        let other = dir.write("lib2/libdep.dylib", &x86_64_dylib(&[]));
        let inserted = dir.write("pre/libpre.dylib", &x86_64_dylib(&[load(&dep)]));
        let exe = dir.write("bin/exe", &x86_64_exe(&[load(&other), load(&inserted)]));
        let mut ctx = context(None);
        ctx.preload = insert_libraries(&inserted);
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&inserted, DepMode::Preload),
                node(&dep, DepMode::Direct),
                node(&other, DepMode::Direct),
                repeat(&inserted, DepMode::Preload),
            ]
        );
    }

    #[test]
    fn dependency_architecture() {
        let keys_off = Arch::process(CPU_TYPE_ARM64, CpuSubtype(0), MH_EXECUTE);
        let x86_64 = Arch::process(CPU_TYPE_X86_64, CpuSubtype(3), MH_EXECUTE);
        let dependency = |data: &[u8], arch| {
            parse_object(data, Check::Dependency(arch), "/exe", "/loader")
                .map(|info| dep_names(&info).join(":"))
        };
        let x86_64_lib = dylib(CPU_TYPE_X86_64, 3, "/x86_64");
        let arm64_lib = dylib(CPU_TYPE_ARM64, 0, "/arm64");
        let arm64e_lib = dylib(CPU_TYPE_ARM64, ARM64E, "/arm64e");

        // A thin file of another architecture is rejected as a dependency,
        // while it is inspected as the input.
        assert!(dependency(&x86_64_lib, &keys_off).is_err());
        assert!(dependency(&arm64_lib, &x86_64).is_err());
        assert!(parse(&x86_64_lib, &Arch::new(None).unwrap()).is_ok());
        assert_eq!(dependency(&arm64_lib, &keys_off).unwrap(), "/arm64");

        // The slice of a universal file is the one the process grades best,
        // whatever the FAT header order.
        for fat64 in [false, true] {
            let file = fat(
                &[
                    (CPU_TYPE_X86_64, 3, &x86_64_lib),
                    (CPU_TYPE_ARM64, 0, &arm64_lib),
                    (CPU_TYPE_ARM64, ARM64E, &arm64e_lib),
                ],
                fat64,
            );
            assert_eq!(dependency(&file, &keys_off).unwrap(), "/arm64e");
            assert_eq!(dependency(&file, &x86_64).unwrap(), "/x86_64");
            let file = fat(&[(CPU_TYPE_X86_64, 3, &x86_64_lib)], fat64);
            assert!(dependency(&file, &keys_off).is_err());
        }

        // libtool leaves out the ABI version of the arm64e slice on the
        // 32-bit FAT header.
        let file = fat(
            &[
                (CPU_TYPE_ARM64, 0, &arm64_lib),
                (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E.0, &arm64e_lib),
            ],
            false,
        );
        assert_eq!(dependency(&file, &keys_off).unwrap(), "/arm64e");

        // A slice past the end of the file.
        let mut file = fat(&[(CPU_TYPE_ARM64, 0, &arm64_lib)], false);
        file.truncate(file.len() - 1);
        assert!(dependency(&file, &keys_off).is_err());
    }

    #[test]
    fn dependency_of_another_architecture() {
        // An arm64 executable linking against an Intel only library, with an
        // arm64 one on the fallback path.
        let dir = Scratch::new("arch");
        let intel = dir.write("usr/local/lib/libfoo.dylib", &x86_64_dylib(&[]));
        let arm64 = dir.write(
            "fallback/libfoo.dylib",
            &macho(CPU_TYPE_ARM64, 0, MH_DYLIB, &[]),
        );
        let exe = dir.write(
            "bin/exe",
            &macho(
                CPU_TYPE_ARM64,
                0,
                MH_EXECUTE,
                &[dylib_command(LC_LOAD_DYLIB, &intel)],
            ),
        );
        let mut ctx = context(None);
        assert_eq!(resolve(&mut ctx, &exe), [node(&intel, DepMode::NotFound)]);
        ctx.env.fallback_library_path = search_path::from_string(dir.path("fallback"), &[':']);
        assert_eq!(
            resolve(&mut ctx, &exe),
            [node(&arm64, DepMode::LdFallbackLibraryPath)]
        );
    }

    #[test]
    fn process_architecture_from_input() {
        // A universal library whose slices link against different paths,
        // and the executables of each architecture linking against it.
        let dir = Scratch::new("process");
        let libfoo = dir.write(
            "lib/libfoo.dylib",
            &fat(
                &[
                    (
                        CPU_TYPE_ARM64,
                        ARM64E,
                        &dylib(CPU_TYPE_ARM64, ARM64E, "/arm64e"),
                    ),
                    (CPU_TYPE_X86_64, 3, &dylib(CPU_TYPE_X86_64, 3, "/x86_64")),
                ],
                false,
            ),
        );
        let exe = |cputype, cpusubtype| {
            macho(
                cputype,
                cpusubtype,
                MH_EXECUTE,
                &[dylib_command(LC_LOAD_DYLIB, &libfoo)],
            )
        };
        let x86_64 = dir.write("bin/x86_64", &exe(CPU_TYPE_X86_64, 3));
        let arm64 = dir.write("bin/arm64", &exe(CPU_TYPE_ARM64, 0));
        let universal = dir.write(
            "bin/universal",
            &fat(
                &[
                    (CPU_TYPE_ARM64, 0, &exe(CPU_TYPE_ARM64, 0)),
                    (CPU_TYPE_X86_64, 3, &exe(CPU_TYPE_X86_64, 3)),
                ],
                false,
            ),
        );

        let tree = |dep| [node(&libfoo, DepMode::Direct), node(dep, DepMode::NotFound)];
        let mut ctx = context(None);
        assert_eq!(resolve(&mut ctx, &x86_64), tree("/x86_64"));
        assert_eq!(resolve(&mut ctx, &arm64), tree("/arm64e"));
        let mut ctx = context(Some("x86_64"));
        assert_eq!(resolve(&mut ctx, &universal), tree("/x86_64"));
        let mut ctx = context(Some("arm64"));
        assert_eq!(resolve(&mut ctx, &universal), tree("/arm64e"));
    }

    #[test]
    fn rpath_entries() {
        let arch = Arch::new(None).unwrap();
        let rpath = |path| string_command(LC_RPATH, &[], path);
        let image = x86_64_dylib(&[
            rpath("/does/not/exist"),
            rpath("@loader_path/../lib"),
            rpath("@executable_path/Frameworks/"),
            rpath("/does/not/exist"),
            rpath(""),
        ]);
        let info = parse(&image, &arch).unwrap();
        assert_eq!(
            info.rpath,
            ["/does/not/exist", "/loader/../lib", "/exe/Frameworks/"]
        );
    }

    #[test]
    fn framework_partial_paths() {
        for (path, partial) in [
            (
                "/System/Library/Frameworks/Foo.framework/Versions/A/Foo",
                Some("Foo.framework/Versions/A/Foo"),
            ),
            (
                "/Library/Frameworks/Foo.framework/Foo",
                Some("Foo.framework/Foo"),
            ),
            ("@rpath/Foo.framework/Foo", Some("Foo.framework/Foo")),
            ("Foo.framework/Foo", Some("Foo.framework/Foo")),
            // The last framework directory of a nested one.
            (
                "/F/Foo.framework/Versions/A/Frameworks/Bar.framework/Bar",
                Some("Bar.framework/Bar"),
            ),
            // The leaf name is not the framework name.
            ("/F/Foo.framework/Versions/A/Bar", None),
            ("/F/Foo.framework/Versions/A/Libraries/libfoo.dylib", None),
            ("/F/Foo.framework", None),
            ("/usr/lib/libz.dylib", None),
        ] {
            assert_eq!(framework_partial_path(path), partial, "{path}");
        }
    }

    #[test]
    fn insert_libraries_list() {
        assert_eq!(insert_libraries(""), Vec::<String>::new());
        assert_eq!(
            insert_libraries("/Library/Application Support/X/libx.dylib:/usr/lib/liby.dylib"),
            [
                "/Library/Application Support/X/libx.dylib",
                "/usr/lib/liby.dylib"
            ]
        );
        assert_eq!(insert_libraries("::a b::c:"), ["a b", "c"]);
    }

    #[test]
    fn malformed_load_commands() {
        let arch = Arch::new(None).unwrap();
        let lib_a = dylib_command(LC_LOAD_DYLIB, "/usr/lib/libA.dylib");
        let lib_b = dylib_command(LC_LOAD_WEAK_DYLIB, "/usr/lib/libB.dylib");

        let good = x86_64_dylib(&[lib_a.clone(), lib_b.clone()]);
        let info = parse(&good, &arch).unwrap();
        assert_eq!(
            dep_names(&info),
            ["/usr/lib/libA.dylib", "/usr/lib/libB.dylib"]
        );

        // A command smaller than the load command header.
        let short = x86_64_dylib(&[words(&[LC_LOAD_DYLIB.0, 4], false), lib_b.clone()]);
        assert!(parse(&short, &arch).is_err());

        // The load command table past the end of the file.
        let mut past_eof = good.clone();
        past_eof[20..24].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        assert!(parse(&past_eof, &arch).is_err());

        // More commands than the table holds.
        let mut too_many = good.clone();
        too_many[16..20].copy_from_slice(&3u32.to_le_bytes());
        assert!(parse(&too_many, &arch).is_err());

        // A command extending past the table.
        let mut too_large = lib_a.clone();
        too_large[4..8].copy_from_slice(&(lib_a.len() as u32 + 8).to_le_bytes());
        assert!(parse(&x86_64_dylib(&[too_large]), &arch).is_err());

        // A name offset past the command size.
        let mut bad_offset = lib_a.clone();
        bad_offset[8..12].copy_from_slice(&4000u32.to_le_bytes());
        assert!(parse(&x86_64_dylib(&[bad_offset, lib_b.clone()]), &arch).is_err());

        // A name without its terminator.
        let mut unterminated = lib_a.clone();
        let len = unterminated.len();
        unterminated[24..len].fill(b'a');
        assert!(parse(&x86_64_dylib(&[unterminated, lib_b.clone()]), &arch).is_err());

        // A dylib command too small for its structure.
        let small = words(&[LC_LOAD_DYLIB.0, 16, 24, 0], false);
        assert!(parse(&x86_64_dylib(&[small, lib_b.clone()]), &arch).is_err());

        // A name that is not valid UTF-8 is still a dependency.
        let mut latin1 = dylib_command(LC_LOAD_DYLIB, "/usr/lib/libX.dylib");
        latin1[36] = 0xe9;
        let info = parse(&x86_64_dylib(&[latin1, lib_b]), &arch).unwrap();
        assert_eq!(
            dep_names(&info),
            ["/usr/lib/lib\u{fffd}.dylib", "/usr/lib/libB.dylib"]
        );
    }

    #[test]
    fn nested_fat_rejected() {
        let arch = Arch::new(None).unwrap();
        for fat64 in [false, true] {
            // A single slice covering the whole file, which is then the FAT
            // header again.
            let (magic, header_size) = if fat64 {
                (FAT_MAGIC_64, 8 + 32)
            } else {
                (FAT_MAGIC, 8 + 20)
            };
            let mut file = words(&[magic, 1, CPU_TYPE_X86_64.0, 3], true);
            if fat64 {
                file.extend(0u64.to_be_bytes());
                file.extend((header_size as u64).to_be_bytes());
                file.extend(words(&[0, 0], true));
            } else {
                file.extend(words(&[0, header_size, 0], true));
            }
            assert_eq!(file.len(), header_size as usize);
            assert!(parse(&file, &arch).is_err());

            // A universal file wrapped as the slice of another one.
            let image = macho(
                CPU_TYPE_X86_64,
                CPU_SUBTYPE_X86_64_ALL.0,
                MH_DYLIB,
                &[dylib_command(LC_LOAD_DYLIB, "/usr/lib/libA.dylib")],
            );
            let inner = fat(&[(CPU_TYPE_X86_64, 3, &image)], fat64);
            let outer = fat(&[(CPU_TYPE_X86_64, 3, &inner)], fat64);
            assert!(parse(&inner, &arch).is_ok());
            assert!(parse(&outer, &arch).is_err());
        }
    }

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
