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
    // The LC_RPATH entries as recorded, expanded when the dependencies are
    // loaded (see expand_rpaths).  Like dyld, an entry is kept whether or not
    // its directory exists on the root filesystem, since the candidates it
    // leads to may still be found in the dyld cache or below the OS cryptex
    // mount.
    rpath: Vec<String>,
    // Whether the image has a __RESTRICT,__restrict section.
    restricted: bool,
    // The LC_DYLD_ENVIRONMENT variables (KEY=VALUE).
    dyld_environment: Vec<String>,
    deps: DepsVec,
    // The LC_ID_DYLIB install name.
    id: Option<String>,
    // The LC_BUILD_VERSION/LC_VERSION_MIN_* information, and the platforms
    // along with their SDK versions in the load command order.
    platform: Option<String>,
    platforms: Vec<(Platform, Version)>,
    // The LC_UUID value.
    uuid: Option<String>,
    // The Mach-O header architecture and file type.
    cputype: CpuType,
    cpusubtype: CpuSubtype,
    filetype: FileType,
}

// The DYLD_* environment variables, mimicked with command line options like
// the ELF backend does for LD_LIBRARY_PATH, as given.
#[derive(Default, Clone)]
struct DyldVars {
    library_path: String,
    framework_path: String,
    fallback_library_path: String,
    fallback_framework_path: String,
    insert_libraries: String,
    image_suffix: Option<String>,
}

impl DyldVars {
    // Add the main executable LC_DYLD_ENVIRONMENT variables VARS after the
    // environment ones, the way dyld does (PathOverrides::addEnvVar): the
    // search path lists, the inserted libraries, and the image suffix, a
    // variable already set being extended with a colon.  An entry starting
    // with @executable_path/ or @loader_path/ is below the main executable
    // directory, and one starting with @ is dropped where dyld does not allow
    // the @ paths.  dyld4 honors them unless AMFI forbids it
    // (allowEmbeddedVars), and dyld2 honored the path lists of any process,
    // restricted or not, so they are always taken.
    fn add_embedded(&mut self, vars: &[String], executable_path: &str, security: Security) {
        let append = |var: &mut String, value: &str| {
            if !var.is_empty() {
                var.push(':');
            }
            var.push_str(value);
        };
        for var in vars {
            let Some((key, value)) = var.split_once('=') else {
                continue;
            };
            let value = if value.contains('@') {
                value
                    .split(':')
                    .filter(|entry| security.allow_at_paths() || !entry.starts_with('@'))
                    .map(|entry| {
                        match entry
                            .strip_prefix("@executable_path/")
                            .or_else(|| entry.strip_prefix("@loader_path/"))
                        {
                            Some(rest) => format!("{executable_path}/{rest}"),
                            None => entry.to_string(),
                        }
                    })
                    .collect::<Vec<String>>()
                    .join(":")
            } else {
                value.to_string()
            };
            match key {
                "DYLD_LIBRARY_PATH" => append(&mut self.library_path, &value),
                "DYLD_FRAMEWORK_PATH" => append(&mut self.framework_path, &value),
                "DYLD_FALLBACK_LIBRARY_PATH" => append(&mut self.fallback_library_path, &value),
                "DYLD_FALLBACK_FRAMEWORK_PATH" => append(&mut self.fallback_framework_path, &value),
                "DYLD_INSERT_LIBRARIES" => append(&mut self.insert_libraries, &value),
                "DYLD_IMAGE_SUFFIX" => {
                    append(self.image_suffix.get_or_insert_with(String::new), &value)
                }
                _ => {}
            }
        }
    }
}

// The DYLD_* environment a process runs with: the search path lists, the
// inserted libraries, and the image suffix.
struct DyldEnv {
    library_path: search_path::SearchPathVec,
    framework_path: search_path::SearchPathVec,
    fallback_library_path: search_path::SearchPathVec,
    fallback_framework_path: search_path::SearchPathVec,
    insert_libraries: Vec<String>,
    image_suffix: Option<String>,
}

impl DyldEnv {
    fn new(vars: &DyldVars) -> DyldEnv {
        let list = |list: &str| search_path::from_string(list, &[':']);
        DyldEnv {
            library_path: list(&vars.library_path),
            framework_path: list(&vars.framework_path),
            fallback_library_path: list(&vars.fallback_library_path),
            fallback_framework_path: list(&vars.fallback_framework_path),
            insert_libraries: insert_libraries(&vars.insert_libraries),
            image_suffix: vars.image_suffix.clone(),
        }
    }
}

// The dyld restrictions on the process running the input.  dyld4 leaves
// the decision to AMFI (ProcessConfig::Security, amfi_check_dyld_policy_self),
// handing it whether the main executable has a __RESTRICT,__restrict section,
// while the rules that can be taken from the file are the ones dyld applied
// itself before (configureProcessRestrictions in dyld2): a setuid or setgid
// program, or one with that section, is restricted.  A restricted process
// ignores the DYLD_* variables (allowEnvVarsPath), does not expand
// @executable_path and the @loader_path of the main executable LC_RPATH
// entries (allowAtPaths), and falls back to the restricted default
// directories (allowClassicFallbackPaths).
#[derive(Clone, Copy, Default)]
struct Security {
    // Why the process is restricted.
    restricted: Option<&'static str>,
}

impl Security {
    fn new(filename: &Path, from_cache: bool, omf: &MachOInfo) -> Security {
        use std::os::unix::fs::PermissionsExt;
        const SETUGID: u32 = 0o6000;
        let setugid = !from_cache
            && std::fs::metadata(filename)
                .is_ok_and(|meta| meta.permissions().mode() & SETUGID != 0);
        let restricted = if setugid {
            Some("setuid or setgid program")
        } else if omf.restricted {
            Some("__RESTRICT,__restrict section")
        } else {
            None
        };
        Security { restricted }
    }

    fn allow_env_vars_path(&self) -> bool {
        self.restricted.is_none()
    }

    fn allow_at_paths(&self) -> bool {
        self.restricted.is_none()
    }

    fn allow_classic_fallback_paths(&self) -> bool {
        self.restricted.is_none()
    }
}

// The resolution context: the architecture selecting the input slice (the
// one requested or the host one), the dyld shared caches, and the command
// line settings.
pub struct MachOContext {
    arch: Arch,
    // The dyld shared caches loaded so far, along with their names, since
    // each input selects the cache flavor of its architecture.
    caches: Vec<(&'static [&'static str], DyldCache)>,
    vars: DyldVars,
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
fn cache_image(cache: &DyldCache, name: &str) -> Option<MachOInfo> {
    match cache.image(name)? {
        Some((data, offset)) => parse_thin(data, offset, Check::Cache).ok(),
        None => Some(MachOInfo::default()),
    }
}

pub fn create_context(opts: &crate::Options) -> Result<MachOContext, String> {
    let arch = Arch::new(opts.arch.as_deref())?;
    Ok(MachOContext {
        arch,
        caches: Vec::new(),
        vars: DyldVars {
            library_path: opts.library_path.clone(),
            framework_path: opts.framework_path.clone(),
            fallback_library_path: opts.fallback_library_path.clone(),
            fallback_framework_path: opts.fallback_framework_path.clone(),
            insert_libraries: opts.preload.clone(),
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
            let omf = open_macho_file(&filename, Check::Input(&ctx.arch))?;
            (filename, omf, false)
        }
        Err(err) => {
            let cache = ctx.load_cache(ctx.arch.cache_names());
            match cache_image(&ctx.caches[cache].1, arg) {
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

    // A restricted process does not take the DYLD_* variables, while the
    // main executable may set its own.
    let security = Security::new(&filename, from_cache, &omf);
    let mut vars = if security.allow_env_vars_path() {
        ctx.vars.clone()
    } else {
        DyldVars::default()
    };
    vars.add_embedded(&omf.dyld_environment, &executable_path, security);
    let env = DyldEnv::new(&vars);
    let main_rpath = expand_rpaths(
        &omf.rpath,
        &executable_path,
        &executable_path,
        security,
        true,
    );

    if ctx.verbose {
        print_object_information(&arch, cache, &env, security, &filename, &omf, &main_rpath);
    }

    let platform = ImagePlatform::new(&omf);
    let config = Config {
        arch: &arch,
        macos: omf.filetype == MH_EXECUTE
            && matches!(platform, ImagePlatform::Single(PLATFORM_MACOS, _)),
        platform: platform.platform(),
        security,
        cache,
        executable_path: &executable_path,
        env: &env,
        all: ctx.all,
        depth: ctx.depth,
        ignore_prefix: &ctx.ignore_prefix,
    };

    let mut tree = Tree::new();
    let path = filename.to_string_lossy().into_owned();
    let cache_image = cache.image_id(&path).filter(|_| from_cache);
    let root = tree.add_image(
        DepNode::new(
            Some(executable_path.clone()),
            pathutils::get_name(&filename),
            DepMode::Executable,
        ),
        None,
        path,
        omf,
        cache_image,
        executable_path.clone(),
    );

    // Like dyld, the inserted libraries are loaded first
    // (RuntimeState::loadInsertedLibraries), a duplicated one only once,
    // then the main executable dependencies along with theirs, and at last
    // the dependencies of each inserted library, whose run-path stack is the
    // main executable one.
    // dyld does not search the default fallback directories for them.
    let requester = Requester {
        place: tree.images[root].place,
        loader_path: &executable_path,
        rpaths: &[],
        default_fallbacks: false,
    };
    let mut inserted = Vec::new();
    for pload in &env.insert_libraries {
        let dep = MachODep {
            name: pload.clone(),
            attrs: Vec::new(),
            version: None,
        };
        if let Some(image) = resolve_dependency(&config, &requester, &dep, &mut tree, true) {
            if image != root && !inserted.contains(&image) {
                inserted.push(image);
            }
        }
    }
    load_dependents(&config, &mut tree, root, &[]);
    for image in inserted {
        load_dependents(&config, &mut tree, image, &main_rpath);
    }

    Ok(tree.deptree)
}

// Load the dependencies of IMAGE the way dyld does
// (JustInTimeLoader::loadDependents): each one is looked up first, and only
// then are the dependencies of the images they lead to loaded, in order.
// So an image a later sibling names is loaded before the dependencies of an
// earlier one, which then match it.  The dependencies of an image are
// loaded once, by the first requester reaching it after it was loaded
// (which may only name it again), with the run-path stack of that
// requester: RPATHS, preceded by the image own LC_RPATH entries.
fn load_dependents(config: &Config, tree: &mut Tree, image: usize, rpaths: &[String]) {
    let Some(pending) = tree.images[image].pending.take() else {
        return;
    };
    let place = tree.images[image].place;
    // Stop descending once the depth limit is reached.
    if config.depth != 0 && place.level >= config.depth {
        return;
    }
    let mut stack = expand_rpaths(
        &pending.rpath,
        config.executable_path,
        &pending.loader_path,
        config.security,
        place.level == 0,
    );
    for rpath in rpaths {
        if !stack.contains(rpath) {
            stack.push(rpath.clone());
        }
    }
    let requester = Requester {
        place,
        loader_path: &pending.loader_path,
        rpaths: &stack,
        default_fallbacks: pending.pre_2022,
    };
    let loaded: Vec<usize> = pending
        .deps
        .iter()
        .filter_map(|dep| resolve_dependency(config, &requester, dep, tree, false))
        .collect();
    for dep in loaded {
        load_dependents(config, tree, dep, &stack);
    }
}

// The node of an image on the tree, along with its level below the root.
#[derive(Clone, Copy)]
struct Place {
    node: usize,
    level: usize,
}

// The image looking a dependency up: its place on the tree, its directory
// (the @loader_path), its run-path stack, and whether dyld searches the
// default fallback directories for it (requestorNeedsFallbacks, set for a
// pre-2022 image).
struct Requester<'a> {
    place: Place,
    loader_path: &'a str,
    rpaths: &'a [String],
    default_fallbacks: bool,
}

// The dependencies of an image, until they are loaded, with the image
// run-path entries and directory (their @loader_path), and whether it was
// built with a pre-2022 SDK.
struct Pending {
    deps: DepsVec,
    rpath: Vec<String>,
    loader_path: String,
    pre_2022: bool,
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
    place: Place,
    pending: Option<Pending>,
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

    // Add the node of the image ELC loaded from PATH, below the REQUESTER (or
    // as the root), returning the image index.  Its dependencies are loaded
    // later, from LOADER_PATH.
    fn add_image(
        &mut self,
        node: DepNode,
        requester: Option<Place>,
        path: String,
        elc: MachOInfo,
        cache_image: Option<(usize, u64)>,
        loader_path: String,
    ) -> usize {
        let pre_2022 = pre_2022(&elc);
        // Only a dylib is also matched by its install name.
        let install_name = elc.id.filter(|_| elc.filetype == MH_DYLIB);
        let place = match requester {
            Some(requester) => Place {
                node: self.deptree.addnode(node.clone(), requester.node),
                level: requester.level + 1,
            },
            None => Place {
                node: self.deptree.addroot(node.clone()),
                level: 0,
            },
        };
        self.images.push(Image {
            path,
            install_name,
            cache_image,
            node,
            place,
            pending: Some(Pending {
                pre_2022,
                deps: elc.deps,
                rpath: elc.rpath,
                loader_path,
            }),
        });
        self.images.len() - 1
    }

    // The image loaded from PATH, or whose install name is PATH.
    fn image(&self, path: &str) -> Option<usize> {
        self.find(|image| image.path == path || image.install_name.as_deref() == Some(path))
    }

    // The image loaded from the file at the real PATH, which dyld matches by
    // the file identity instead.
    fn file_image(&self, path: &str) -> Option<usize> {
        self.find(|image| image.cache_image.is_none() && image.path == path)
    }

    // The image loaded from the dyld cache image ID.
    fn cache_image(&self, id: Option<(usize, u64)>) -> Option<usize> {
        id.and_then(|id| self.find(|image| image.cache_image == Some(id)))
    }

    fn find(&self, matches: impl Fn(&Image) -> bool) -> Option<usize> {
        self.images.iter().position(matches)
    }
}

// The verbose object information: the object metadata from the load
// commands along with the search path lists used for the resolution.
fn print_object_information(
    arch: &Arch,
    cache: &DyldCache,
    env: &DyldEnv,
    security: Security,
    filename: &Path,
    omf: &MachOInfo,
    rpath: &[String],
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
    if let Some(reason) = security.restricted {
        lines.push(format!(
            "  restricted: {reason} (the DYLD_* options and @executable_path are ignored)"
        ));
    }
    if !omf.dyld_environment.is_empty() {
        lines.push(format!(
            "  dyld environment: {}",
            omf.dyld_environment.join(" ")
        ));
    }
    lines.push(format!(
        "  rpath: {}",
        search_path::format_entries(rpath.iter().map(String::as_str))
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
    // The process platform, the one of the input.
    platform: Option<Platform>,
    security: Security,
    cache: &'a DyldCache,
    executable_path: &'a str,
    // The DYLD_* environment of the process.
    env: &'a DyldEnv,
    all: bool,
    // Limit the dependency tree to DEPTH levels, mimicking dylibtree, with
    // 0 meaning no limit.
    depth: usize,
    // Prune dependencies whose load path starts with any of the prefixes,
    // mimicking dylibtree.
    ignore_prefix: &'a [String],
}

// Look the dependency DEP of the REQUESTER image up, adding its node to the
// tree, and return the image it leads to, either a new one or one already
// loaded, or None when it is not found (or skipped).
fn resolve_dependency(
    config: &Config,
    requester: &Requester,
    dep: &MachODep,
    tree: &mut Tree,
    preload: bool,
) -> Option<usize> {
    // dyld does not expand @loader_path in DYLD_INSERT_LIBRARIES, nor
    // @executable_path in a restricted process.
    let dependency = expand_at_path(
        &dep.name,
        config
            .security
            .allow_at_paths()
            .then_some(config.executable_path),
        (!preload).then_some(requester.loader_path),
    );

    if pathutils::has_prefix(&dependency, config.ignore_prefix) {
        return None;
    }

    // To avoid circular dependencies, check if the dependency names an image
    // already loaded.  An @rpath load path only names an image with that
    // install name (dyld checks it first, before expanding the run-path
    // list), and its expansions are checked like any other candidate.
    let found = tree.image(&dependency);
    if let Some(image) = check_already_resolved(config, found, dep, tree, requester.place) {
        return Some(image);
    }

    find_dependency(config, requester, &dependency, dep, tree, preload)
}

// Check if the dependency names the image FOUND already loaded, adding an
// already found node when the -a option is used, and return it.
fn check_already_resolved(
    config: &Config,
    found: Option<usize>,
    dep: &MachODep,
    tree: &mut Tree,
    requester: Place,
) -> Option<usize> {
    let image = found?;
    let entry = &tree.images[image].node;
    let node = DepNode::repeat_of(entry, entry.name.clone())
        .with_attrs(dep.attrs.clone())
        .with_version(dep.version.clone());
    tree.deptree.add_repeated(config.all, node, requester.node);
    Some(image)
}

// Resolve DEPENDENCY the way dyld_info/otool, the recorded load path is taken
// verbatim (with @executable_path, @loader_path, and @rpath expanded) and
// checked against the dyld cache and the filesystem, with the DYLD_*
// environment search paths applied in the dyld order.
// When found a node is added to the dependency tree, and the image it
// leads to (a new one or one already loaded) is returned.
fn find_dependency(
    config: &Config,
    requester: &Requester,
    dependency: &str,
    dep: &MachODep,
    tree: &mut Tree,
    preload: bool,
) -> Option<usize> {
    for (candidate, mode) in candidate_paths(config, requester, dependency, preload) {
        for candidate in suffix_variants(config.env.image_suffix.as_deref(), &candidate) {
            match resolve_path(config, &candidate, dep, mode, tree, requester.place) {
                ResolveResult::Loaded(image) => return Some(image),
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
            searched_locations(config, requester, dependency, preload),
        )
        .with_attrs(dep.attrs.clone())
        .with_version(dep.version.clone()),
        requester.place.node,
    );
    None
}

// The candidate locations for a load path, in the order dyld searches them
// (PathOverrides::forEachPathVariant):
// 1. The DYLD_FRAMEWORK_PATH directories for a framework load path, or the
//    DYLD_LIBRARY_PATH directories (by leaf name) for any other one,
// 2. The load path itself (with @rpath expanded against the run-path list),
// 3. And at last the DYLD_FALLBACK_FRAMEWORK_PATH or DYLD_FALLBACK_LIBRARY_PATH
//    directories, or the default ones (see fallback_directories).
fn candidate_paths(
    config: &Config,
    requester: &Requester,
    dependency: &str,
    preload: bool,
) -> Vec<(String, DepMode)> {
    let rpaths = requester.rpaths;
    let mut candidates = Vec::new();

    // Like the fallback lists, the framework and library lists are mutually
    // exclusive: a framework is not looked up in the DYLD_LIBRARY_PATH
    // directories.
    let partial = framework_partial_path(dependency, config.env.image_suffix.as_deref());
    let leaf = pathutils::get_name(&Path::new(dependency));
    if let Some(partial) = partial {
        for dir in &config.env.framework_path {
            candidates.push((format!("{}/{partial}", dir.path), DepMode::LdFrameworkPath));
        }
    } else {
        for dir in &config.env.library_path {
            candidates.push((format!("{}/{leaf}", dir.path), DepMode::LdLibraryPath));
        }
    }

    let mode = if preload {
        DepMode::Preload
    } else {
        DepMode::Direct
    };
    let rpath = dependency.starts_with("@rpath/");
    if rpath && !preload {
        for rpath in rpaths {
            candidates.push((expand_rpath(dependency, rpath), DepMode::DtRpath));
        }
    } else if rpath || !dependency.starts_with('@') {
        // dyld does not expand @rpath in DYLD_INSERT_LIBRARIES, and takes the
        // load path as is, which only an image with that install name
        // matches.  Otherwise it never tries a load path still starting with
        // @, such as an @loader_path one of an inserted library
        // (Loader::forEachResolvedAtPathVar).
        candidates.push((dependency.to_string(), mode));
    }

    // Like dyld, the fallback framework and library lists are mutually
    // exclusive.  Frameworks use the former, plain dylibs the latter, and a
    // fallback candidate that is the load path itself is not tried again.
    let name = partial.unwrap_or(&leaf);
    for (dir, mode) in fallback_directories(config, partial.is_some(), requester.default_fallbacks)
    {
        let candidate = format!("{dir}/{name}");
        if candidate != dependency {
            candidates.push((candidate, mode));
        }
    }

    candidates
}

// The fallback directories: the DYLD_FALLBACK_FRAMEWORK_PATH ones for a
// FRAMEWORK, or the DYLD_FALLBACK_LIBRARY_PATH ones.  When the list is unset,
// dyld still searches default directories for the dependencies of an image
// built with a pre-2022 SDK (DEFAULTS), which depend on the process platform
// (PathOverrides::forEachDylibFallback and forEachFrameworkFallback): on
// macOS /usr/local/lib and /usr/lib, or /Library/Frameworks and
// /System/Library/Frameworks, only the last one for a restricted process
// (FallbackPathMode::restricted).
fn fallback_directories(
    config: &Config,
    framework: bool,
    defaults: bool,
) -> Vec<(String, DepMode)> {
    let (list, mode) = if framework {
        (
            &config.env.fallback_framework_path,
            DepMode::LdFallbackFrameworkPath,
        )
    } else {
        (
            &config.env.fallback_library_path,
            DepMode::LdFallbackLibraryPath,
        )
    };
    if !list.is_empty() {
        return list.iter().map(|dir| (dir.path.clone(), mode)).collect();
    }
    if !defaults {
        return Vec::new();
    }
    let classic = config.security.allow_classic_fallback_paths();
    let dirs: &[&str] = match (config.platform, framework) {
        (None | Some(PLATFORM_DRIVERKIT), _) => &[],
        (Some(PLATFORM_MACOS), false) if classic => &["/usr/local/lib", "/usr/lib"],
        (Some(PLATFORM_MACOS), false) => &["/usr/lib"],
        (Some(PLATFORM_MACOS), true) if classic => {
            &["/Library/Frameworks", "/System/Library/Frameworks"]
        }
        (Some(_), true) => &["/System/Library/Frameworks"],
        (
            Some(
                PLATFORM_IOS | PLATFORM_WATCHOS | PLATFORM_TVOS | PLATFORM_BRIDGEOS
                | PLATFORM_VISIONOS,
            ),
            false,
        ) => &["/usr/local/lib", "/usr/lib"],
        (
            Some(
                PLATFORM_IOSSIMULATOR
                | PLATFORM_TVOSSIMULATOR
                | PLATFORM_WATCHOSSIMULATOR
                | PLATFORM_VISIONOSSIMULATOR
                | PLATFORM_MACCATALYST,
            ),
            false,
        ) => &["/usr/local/lib"],
        (Some(_), false) => &[],
    };
    dirs.iter()
        .map(|dir| (dir.to_string(), DepMode::SystemDirs))
        .collect()
}

// The @rpath load path DEPENDENCY with the run-path entry RPATH in place of
// its leading @rpath, without a second slash after an entry ending with one
// (Utils::concatenatePaths).
fn expand_rpath(dependency: &str, rpath: &str) -> String {
    let tail = dependency.strip_prefix("@rpath").unwrap_or(dependency);
    format!("{}{tail}", rpath.strip_suffix('/').unwrap_or(rpath))
}

// The rest of PATH when it starts with the TOKEN component (@rpath,
// @executable_path, or @loader_path), which dyld only expands at the start.
fn at_path<'a>(path: &'a str, token: &str) -> Option<&'a str> {
    path.strip_prefix(token)
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
}

// A load path or run-path entry with its leading @executable_path or
// @loader_path expanded the way dyld does (Loader::forEachResolvedAtPathVar).
// The main executable directory being a real path, dyld drops the leading
// ../ components of an @executable_path one against it
// (expandAndNormalizeAtExecutablePath), while @loader_path is replaced as is.
// A path whose token dyld does not expand is left as is: EXECUTABLE_PATH is
// None in a restricted process (Loader::expandAtExecutablePath), and
// LOADER_PATH for an inserted library (Loader::expandAtLoaderPath).
fn expand_at_path(path: &str, executable_path: Option<&str>, loader_path: Option<&str>) -> String {
    if let (Some(mut tail), Some(executable_path)) =
        (at_path(path, "@executable_path"), executable_path)
    {
        if tail.is_empty() {
            return format!("{executable_path}/");
        }
        let mut dir = executable_path;
        while let Some(rest) = tail.strip_prefix("/..") {
            match dir.rfind('/') {
                Some(slash) if slash > 0 => {
                    dir = &dir[..slash];
                    tail = rest;
                }
                _ => break,
            }
        }
        return format!("{dir}{tail}");
    }
    match (at_path(path, "@loader_path"), loader_path) {
        (Some(tail), Some(loader_path)) => format!("{loader_path}{tail}"),
        _ => path.to_string(),
    }
}

// The LC_RPATH entries RPATHS of an image, expanded the way dyld does
// (Loader::forEachResolvedAtPathVar): a leading @loader_path is the image
// directory LOADER_PATH, and @executable_path the main executable one.  A
// restricted process neither expands @executable_path nor the @loader_path
// of the MAIN executable entries, and only takes the absolute entries, a
// relative one being taken where dyld allows the @ paths.
fn expand_rpaths(
    rpaths: &[String],
    executable_path: &str,
    loader_path: &str,
    security: Security,
    main: bool,
) -> Vec<String> {
    let allow = security.allow_at_paths();
    let mut expanded: Vec<String> = Vec::new();
    for rpath in rpaths {
        let rpath = expand_at_path(
            rpath,
            allow.then_some(executable_path),
            (allow || !main).then_some(loader_path),
        );
        if (allow || rpath.starts_with('/')) && !expanded.contains(&rpath) {
            expanded.push(rpath);
        }
    }
    expanded
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
// getFrameworkPartialPath check used for the framework search paths.  With
// an image SUFFIX, a leaf with the suffix appended to the framework name
// (the install name of some debug frameworks) also matches, the suffix
// being compared whole even when it is a list.
fn framework_partial_path<'a>(path: &'a str, suffix: Option<&str>) -> Option<&'a str> {
    let idx = path.rfind(".framework/")?;
    let start = path[..idx].rfind('/').map(|i| i + 1).unwrap_or(0);
    let leaf = path.rsplit('/').next()?;
    let name = &path[start..idx];
    let matches =
        leaf == name || suffix.is_some_and(|suffix| leaf.strip_prefix(name) == Some(suffix));
    matches.then(|| &path[start..])
}

// The DYLD_IMAGE_SUFFIX variants of a candidate path, the way dyld tries
// them (PathOverrides::forEachImageSuffix): the path with each suffix of the
// colon separated list first, inserted before the last dot of the leaf name
// or appended when it has none (addSuffix), and then the plain one.
fn suffix_variants(suffixes: Option<&str>, path: &str) -> Vec<String> {
    let mut variants = Vec::new();
    if let Some(suffixes) = suffixes {
        let leaf = path.rfind('/').map_or(0, |idx| idx + 1);
        for suffix in suffixes.split(':') {
            variants.push(match path[leaf..].rfind('.') {
                Some(dot) => {
                    let (stem, extension) = path.split_at(leaf + dot);
                    format!("{stem}{suffix}{extension}")
                }
                None => format!("{path}{suffix}"),
            });
        }
    }
    variants.push(path.to_string());
    variants
}

// The locations searched for a not found dependency, printed in verbose mode.
fn searched_locations(
    config: &Config,
    requester: &Requester,
    dependency: &str,
    preload: bool,
) -> Vec<String> {
    let mut searched = Vec::new();
    if dependency.starts_with("@rpath/") && !preload && requester.rpaths.is_empty() {
        searched.push(format!("{dependency} (empty run-path list)"));
    }
    for (candidate, _) in candidate_paths(config, requester, dependency, preload) {
        for variant in suffix_variants(config.env.image_suffix.as_deref(), &candidate) {
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
    // The image the candidate leads to, either loaded now and added to the
    // dependency tree, or loaded already.
    Loaded(usize),
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
    requester: Place,
) -> ResolveResult {
    match resolve_cache(config, dependency, dep, tree, requester) {
        ResolveResult::Miss => {}
        result => return result,
    }

    // Then the filesystem, only for absolute paths.
    let path = Path::new(dependency);
    if !path.is_absolute() {
        return ResolveResult::Miss;
    }
    match resolve_file(config, path, dep, mode, tree, requester) {
        ResolveResult::Miss => {}
        result => return result,
    }
    if let Some(cryptex) = cryptex_path(path) {
        match resolve_file(config, &cryptex, dep, mode, tree, requester) {
            ResolveResult::Miss => {}
            result => return result,
        }
    }

    // dyld only retries a recorded load path through its realpath when it
    // does not start with @ (Loader::getLoader).
    if matches!(mode, DepMode::Direct | DepMode::Preload) && !dep.name.starts_with('@') {
        if let Some(real) = realpath_leaf(path).filter(|real| real != dependency) {
            return resolve_cache(config, &real, dep, tree, requester);
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
    requester: Place,
) -> ResolveResult {
    // Each candidate is checked against the images already loaded, by its
    // path and by the cache image an alias path leads to.
    let cache_image = config.cache.image_id(name);
    let found = tree.image(name).or_else(|| tree.cache_image(cache_image));
    if let Some(image) = check_already_resolved(config, found, dep, tree, requester) {
        return ResolveResult::Loaded(image);
    }
    let Some(elc) = self::cache_image(config.cache, name).filter(|elc| loads_platform(config, elc))
    else {
        return ResolveResult::Miss;
    };
    add_found(
        elc,
        Path::new(name),
        DepMode::LdCache,
        dep,
        tree,
        requester,
        cache_image,
    )
}

fn resolve_file(
    config: &Config,
    path: &Path,
    dep: &MachODep,
    mode: DepMode,
    tree: &mut Tree,
    requester: Place,
) -> ResolveResult {
    let found = tree.image(&path.to_string_lossy());
    if let Some(image) = check_already_resolved(config, found, dep, tree, requester) {
        return ResolveResult::Loaded(image);
    }
    // The canonicalization also checks the file existence, and gives the
    // path of an image already loaded through another path (dyld compares
    // the file identity).
    let Ok(path) = path.canonicalize() else {
        return ResolveResult::Miss;
    };
    let found = tree.file_image(&path.to_string_lossy());
    if let Some(image) = check_already_resolved(config, found, dep, tree, requester) {
        return ResolveResult::Loaded(image);
    }
    // dyld only links against a dylib: the dependencies and the inserted
    // libraries are loaded with the canBeDylib option alone, so a bundle or
    // an executable is refused (JustInTimeLoader::makeJustInTimeLoaderDisk)
    // and the search continues.
    let Some(elc) = open_macho_file(&path, Check::Dependency(config.arch))
        .ok()
        .filter(|elc| elc.filetype == MH_DYLIB && loads_platform(config, elc))
    else {
        return ResolveResult::Miss;
    };
    add_found(elc, &path, mode, dep, tree, requester, None)
}

// Whether the process platform loads the image ELC, the images of another
// platform being rejected like the other architectures (see Config::macos).
// A cache image whose header is outside the cache mappings is taken as is.
fn loads_platform(config: &Config, elc: &MachOInfo) -> bool {
    !config.macos || elc.cputype == CpuType(0) || built_for_macos(elc)
}

// Add the object ELC found at PATH (or at the CACHE_IMAGE of the dyld cache)
// to the dependency tree, below the REQUESTER.  Its directory is the
// @loader_path of its own dependencies.
fn add_found(
    elc: MachOInfo,
    path: &Path,
    mode: DepMode,
    dep: &MachODep,
    tree: &mut Tree,
    requester: Place,
    cache_image: Option<(usize, u64)>,
) -> ResolveResult {
    let dir = pathutils::get_path(&path);
    let image = tree.add_image(
        DepNode::new(dir.clone(), pathutils::get_name(&path), mode)
            .with_attrs(dep.attrs.clone())
            .with_version(dep.version.clone()),
        Some(requester),
        path.to_string_lossy().into_owned(),
        elc,
        cache_image,
        dir.unwrap_or_default(),
    );
    ResolveResult::Loaded(image)
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
) -> Result<MachOInfo, std::io::Error> {
    let mmap = pathutils::map_file(filename)?;
    parse_object(&mmap, check).map_err(Error::other)
}

// Parse a Mach-O file, either a thin image or a universal (FAT) file whose
// selected slice is then parsed.
fn parse_object(data: &[u8], check: Check) -> Result<MachOInfo, String> {
    match object::FileKind::parse(data).map_err(|_| "Failed to parse file".to_string())? {
        object::FileKind::MachOFat32 => {
            let fat = MachOFatFile32::parse(data)
                .map_err(|_| "Invalid FAT Mach-O 32 object".to_string())?;
            parse_macho_fat(data, fat.arches(), check)
        }
        object::FileKind::MachOFat64 => {
            let fat = MachOFatFile64::parse(data)
                .map_err(|_| "Invalid FAT Mach-O 64 object".to_string())?;
            parse_macho_fat(data, fat.arches(), check)
        }
        _ => parse_thin(data, 0, check),
    }
}

// Parse the thin Mach-O image at OFFSET: a file, the slice of a universal
// file, or an image of the dyld cache.  Like dyld (MachOFile::compatibleSlice
// only accepts a slice with the MH_MAGIC header) and lipo, a universal file
// is not accepted as a slice of another one, which would otherwise recurse
// without end on a slice covering the whole file.
fn parse_thin(data: &[u8], offset: u64, check: Check) -> Result<MachOInfo, String> {
    match object::FileKind::parse_at(data, offset)
        .map_err(|_| "Failed to parse file".to_string())?
    {
        object::FileKind::MachO32 => {
            let header = MachHeader32::parse(data, offset)
                .map_err(|_| "Invalid Mach-O 32 object".to_string())?;
            parse_macho(header, data, offset, check)
        }
        object::FileKind::MachO64 => {
            let header = MachHeader64::parse(data, offset)
                .map_err(|_| "Invalid Mach-O 64 object".to_string())?;
            parse_macho(header, data, offset, check)
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
    parse_thin(slices[idx], 0, check)
}

fn parse_macho<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    data: &[u8],
    offset: u64,
    check: Check,
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
                if !path.is_empty() && !info.rpath.contains(&path) {
                    info.rpath.push(path);
                }
            }
            Some(LoadCommand::Id(name)) => info.id = Some(name),
            Some(LoadCommand::Platform(platform)) => platforms.push(platform),
            Some(LoadCommand::Uuid(uuid)) => info.uuid = Some(uuid),
            Some(LoadCommand::Restrict) => info.restricted = true,
            Some(LoadCommand::DyldEnvironment(var)) => info.dyld_environment.push(var),
            None => {}
        }
    }

    info.platforms = platforms
        .iter()
        .map(|platform| (platform.id, platform.sdk_version))
        .collect();
    info.platform = format_platforms(platforms);
    Ok(info)
}

// The platform of an image, along with its SDK version, the way dyld
// combines its platform load commands (PlatformAndVersions::zip): the first
// one sets the platform, which a macOS and a Mac Catalyst pair turns into a
// zippered image loadable in both, and any other platform after it is
// ignored.  An image without any is taken as a macOS one on the Intel and
// arm64 architectures (UnsafeHeader::forEachPlatformLoadCommand).
#[derive(Clone, Copy, Debug, PartialEq)]
enum ImagePlatform {
    None,
    Single(Platform, Version),
    // The macOS and the Mac Catalyst SDK versions.
    Zippered(Version, Version),
}

impl ImagePlatform {
    fn new(info: &MachOInfo) -> ImagePlatform {
        use ImagePlatform::*;
        if info.platforms.is_empty() {
            return match info.cputype {
                CPU_TYPE_X86_64 | CPU_TYPE_X86 => Single(PLATFORM_MACOS, Version::new(10, 5, 0)),
                CPU_TYPE_ARM64 => Single(PLATFORM_MACOS, Version::new(11, 0, 0)),
                _ => None,
            };
        }
        info.platforms
            .iter()
            .fold(None, |current, &(platform, sdk)| {
                match (current, platform) {
                    (None, _) => Single(platform, sdk),
                    (Single(id, _), _) if id == platform => Single(platform, sdk),
                    (Single(PLATFORM_MACOS, macos), PLATFORM_MACCATALYST) => Zippered(macos, sdk),
                    (Single(PLATFORM_MACCATALYST, catalyst), PLATFORM_MACOS) => {
                        Zippered(sdk, catalyst)
                    }
                    (Zippered(_, catalyst), PLATFORM_MACOS) => Zippered(sdk, catalyst),
                    (Zippered(macos, _), PLATFORM_MACCATALYST) => Zippered(macos, sdk),
                    (current, _) => current,
                }
            })
    }

    // The process platform, a zippered image running as a macOS one.
    fn platform(self) -> Option<Platform> {
        match self {
            ImagePlatform::None => None,
            ImagePlatform::Single(platform, _) => Some(platform),
            ImagePlatform::Zippered(_, _) => Some(PLATFORM_MACOS),
        }
    }
}

// Whether an image is built for macOS, zippered images included.
fn built_for_macos(info: &MachOInfo) -> bool {
    matches!(
        ImagePlatform::new(info),
        ImagePlatform::Single(PLATFORM_MACOS, _) | ImagePlatform::Zippered(_, _)
    )
}

// Whether an image was built with an SDK older than the 2022 releases
// (macOS 14, iOS 17, and so on), which dyld records as the pre2022Binary
// Loader flag (MachOFile::enforceFormat with Malformed::sdkOnOrAfter2022),
// and for which it still searches the default fallback directories.
fn pre_2022(info: &MachOInfo) -> bool {
    let enforced = |platform: Platform, sdk: Version| match platform {
        PLATFORM_MACOS => sdk.0 >= 0x000E_0000,
        PLATFORM_IOS | PLATFORM_TVOS | PLATFORM_MACCATALYST => sdk.0 >= 0x0011_0000,
        PLATFORM_WATCHOS => sdk.0 >= 0x000A_0000,
        PLATFORM_VISIONOS | PLATFORM_VISIONOSSIMULATOR => sdk.0 >= 0x0002_0000,
        _ => true,
    };
    !match ImagePlatform::new(info) {
        ImagePlatform::None => false,
        ImagePlatform::Single(platform, sdk) => enforced(platform, sdk),
        ImagePlatform::Zippered(macos, catalyst) => {
            enforced(PLATFORM_MACOS, macos) || enforced(PLATFORM_MACCATALYST, catalyst)
        }
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
    sdk_version: Version,
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
    // A segment with the __RESTRICT,__restrict section.
    Restrict,
    // A LC_DYLD_ENVIRONMENT variable.
    DyldEnvironment(String),
}

// Whether a segment is the __RESTRICT one holding a __restrict section, the
// section dyld checks to hand AMFI the restricted process mark
// (UnsafeHeader::isRestricted, AMFI_DYLD_INPUT_PROC_HAS_RESTRICT_SEG).
fn restrict_section<S: Segment>(endian: S::Endian, segment: &S, data: &[u8]) -> bool {
    segment.name() == b"__RESTRICT"
        && segment.sections(endian, data).is_ok_and(|sections| {
            sections
                .iter()
                .any(|section| section.name() == b"__restrict")
        })
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
            sdk_version: x.sdk.get(endian),
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
            // The original LC_VERSION_MIN_MACOSX had no SDK version, which
            // dyld takes as the minimum one.
            let sdk_version = match (id, x.sdk.get(endian)) {
                (PLATFORM_MACOS, Version(0)) => x.version.get(endian),
                (_, sdk) => sdk,
            };
            Some(LoadCommand::Platform(PlatformInfo {
                id,
                sdk_version,
                name: platform.to_string(),
                min: format_os_version(x.version.get(endian)),
                sdk: format_os_version(x.sdk.get(endian)),
            }))
        }
        LoadCommandVariant::Uuid(x) => Some(LoadCommand::Uuid(format_uuid(&x.uuid))),
        LoadCommandVariant::DyldEnvironment(x) => Some(LoadCommand::DyldEnvironment(
            parse_string::<Mach>(endian, &command, x.name)?,
        )),
        LoadCommandVariant::Segment32(segment, data) => {
            restrict_section(endian, segment, data).then_some(LoadCommand::Restrict)
        }
        LoadCommandVariant::Segment64(segment, data) => {
            restrict_section(endian, segment, data).then_some(LoadCommand::Restrict)
        }
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
        parse_object(data, Check::Input(arch))
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
            vars: DyldVars::default(),
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

    // The nodes below IDX in the order the listing shows them, along with
    // their level.
    fn walk<'a>(
        tree: &'a DepTree,
        idx: usize,
        level: usize,
        nodes: &mut Vec<(usize, &'a DepNode)>,
    ) {
        for &child in &tree.arena[idx].children {
            nodes.push((level, &tree.arena[child].val));
            walk(tree, child, level + 1, nodes);
        }
    }

    // The nodes below the root in the listing order: the full path of a
    // resolved one or the name of one not found, its mode, and whether it
    // repeats an earlier one.
    fn resolve(ctx: &mut MachOContext, input: &str) -> Vec<(String, DepMode, bool)> {
        let tree = resolve_binary(ctx, input).unwrap();
        let mut nodes = Vec::new();
        walk(&tree, 0, 1, &mut nodes);
        nodes
            .into_iter()
            .map(|(_, node)| {
                let name = match &node.path {
                    Some(path) => pathutils::join(path, &node.name),
                    None => node.name.clone(),
                };
                (name, node.mode, node.found)
            })
            .collect()
    }

    // The tree the listing shows, a line for each node with its leaf name
    // indented by its level and a trailing * when it repeats an earlier
    // one, and the leaf names of the images in the order they were loaded.
    fn listing(ctx: &mut MachOContext, input: &str) -> (Vec<String>, Vec<String>) {
        let tree = resolve_binary(ctx, input).unwrap();
        let mut nodes = Vec::new();
        walk(&tree, 0, 1, &mut nodes);
        let lines = nodes
            .into_iter()
            .map(|(level, node)| {
                let name = pathutils::get_name(&Path::new(&node.name));
                let repeat = if node.found { " *" } else { "" };
                format!("{}{name}{repeat}", "  ".repeat(level - 1))
            })
            .collect();
        let loaded = tree.arena[1..]
            .iter()
            .filter(|node| !node.val.found && node.val.mode != DepMode::NotFound)
            .map(|node| node.val.name.clone())
            .collect();
        (lines, loaded)
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
        ctx.vars.fallback_library_path = dir.path("fb");
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
        ctx.vars.library_path = dir.path("lp");
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
        ctx.vars.fallback_library_path = dir.path("fb");
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

    // An image of CPUTYPE with the platform load commands PLATFORMS, and the
    // SDK version 14.0.
    fn platform_info(cputype: CpuType, platforms: &[Platform]) -> MachOInfo {
        platform_sdk_info(
            cputype,
            &platforms
                .iter()
                .map(|platform| (*platform, Version::new(14, 0, 0)))
                .collect::<Vec<_>>(),
        )
    }

    fn platform_sdk_info(cputype: CpuType, platforms: &[(Platform, Version)]) -> MachOInfo {
        MachOInfo {
            cputype,
            platforms: platforms.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn image_platform() {
        let (v13, v14, v17) = (
            Version::new(13, 0, 0),
            Version::new(14, 0, 0),
            Version::new(17, 0, 0),
        );
        let platform = |platforms: &[(Platform, Version)]| {
            ImagePlatform::new(&platform_sdk_info(CPU_TYPE_ARM64, platforms))
        };
        assert_eq!(
            ImagePlatform::new(&platform_info(CPU_TYPE_X86_64, &[])),
            ImagePlatform::Single(PLATFORM_MACOS, Version::new(10, 5, 0))
        );
        assert_eq!(
            ImagePlatform::new(&platform_info(CPU_TYPE_POWERPC, &[])),
            ImagePlatform::None
        );
        assert_eq!(
            platform(&[(PLATFORM_MACOS, v13), (PLATFORM_MACCATALYST, v17)]),
            ImagePlatform::Zippered(v13, v17)
        );
        assert_eq!(
            platform(&[
                (PLATFORM_MACCATALYST, v17),
                (PLATFORM_IOS, v14),
                (PLATFORM_MACOS, v13)
            ]),
            ImagePlatform::Zippered(v13, v17)
        );
        assert_eq!(
            platform(&[(PLATFORM_IOS, v14), (PLATFORM_IOS, v17)]),
            ImagePlatform::Single(PLATFORM_IOS, v17)
        );
        assert_eq!(
            platform(&[(PLATFORM_IOS, v14), (PLATFORM_MACOS, v17)]),
            ImagePlatform::Single(PLATFORM_IOS, v14)
        );
        assert_eq!(
            platform(&[(PLATFORM_MACOS, v13), (PLATFORM_MACCATALYST, v17)]).platform(),
            Some(PLATFORM_MACOS)
        );
    }

    #[test]
    fn pre_2022_images() {
        let version = |major, minor| Version::new(major, minor, 0);
        for (cputype, platforms, expected) in [
            // Without any platform load command, an old macOS binary.
            (CPU_TYPE_X86_64, vec![], true),
            (CPU_TYPE_ARM64, vec![], true),
            (CPU_TYPE_POWERPC, vec![], true),
            (CPU_TYPE_ARM64, vec![(PLATFORM_MACOS, version(13, 3))], true),
            (
                CPU_TYPE_ARM64,
                vec![(PLATFORM_MACOS, version(14, 0))],
                false,
            ),
            (CPU_TYPE_ARM64, vec![(PLATFORM_IOS, version(16, 4))], true),
            (CPU_TYPE_ARM64, vec![(PLATFORM_IOS, version(17, 0))], false),
            (
                CPU_TYPE_ARM64,
                vec![(PLATFORM_MACCATALYST, version(16, 0))],
                true,
            ),
            (
                CPU_TYPE_ARM64,
                vec![(PLATFORM_WATCHOS, version(9, 0))],
                true,
            ),
            (
                CPU_TYPE_ARM64,
                vec![(PLATFORM_WATCHOS, version(10, 0))],
                false,
            ),
            (
                CPU_TYPE_ARM64,
                vec![(PLATFORM_VISIONOS, version(1, 0))],
                true,
            ),
            (
                CPU_TYPE_ARM64,
                vec![(PLATFORM_DRIVERKIT, version(19, 0))],
                false,
            ),
            (
                CPU_TYPE_ARM64,
                vec![(PLATFORM_IOSSIMULATOR, version(13, 0))],
                false,
            ),
            // Zippered, the new Mac Catalyst SDK is enough.
            (
                CPU_TYPE_ARM64,
                vec![
                    (PLATFORM_MACOS, version(13, 0)),
                    (PLATFORM_MACCATALYST, version(17, 0)),
                ],
                false,
            ),
            (
                CPU_TYPE_ARM64,
                vec![
                    (PLATFORM_MACOS, version(13, 0)),
                    (PLATFORM_MACCATALYST, version(16, 0)),
                ],
                true,
            ),
        ] {
            let info = platform_sdk_info(cputype, &platforms);
            assert_eq!(pre_2022(&info), expected, "{platforms:?}");
        }
    }

    // The candidate paths of DEPENDENCY for a requester that takes the
    // default fallback directories (DEFAULTS), in a process of PLATFORM.
    fn candidates(
        platform: Option<Platform>,
        security: Security,
        vars: &DyldVars,
        dependency: &str,
        defaults: bool,
    ) -> Vec<(String, DepMode)> {
        let arch = Arch::process(CPU_TYPE_X86_64, CpuSubtype(3), MH_EXECUTE);
        let cache = DyldCache::default();
        let env = DyldEnv::new(vars);
        let config = Config {
            arch: &arch,
            macos: platform == Some(PLATFORM_MACOS),
            platform,
            security,
            cache: &cache,
            executable_path: "/exe",
            env: &env,
            all: true,
            depth: 0,
            ignore_prefix: &[],
        };
        let requester = Requester {
            place: Place { node: 0, level: 0 },
            loader_path: "/exe",
            rpaths: &[],
            default_fallbacks: defaults,
        };
        candidate_paths(&config, &requester, dependency, false)
    }

    #[test]
    fn default_fallbacks() {
        let vars = DyldVars::default();
        let dylib = "/opt/lib/libfoo.dylib";
        let framework = "/opt/F/Foo.framework/Versions/A/Foo";
        let restricted = Security {
            restricted: Some("test"),
        };
        let paths = |platform, security, dependency, defaults| {
            candidates(platform, security, &vars, dependency, defaults)
                .into_iter()
                .map(|(path, _)| path)
                .collect::<Vec<String>>()
        };
        let macos = Some(PLATFORM_MACOS);
        let open = Security::default();
        // Only for a pre-2022 requester.
        assert_eq!(paths(macos, open, dylib, false), [dylib]);
        assert_eq!(
            paths(macos, open, dylib, true),
            [
                dylib,
                "/usr/local/lib/libfoo.dylib",
                "/usr/lib/libfoo.dylib"
            ]
        );
        assert_eq!(
            candidates(macos, open, &vars, dylib, true)[1].1,
            DepMode::SystemDirs
        );
        assert_eq!(
            paths(macos, restricted, dylib, true),
            [dylib, "/usr/lib/libfoo.dylib"]
        );
        assert_eq!(
            paths(macos, open, framework, true),
            [
                framework,
                "/Library/Frameworks/Foo.framework/Versions/A/Foo",
                "/System/Library/Frameworks/Foo.framework/Versions/A/Foo"
            ]
        );
        assert_eq!(
            paths(macos, restricted, framework, true),
            [
                framework,
                "/System/Library/Frameworks/Foo.framework/Versions/A/Foo"
            ]
        );
        // The load path itself is not tried again.
        assert_eq!(
            paths(macos, open, "/usr/lib/libz.dylib", true),
            ["/usr/lib/libz.dylib", "/usr/local/lib/libz.dylib"]
        );
        // The other platforms.
        assert_eq!(
            paths(Some(PLATFORM_IOS), open, dylib, true),
            [
                dylib,
                "/usr/local/lib/libfoo.dylib",
                "/usr/lib/libfoo.dylib"
            ]
        );
        assert_eq!(
            paths(Some(PLATFORM_MACCATALYST), open, dylib, true),
            [dylib, "/usr/local/lib/libfoo.dylib"]
        );
        assert_eq!(
            paths(Some(PLATFORM_MACCATALYST), open, framework, true),
            [
                framework,
                "/System/Library/Frameworks/Foo.framework/Versions/A/Foo"
            ]
        );
        assert_eq!(paths(Some(PLATFORM_DRIVERKIT), open, dylib, true), [dylib]);
        assert_eq!(paths(None, open, dylib, true), [dylib]);

        // A DYLD_FALLBACK_LIBRARY_PATH replaces them, for any requester.
        let dir = Scratch::new("fallbacks");
        let custom = DyldVars {
            fallback_library_path: dir.path(""),
            ..Default::default()
        };
        for defaults in [false, true] {
            assert_eq!(
                candidates(macos, open, &custom, dylib, defaults),
                [
                    (dylib.to_string(), DepMode::Direct),
                    (dir.path("libfoo.dylib"), DepMode::LdFallbackLibraryPath)
                ]
            );
        }
    }

    #[test]
    fn macos_platform() {
        let info = platform_info;
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
        ctx.vars.fallback_library_path = dir.path("fb");
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
    fn library_path_not_for_frameworks() {
        // DYLD_LIBRARY_PATH holds a file with the framework leaf name, which
        // only the non-framework load paths are looked up in.
        let dir = Scratch::new("fwpath");
        let lib = dir.write("lp/Foo", &x86_64_dylib(&[]));
        let framework = dir.path("missing/Foo.framework/Versions/A/Foo");
        let exe = dir.write(
            "bin/exe",
            &x86_64_exe(&[load(&framework), load(&dir.path("missing/Foo"))]),
        );
        let mut ctx = context(None);
        ctx.vars.library_path = dir.path("lp");
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&framework, DepMode::NotFound),
                node(&lib, DepMode::LdLibraryPath),
            ]
        );

        // The framework is found on DYLD_FRAMEWORK_PATH.
        let found = dir.write("fp/Foo.framework/Versions/A/Foo", &x86_64_dylib(&[]));
        ctx.vars.framework_path = dir.path("fp");
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&found, DepMode::LdFrameworkPath),
                node(&lib, DepMode::LdLibraryPath),
            ]
        );
    }

    #[test]
    fn at_path_expansion() {
        let expand = |path| expand_at_path(path, Some("/a/b/MacOS"), Some("/l/lib"));
        for (path, expanded) in [
            ("@executable_path/libx.dylib", "/a/b/MacOS/libx.dylib"),
            ("@executable_path/../Frameworks/X", "/a/b/Frameworks/X"),
            ("@executable_path/../../../../x", "/a/../../x"),
            ("@executable_path", "/a/b/MacOS/"),
            ("@loader_path/../libx.dylib", "/l/lib/../libx.dylib"),
            ("@loader_path", "/l/lib"),
            // Only a leading component is expanded.
            (
                "@executable_pathx/libx.dylib",
                "@executable_pathx/libx.dylib",
            ),
            ("/x/@loader_path/libx.dylib", "/x/@loader_path/libx.dylib"),
            ("@rpath/libx.dylib", "@rpath/libx.dylib"),
            ("/usr/lib/libz.dylib", "/usr/lib/libz.dylib"),
        ] {
            assert_eq!(expand(path), expanded, "{path}");
        }
        // Not for an inserted library.
        assert_eq!(
            expand_at_path("@loader_path/libx.dylib", Some("/a"), None),
            "@loader_path/libx.dylib"
        );
        assert_eq!(expand_rpath("@rpath/x/@rpath/y", "/r"), "/r/x/@rpath/y");
    }

    #[test]
    fn inserted_library_at_paths() {
        // The inserted @rpath and @loader_path entries are not expanded, so
        // only the DYLD_LIBRARY_PATH and fallback directories provide them,
        // while an @executable_path one is.
        let dir = Scratch::new("insertat");
        dir.write("rp/librp.dylib", &x86_64_dylib(&[]));
        dir.write("bin/libld.dylib", &x86_64_dylib(&[]));
        let exec = dir.write("bin/libex.dylib", &x86_64_dylib(&[]));
        let lp = dir.write("lp/librp.dylib", &x86_64_dylib(&[]));
        let fb = dir.write("fb/libld.dylib", &x86_64_dylib(&[]));
        let exe = dir.write(
            "bin/exe",
            &x86_64_exe(&[string_command(LC_RPATH, &[], &dir.path("rp"))]),
        );
        let mut ctx = context(None);
        ctx.vars.insert_libraries =
            "@rpath/librp.dylib:@loader_path/libld.dylib:@executable_path/libex.dylib".to_string();
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node("@rpath/librp.dylib", DepMode::NotFound),
                node("@loader_path/libld.dylib", DepMode::NotFound),
                node(&exec, DepMode::Preload),
            ]
        );
        ctx.vars.library_path = dir.path("lp");
        ctx.vars.fallback_library_path = dir.path("fb");
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&lp, DepMode::LdLibraryPath),
                node(&fb, DepMode::LdFallbackLibraryPath),
                node(&exec, DepMode::Preload),
            ]
        );
    }

    fn lines(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|line| line.to_string()).collect()
    }

    #[test]
    fn load_order_sibling_first() {
        // The main executable links against libA and @rpath/libX.dylib, and
        // libA against @rpath/libX.dylib too, with its own run-path entry.
        // dyld loads @rpath/libX.dylib through the main executable run-path
        // list before looking at the libA dependencies, which then match it
        // by its install name.
        let dir = Scratch::new("order");
        let id = dylib_command(LC_ID_DYLIB, "@rpath/libX.dylib");
        let rpath = |dir: String| string_command(LC_RPATH, &[], &dir);
        let libx_main = dir.write("m/libX.dylib", &x86_64_dylib(std::slice::from_ref(&id)));
        dir.write("a/libX.dylib", &x86_64_dylib(&[id]));
        let lib_a = dir.write(
            "a/libA.dylib",
            &x86_64_dylib(&[load("@rpath/libX.dylib"), rpath(dir.path("a"))]),
        );
        let exe = dir.write(
            "bin/exe",
            &x86_64_exe(&[
                load(&lib_a),
                load("@rpath/libX.dylib"),
                rpath(dir.path("m")),
            ]),
        );
        let mut ctx = context(None);
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&lib_a, DepMode::Direct),
                repeat(&libx_main, DepMode::DtRpath),
                node(&libx_main, DepMode::DtRpath),
            ]
        );
    }

    #[test]
    fn load_order_dependents_once() {
        // libC is a dependency of both the main executable and libA, and
        // links against @rpath/libY.dylib, found through the libA run-path
        // entry.  dyld loads libC for the main executable, but its
        // dependencies when libA reaches it, with the libA run-path stack.
        let dir = Scratch::new("once");
        dir.write(
            "a/libY.dylib",
            &x86_64_dylib(&[load(&dir.path("z/libZ.dylib"))]),
        );
        dir.write("z/libZ.dylib", &x86_64_dylib(&[]));
        let lib_c = dir.write("c/libC.dylib", &x86_64_dylib(&[load("@rpath/libY.dylib")]));
        let lib_a = dir.write(
            "a/libA.dylib",
            &x86_64_dylib(&[load(&lib_c), string_command(LC_RPATH, &[], &dir.path("a"))]),
        );
        let exe = dir.write("bin/exe", &x86_64_exe(&[load(&lib_a), load(&lib_c)]));
        let mut ctx = context(None);
        let (tree, loaded) = listing(&mut ctx, &exe);
        assert_eq!(
            tree,
            lines(&[
                "libA.dylib",
                "  libC.dylib *",
                "libC.dylib",
                "  libY.dylib",
                "    libZ.dylib",
            ])
        );
        assert_eq!(
            loaded,
            lines(&["libA.dylib", "libC.dylib", "libY.dylib", "libZ.dylib"])
        );

        // The depth limit prunes the levels the listing shows.
        ctx.depth = 1;
        assert_eq!(
            listing(&mut ctx, &exe).0,
            lines(&["libA.dylib", "libC.dylib"])
        );
        ctx.depth = 2;
        assert_eq!(
            listing(&mut ctx, &exe).0,
            lines(&["libA.dylib", "  libC.dylib *", "libC.dylib", "  libY.dylib"])
        );
    }

    #[test]
    fn load_order_listing() {
        // The images are loaded level by level below each image, so libB is
        // loaded before libC, a dependency of the earlier libA, while the
        // listing shows libC below libA.
        let dir = Scratch::new("listing");
        let lib_c = dir.write("lib/libC.dylib", &x86_64_dylib(&[]));
        let lib_a = dir.write("lib/libA.dylib", &x86_64_dylib(&[load(&lib_c)]));
        let lib_b = dir.write("lib/libB.dylib", &x86_64_dylib(&[]));
        let exe = dir.write("bin/exe", &x86_64_exe(&[load(&lib_a), load(&lib_b)]));
        let mut ctx = context(None);
        let (tree, loaded) = listing(&mut ctx, &exe);
        assert_eq!(tree, lines(&["libA.dylib", "  libC.dylib", "libB.dylib"]));
        assert_eq!(loaded, lines(&["libA.dylib", "libB.dylib", "libC.dylib"]));
    }

    #[test]
    fn load_order_inserted_libraries() {
        // The inserted libraries are loaded first, but their dependencies
        // after the main executable ones, so libD is loaded for libA, and
        // libP only repeats it.
        let dir = Scratch::new("insertorder");
        let lib_d = dir.write("lib/libD.dylib", &x86_64_dylib(&[]));
        let lib_a = dir.write("lib/libA.dylib", &x86_64_dylib(&[load(&lib_d)]));
        let lib_p = dir.write("pre/libP.dylib", &x86_64_dylib(&[load(&lib_d)]));
        let exe = dir.write("bin/exe", &x86_64_exe(&[load(&lib_a)]));
        let mut ctx = context(None);
        ctx.vars.insert_libraries = format!("{lib_p}:{lib_p}");
        let (tree, loaded) = listing(&mut ctx, &exe);
        assert_eq!(
            tree,
            lines(&[
                "libP.dylib",
                "  libD.dylib *",
                "libP.dylib *",
                "libA.dylib",
                "  libD.dylib",
            ])
        );
        assert_eq!(loaded, lines(&["libP.dylib", "libA.dylib", "libD.dylib"]));
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
        ctx.vars.insert_libraries = inserted.clone();
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
            parse_object(data, Check::Dependency(arch)).map(|info| dep_names(&info).join(":"))
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
        ctx.vars.fallback_library_path = dir.path("fallback");
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
            [
                "/does/not/exist",
                "@loader_path/../lib",
                "@executable_path/Frameworks/"
            ]
        );
        let expand = |security, main| expand_rpaths(&info.rpath, "/exe", "/loader", security, main);
        let unrestricted = Security::default();
        for main in [true, false] {
            assert_eq!(
                expand(unrestricted, main),
                ["/does/not/exist", "/loader/../lib", "/exe/Frameworks/"]
            );
        }
        // A restricted process neither expands @executable_path nor the main
        // executable @loader_path, and drops a relative entry.
        let restricted = Security {
            restricted: Some("test"),
        };
        assert_eq!(expand(restricted, true), ["/does/not/exist"]);
        assert_eq!(
            expand(restricted, false),
            ["/does/not/exist", "/loader/../lib"]
        );
        let relative = vec!["lib".to_string(), "/usr/lib".to_string()];
        assert_eq!(
            expand_rpaths(&relative, "/exe", "/loader", unrestricted, true),
            ["lib", "/usr/lib"]
        );
        assert_eq!(
            expand_rpaths(&relative, "/exe", "/loader", restricted, true),
            ["/usr/lib"]
        );
    }

    // A LC_SEGMENT_64 command for SEGNAME with the SECTIONS.
    fn segment64(segname: &str, sections: &[&str]) -> Vec<u8> {
        let name = |name: &str| {
            let mut bytes = name.as_bytes().to_vec();
            bytes.resize(16, 0);
            bytes
        };
        let mut command = words(&[LC_SEGMENT_64.0, 72 + 80 * sections.len() as u32], false);
        command.extend(name(segname));
        command.extend([0; 32]);
        command.extend(words(&[0, 0, sections.len() as u32, 0], false));
        for section in sections {
            command.extend(name(section));
            command.extend(name(segname));
            command.extend([0; 48]);
        }
        command
    }

    #[test]
    fn restrict_section() {
        let arch = Arch::new(None).unwrap();
        let restricted = |cmds: &[Vec<u8>]| parse(&x86_64_exe(cmds), &arch).unwrap().restricted;
        assert!(restricted(&[segment64("__RESTRICT", &["__restrict"])]));
        assert!(restricted(&[
            segment64("__TEXT", &["__text"]),
            segment64("__RESTRICT", &["__other", "__restrict"]),
        ]));
        assert!(!restricted(&[segment64("__RESTRICT", &["__other"])]));
        assert!(!restricted(&[segment64("__DATA", &["__restrict"])]));
        assert!(!restricted(&[]));
    }

    #[test]
    fn restricted_process() {
        use std::os::unix::fs::PermissionsExt;

        // A program linking against an @executable_path library and one
        // only found on the DYLD_LIBRARY_PATH directory, with an inserted
        // library.
        let dir = Scratch::new("restricted");
        let exec = dir.write("bin/libe.dylib", &x86_64_dylib(&[]));
        let lib = dir.write("lp/libfoo.dylib", &x86_64_dylib(&[]));
        let inserted = dir.write("pre/libp.dylib", &x86_64_dylib(&[]));
        let missing = dir.path("missing/libfoo.dylib");
        let deps = [load("@executable_path/libe.dylib"), load(&missing)];
        let plain = dir.write("bin/plain", &x86_64_exe(&deps));
        let mut cmds = deps.to_vec();
        cmds.push(segment64("__RESTRICT", &["__restrict"]));
        let restrict = dir.write("bin/restrict", &x86_64_exe(&cmds));
        let setuid = dir.write("bin/setuid", &x86_64_exe(&deps));
        std::fs::set_permissions(&setuid, std::fs::Permissions::from_mode(0o4755)).unwrap();

        let mut ctx = context(None);
        ctx.vars.library_path = dir.path("lp");
        ctx.vars.insert_libraries = inserted.clone();
        assert_eq!(
            resolve(&mut ctx, &plain),
            [
                node(&inserted, DepMode::Preload),
                node(&exec, DepMode::Direct),
                node(&lib, DepMode::LdLibraryPath),
            ]
        );
        // The restricted ones neither take the DYLD_* variables nor expand
        // @executable_path.
        for input in [&restrict, &setuid] {
            assert_eq!(
                resolve(&mut ctx, input),
                [
                    node("@executable_path/libe.dylib", DepMode::NotFound),
                    node(&missing, DepMode::NotFound),
                ]
            );
        }

        let security = |path: &str| {
            let info = parse(&std::fs::read(path).unwrap(), &Arch::new(None).unwrap()).unwrap();
            Security::new(Path::new(path), false, &info).restricted
        };
        assert_eq!(security(&plain), None);
        assert_eq!(security(&restrict), Some("__RESTRICT,__restrict section"));
        assert_eq!(security(&setuid), Some("setuid or setgid program"));
    }

    #[test]
    fn embedded_variables() {
        let vars = |embedded: &[&str], security| {
            let mut vars = DyldVars {
                library_path: "/env".to_string(),
                image_suffix: Some("_env".to_string()),
                ..Default::default()
            };
            let embedded: Vec<String> = embedded.iter().map(|var| var.to_string()).collect();
            vars.add_embedded(&embedded, "/app/MacOS", security);
            vars
        };
        let embedded = [
            "DYLD_LIBRARY_PATH=@executable_path/../lib:/opt/lib:@rpath/x",
            "DYLD_FALLBACK_LIBRARY_PATH=@loader_path/fb",
            "DYLD_FRAMEWORK_PATH=/fw",
            "DYLD_FALLBACK_FRAMEWORK_PATH=/fbfw",
            "DYLD_INSERT_LIBRARIES=/pre/libp.dylib",
            "DYLD_IMAGE_SUFFIX=_debug",
            "DYLD_PRINT_LIBRARIES=1",
            "DYLD_NO_VALUE",
        ];
        let all = vars(&embedded, Security::default());
        assert_eq!(all.library_path, "/env:/app/MacOS/../lib:/opt/lib:@rpath/x");
        assert_eq!(all.fallback_library_path, "/app/MacOS/fb");
        assert_eq!(all.framework_path, "/fw");
        assert_eq!(all.fallback_framework_path, "/fbfw");
        assert_eq!(all.insert_libraries, "/pre/libp.dylib");
        assert_eq!(all.image_suffix.as_deref(), Some("_env:_debug"));
        // A restricted process drops the @ entries.
        let restricted = vars(
            &embedded,
            Security {
                restricted: Some("test"),
            },
        );
        assert_eq!(restricted.library_path, "/env:/opt/lib");
        assert_eq!(restricted.fallback_library_path, "");
    }

    #[test]
    fn embedded_library_path() {
        // The main executable sets its DYLD_LIBRARY_PATH, which also applies
        // to a restricted process.
        let dir = Scratch::new("dyldenv");
        let lib = dir.write("lp/libfoo.dylib", &x86_64_dylib(&[]));
        let inserted = dir.write("pre/libp.dylib", &x86_64_dylib(&[]));
        let missing = dir.path("missing/libfoo.dylib");
        let env = |var: &str| string_command(LC_DYLD_ENVIRONMENT, &[], var);
        let cmds = [
            load(&missing),
            env("DYLD_LIBRARY_PATH=@executable_path/../lp"),
            env(&format!("DYLD_INSERT_LIBRARIES={inserted}")),
        ];
        let exe = dir.write("bin/exe", &x86_64_exe(&cmds));
        let arch = Arch::new(None).unwrap();
        assert_eq!(
            parse(&std::fs::read(&exe).unwrap(), &arch)
                .unwrap()
                .dyld_environment,
            [
                "DYLD_LIBRARY_PATH=@executable_path/../lp".to_string(),
                format!("DYLD_INSERT_LIBRARIES={inserted}")
            ]
        );
        let mut ctx = context(None);
        assert_eq!(
            resolve(&mut ctx, &exe),
            [
                node(&inserted, DepMode::Preload),
                node(&lib, DepMode::LdLibraryPath),
            ]
        );

        let mut cmds = cmds.to_vec();
        cmds.push(segment64("__RESTRICT", &["__restrict"]));
        let restricted = dir.write("bin/restricted", &x86_64_exe(&cmds));
        let absolute = dir.write(
            "bin/absolute",
            &x86_64_exe(&[
                load(&missing),
                env(&format!("DYLD_LIBRARY_PATH={}", dir.path("lp"))),
                segment64("__RESTRICT", &["__restrict"]),
            ]),
        );
        assert_eq!(
            resolve(&mut ctx, &restricted),
            [
                node(&inserted, DepMode::Preload),
                node(&missing, DepMode::NotFound),
            ]
        );
        assert_eq!(
            resolve(&mut ctx, &absolute),
            [node(&lib, DepMode::LdLibraryPath)]
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
            assert_eq!(framework_partial_path(path, None), partial, "{path}");
        }

        // A leaf with the image suffix appended to the framework name.
        let debug = "/F/Foo.framework/Versions/A/Foo_debug";
        for (suffix, partial) in [
            (None, None),
            (Some("_debug"), Some("Foo.framework/Versions/A/Foo_debug")),
            (Some("_profile"), None),
            (Some("_de"), None),
            (Some("_debug:_profile"), None),
        ] {
            assert_eq!(framework_partial_path(debug, suffix), partial, "{suffix:?}");
        }
        assert_eq!(
            framework_partial_path("/F/Foo.framework/Foo", Some("_debug")),
            Some("Foo.framework/Foo")
        );
    }

    #[test]
    fn image_suffix_variants() {
        assert_eq!(
            suffix_variants(None, "/p/libfoo.dylib"),
            ["/p/libfoo.dylib"]
        );
        for (path, suffixed) in [
            ("/p/libfoo.dylib", "/p/libfoo_debug.dylib"),
            ("/p/libbar.A.dylib", "/p/libbar.A_debug.dylib"),
            ("/p/libz.so", "/p/libz_debug.so"),
            ("/p/Foo", "/p/Foo_debug"),
            ("/p.d/Foo", "/p.d/Foo_debug"),
            ("foo.dylib", "foo_debug.dylib"),
        ] {
            assert_eq!(suffix_variants(Some("_debug"), path), [suffixed, path]);
        }
        // Each suffix of the list, in order.
        assert_eq!(
            suffix_variants(Some("_debug:_profile"), "/p/libfoo.dylib"),
            [
                "/p/libfoo_debug.dylib",
                "/p/libfoo_profile.dylib",
                "/p/libfoo.dylib"
            ]
        );
    }

    #[test]
    fn framework_path_image_suffix() {
        // A debug framework install name is still a framework load path,
        // looked up on DYLD_FRAMEWORK_PATH, when its suffix is the image one.
        let dir = Scratch::new("fwsuffix");
        let framework = dir.write("fp/Foo.framework/Versions/A/Foo_debug", &x86_64_dylib(&[]));
        let missing = dir.path("missing/Foo.framework/Versions/A/Foo_debug");
        let exe = dir.write("bin/exe", &x86_64_exe(&[load(&missing)]));
        let mut ctx = context(None);
        ctx.vars.framework_path = dir.path("fp");
        assert_eq!(resolve(&mut ctx, &exe), [node(&missing, DepMode::NotFound)]);
        ctx.vars.image_suffix = Some("_debug".to_string());
        assert_eq!(
            resolve(&mut ctx, &exe),
            [node(&framework, DepMode::LdFrameworkPath)]
        );
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
