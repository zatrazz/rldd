use std::cell::OnceCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::Error;
use std::path::Path;
use std::{fs, str};

use object::pe;
use object::read::pe::ExportTarget;
use object::read::pe::{ExportTable, ImageNtHeaders, ImageOptionalHeader, ImageThunkData, PeFile};
use object::{FileKind, LittleEndian as LE};

use crate::deptree::*;
use crate::pathutils;
use crate::search_path;
use machine::Wow64;

mod apiset;
mod knowndlls;
mod machine;
mod registry;
mod search_dirs;
mod sxs;
#[cfg(test)]
mod testimage;

// A symbol imported from a dependency.
#[derive(Clone, Debug)]
enum ImportName {
    Name(String),
    Ordinal(u16),
}

impl fmt::Display for ImportName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ImportName::Name(name) => write!(f, "{name}"),
            ImportName::Ordinal(ordinal) => write!(f, "#{ordinal}"),
        }
    }
}

// A dependency recorded on the import or the delay load import directory.
#[derive(Clone, Debug)]
struct PeDep {
    name: String,
    attrs: Vec<&'static str>,
    // The symbols imported from it, used to follow the export forwarders and
    // to check the imports.
    imports: Vec<ImportName>,
}

impl PeDep {
    fn is_delay_load(&self) -> bool {
        self.attrs.contains(&"delay-load")
    }
}

// Where an exported symbol points to.
enum ExportLookup<'a> {
    Local,
    // Forwarded to another module, which the loader loads to bind it.
    Forwarded(&'a str),
    Missing,
}

#[derive(Default, Debug)]
struct PeExports {
    // The value is the module a forwarded export points at.
    names: HashMap<String, Option<String>>,
    ordinals: HashMap<u16, Option<String>>,
}

impl PeExports {
    fn lookup(&self, import: &ImportName) -> ExportLookup<'_> {
        let forward = match import {
            ImportName::Name(name) => self.names.get(name),
            ImportName::Ordinal(ordinal) => self.ordinals.get(ordinal),
        };
        match forward {
            Some(Some(module)) => ExportLookup::Forwarded(module),
            Some(None) => ExportLookup::Local,
            None => ExportLookup::Missing,
        }
    }
}

#[derive(Default, Debug)]
struct PeInfo {
    machine: pe::Machine,
    subsystem: pe::Subsystem,
    image_base: u64,
    is_dll: bool,
    deps: Vec<PeDep>,
    exports: PeExports,
    // The dependent assemblies of the manifest the loader activates for the
    // imports of the object, which it searches before the standard order:
    // the one of a module, or the process one for the executable (see
    // process_manifest).
    assemblies: Vec<sxs::Assembly>,
    // Whether the process starts with a manifest, the resource 1 or the
    // external file of the executable, which disables the '.local'
    // redirection.  The resource 2 of an executable is activated for its
    // imports, but does not count.
    manifest: bool,
    // The RT_MANIFEST resource the process starts with, when the object is
    // the executable.
    process_manifest: Option<Vec<sxs::Assembly>>,
    // Whether the object is an IL only .NET image that runs on any CPU.
    any_cpu: bool,
}

// The RT_MANIFEST resource IDs the loader reads, from winuser.h.  Resource 3
// (ISOLATIONAWARE_NOSTATICIMPORT_MANIFEST_RESOURCE_ID) is only activated by
// the isolation aware wrappers, never for the static imports.
const CREATEPROCESS_MANIFEST_RESOURCE_ID: u16 = 1;
const ISOLATIONAWARE_MANIFEST_RESOURCE_ID: u16 = 2;

const SIDE_BY_SIDE_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide";
const IMAGE_FILE_EXECUTION_OPTIONS_KEY: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

// The resolution context: the system state the loader consults before the search order,
// along with the command line settings.
pub struct PeContext {
    apiset: apiset::ApiSetMap,
    knowndlls: knowndlls::KnownDlls,
    // The known DLL sections of the native, the x86 and the 32 bit ARM
    // images, built on first use.
    known_sections: [OnceCell<HashSet<String>>; 3],
    winsxs: sxs::WinSxs,
    windows_dir: String,
    safe_search: bool,
    // The PreferExternalManifest value, which puts the external manifest of
    // an executable before the embedded one.
    prefer_external_manifest: bool,
    // The DevOverrideEnable value, which keeps the '.local' redirection for
    // an executable with a manifest.
    dev_override: bool,
    // The machine the native processes run as.
    native_machine: pe::Machine,
    dll_directory: search_path::SearchPathVec,
    all: bool,
    verbose: bool,
    depth: usize,
    ignore_prefix: Vec<String>,
}

pub fn create_context(opts: &crate::Options) -> Result<PeContext, String> {
    Ok(PeContext {
        dll_directory: search_path::from_string(&opts.library_path, &[search_path::LIST_SEPARATOR]),
        all: opts.all,
        verbose: opts.verbose,
        depth: opts.depth,
        ignore_prefix: opts.ignore_prefix.clone(),
        ..PeContext::new(!opts.no_safe_search)
    })
}

impl PeContext {
    // The system state, with the default settings.
    fn new(safe_search: bool) -> Self {
        let windows_dir = search_dirs::windows_dir();
        let apiset = apiset::load(&search_dirs::system_dir(&windows_dir, Wow64::Native));
        let native_machine = native_machine(&windows_dir);
        Self {
            apiset,
            knowndlls: knowndlls::load(),
            known_sections: Default::default(),
            winsxs: sxs::WinSxs::new(&windows_dir),
            windows_dir,
            safe_search,
            prefer_external_manifest: registry::dword(SIDE_BY_SIDE_KEY, "PreferExternalManifest")
                .is_some_and(|value| value != 0),
            dev_override: registry::dword(IMAGE_FILE_EXECUTION_OPTIONS_KEY, "DevOverrideEnable")
                .is_some_and(|value| value != 0),
            native_machine,
            dll_directory: search_path::SearchPathVec::new(),
            all: false,
            verbose: false,
            depth: 1,
            ignore_prefix: Vec::new(),
        }
    }

    // The directories the known DLLs are resolved from.  The registry values
    // are gone on the recent Windows versions, where the loader creates the
    // known DLLs from the system directories.
    fn knowndll_dirs(&self, wow64: Wow64) -> Vec<String> {
        let dir = match wow64 {
            Wow64::Native => self.knowndlls.directory(false),
            Wow64::X86 => self.knowndlls.directory(true),
            Wow64::Arm32 => None,
        };
        match dir {
            Some(dir) => vec![dir.to_string()],
            None => search_dirs::system_dirs(&self.windows_dir, wow64),
        }
    }

    // The known DLL sections for an image, built the way smss does from the
    // registry list and the static imports of the modules on the known DLLs
    // directory.
    fn known_dlls(&self, wow64: Wow64) -> &HashSet<String> {
        self.known_sections[wow64 as usize].get_or_init(|| {
            let dirs = self.knowndll_dirs(wow64);
            knowndlls::sections(self.knowndlls.names(), |name| {
                let deps = dirs
                    .iter()
                    .find_map(|dir| static_import_modules(&Path::new(dir).join(name)))?;
                Some(
                    deps.into_iter()
                        .filter_map(|dep| match self.apiset.resolve(&dep, name) {
                            Some("") => None,
                            Some(host) => Some(host.to_string()),
                            None => Some(dep),
                        })
                        .collect(),
                )
            })
        })
    }

    fn is_known_dll(&self, name: &str, wow64: Wow64) -> bool {
        self.known_dlls(wow64).contains(&name.to_lowercase())
    }
}

struct Config<'a> {
    ctx: &'a PeContext,
    dirs: search_dirs::SearchDirs,
    // The '.local' DLL redirection directory, searched first when present.
    redirect: search_dirs::SearchDirs,
    machine: pe::Machine,
    all: bool,
    depth: usize,
    ignore_prefix: &'a [String],
}

pub fn resolve_binary(ctx: &mut PeContext, arg: &str) -> Result<DepTree, std::io::Error> {
    let ctx: &PeContext = ctx;
    let canonical = Path::new(arg).canonicalize()?;
    let filename = pathutils::strip_verbatim(&canonical.to_string_lossy());
    let filename = Path::new(&filename);
    let pei = open_object(ctx, &filename, true)?;

    let application = pathutils::get_path(&filename);
    let dirs = search_dirs::build(
        application.as_deref(),
        &ctx.dll_directory,
        &ctx.windows_dir,
        Wow64::of(pei.machine),
        ctx.safe_search,
    );

    if ctx.verbose {
        print_object_information(ctx, filename, &pei, &dirs);
    }

    let redirect = dot_local(ctx, filename, application.as_deref(), &pei);

    let mut deptree = DepTree::new();
    let depp = deptree.addroot(DepNode::new(
        application,
        pathutils::get_name(&filename),
        DepMode::Executable,
    ));

    let config = Config {
        ctx,
        dirs,
        redirect,
        machine: pei.machine,
        all: ctx.all,
        depth: ctx.depth,
        ignore_prefix: &ctx.ignore_prefix,
    };
    resolve_dependencies(&config, &pei, &mut deptree, depp);

    Ok(deptree)
}

fn print_object_information(
    ctx: &PeContext,
    filename: &Path,
    pei: &PeInfo,
    dirs: &search_dirs::SearchDirs,
) {
    let mut lines = vec![format!("{}: object information", filename.display())];
    lines.push(format!(
        "  machine: {}{}",
        machine::name(pei.machine),
        if pei.any_cpu {
            " (IL only, any CPU)"
        } else {
            ""
        }
    ));
    lines.push(format!(
        "  subsystem: {}",
        machine::subsystem_name(pei.subsystem)
    ));
    lines.push(format!("  image base: {:#x}", pei.image_base));
    lines.push(format!(
        "  type: {}",
        if pei.is_dll { "dll" } else { "executable" }
    ));
    lines.push(format!(
        "  api set schema: {}",
        if ctx.apiset.is_empty() {
            format!("not found (version {})", ctx.apiset.version())
        } else {
            format!("{} sets", ctx.apiset.len())
        }
    ));
    lines.push(format!(
        "  known dlls: {} modules",
        ctx.known_dlls(Wow64::of(pei.machine)).len()
    ));
    lines.push(format!(
        "  winsxs: {}",
        if ctx.winsxs.is_empty() {
            "not found".to_string()
        } else {
            format!("{} assemblies", ctx.winsxs.len())
        }
    ));
    lines.push(format!(
        "  safe dll search mode: {}",
        if ctx.safe_search {
            "enabled"
        } else {
            "disabled"
        }
    ));
    for assembly in &pei.assemblies {
        let dir = ctx.winsxs.resolve(assembly, pei.machine);
        lines.push(format!(
            "  side-by-side: {} ({})",
            assembly.name,
            dir.unwrap_or_else(|| "not found".to_string())
        ));
    }
    for (dir, mode) in dirs {
        lines.push(format!("  search path: {} {mode}", dir.path));
    }
    outln!("{}", lines.join("\n"));
}

// The '.local' redirection of the executable, which the loader ignores when
// the process starts with a manifest unless the DevOverrideEnable value is
// set, as https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection
// documents.  An executable whose only manifest is the resource 2 still has
// it (checked on Windows 11 24H2).
fn dot_local(
    ctx: &PeContext,
    filename: &Path,
    application: Option<&str>,
    pei: &PeInfo,
) -> search_dirs::SearchDirs {
    match pei.manifest && !ctx.dev_override {
        true => search_dirs::SearchDirs::new(),
        false => dot_local_dirs(filename, application),
    }
}

// When a '<object>.local' directory exists the dependencies are taken from it, and
// when it is a plain file they are taken from the application directory.
fn dot_local_dirs(filename: &Path, application: Option<&str>) -> search_dirs::SearchDirs {
    let mut dirs = search_dirs::SearchDirs::new();
    let local = format!("{}.local", filename.to_string_lossy());
    let Ok(meta) = fs::metadata(&local) else {
        return dirs;
    };
    let dir = match meta.is_dir() {
        true => Some(local.as_str()),
        false => application,
    };
    if let Some(dir) = dir {
        search_dirs::add(&mut dirs, dir, DepMode::DllRedirection);
    }
    dirs
}

// A pending dependency to resolve, along the base name of the module that
// imports it (which selects the api set alias) and its tree level.
struct WorkItem {
    dep: PeDep,
    importing: String,
    // The directories the loading chain redirects to, searched before the
    // loaded module list.
    redirect: search_dirs::SearchDirs,
    depp: usize,
    level: usize,
}

// The side-by-side directories of an object, added to the ones it inherits
// from the loading chain.
fn assembly_dirs(
    config: &Config,
    inherited: &search_dirs::SearchDirs,
    assemblies: &[sxs::Assembly],
) -> search_dirs::SearchDirs {
    let mut dirs = inherited.clone();
    for dir in sxs_dirs(config.ctx, assemblies, config.machine) {
        search_dirs::add(&mut dirs, &dir, DepMode::SideBySide);
    }
    dirs
}

fn sxs_dirs(ctx: &PeContext, assemblies: &[sxs::Assembly], machine: pe::Machine) -> Vec<String> {
    assemblies
        .iter()
        .filter_map(|assembly| ctx.winsxs.resolve(assembly, machine))
        .collect()
}

// Resolve the dependencies in breadth-first orde: a module is loaded once
// and attributed to the first importer, and the search order is the one of
// the application (not of the importing module).
fn resolve_dependencies(config: &Config, root: &PeInfo, deptree: &mut DepTree, root_depp: usize) {
    let root_name = deptree.arena[root_depp].val.name.clone();
    let root_sxs = assembly_dirs(config, &config.redirect, &root.assemblies);

    // The objects already parsed, so a module shared by several importers is
    // only read once, and the forwarders already queued for them.
    let mut cache = HashMap::<String, PeInfo>::new();
    let mut forwarded = HashSet::<(usize, String)>::new();

    let mut queue = VecDeque::new();
    for dep in &root.deps {
        queue.push_back(WorkItem {
            dep: dep.clone(),
            importing: root_name.clone(),
            redirect: root_sxs.clone(),
            depp: root_depp,
            level: 1,
        });
    }

    while let Some(item) = queue.pop_front() {
        // The api set names are virtual, where the loader redirects them to the
        // module that implements them before any other check.
        let (name, alias) = match config.ctx.apiset.resolve(&item.dep.name, &item.importing) {
            Some(host) if !host.is_empty() => (host.to_string(), Some(item.dep.name.clone())),
            Some(_) => {
                add_not_found(
                    config,
                    &item,
                    deptree,
                    vec!["api set schema (no host)".to_string()],
                    false,
                );
                continue;
            }
            None => (item.dep.name.clone(), None),
        };

        if ignored(config, &name) {
            continue;
        }

        // A recorded name with a path component resolves to the module FILE
        // names, and is printed as an alias of it.  The '.local' redirection
        // takes its base name, but the side-by-side one does not apply to it
        // (with a manifest asking for the common controls version 6, an
        // import of 'C:\Windows\System32\comctl32.dll' still maps version
        // 5.82).
        let file = pathutils::get_name(&Path::new(&name));
        let path_name = file != name;
        let alias = match path_name {
            true => Some(item.dep.name.clone()),
            false => alias,
        };

        // The redirection comes before the loaded-module list, so the same
        // name may be loaded from more than one assembly.
        let mut searched = Vec::new();
        let redirect_dirs = item
            .redirect
            .iter()
            .filter(|(_, mode)| !path_name || *mode == DepMode::DllRedirection)
            .map(|(dir, mode)| (dir.path.as_str(), *mode));
        let Ok(redirect) = find_in(config, &file, redirect_dirs, &mut searched) else {
            add_not_found(config, &item, deptree, searched, true);
            continue;
        };

        // A plain name is checked against the loaded modules before the
        // search order, while one with a path component is only known once
        // resolved, since the loader compares the full path then.
        let mut found = match redirect {
            Some(found) => Some(found),
            None if path_name => match find_dependency(config, &name, &mut searched) {
                Ok(Some(found)) => Some(found),
                result => {
                    add_not_found(config, &item, deptree, searched, result.is_err());
                    continue;
                }
            },
            None => None,
        };
        let lookup = match &found {
            Some((_, dir, _)) => pathutils::join(dir, &file),
            None => name.clone(),
        };

        if let Some(index) = deptree.index(&lookup) {
            let entry = deptree.arena[index].val.clone();
            deptree.add_repeated(
                config.all,
                // The name this entry records, which only matches the one
                // already on the tree without regard to case.
                DepNode::repeat_of(&entry, file.clone())
                    .with_alias(alias)
                    .with_attrs(item.dep.attrs.clone()),
                item.depp,
            );

            // The module was resolved through another object, so the
            // forwarders of the symbols only this one imports are still
            // pending; they belong to the module already on the tree.
            if config.depth != 0 && item.level >= config.depth {
                continue;
            }
            let Some(exports) = module_exports(&entry, &mut cache) else {
                continue;
            };
            for module in forwarded_modules(&item.dep.imports, exports) {
                if !forwarded.insert((index, module.to_lowercase())) {
                    continue;
                }
                queue.push_back(WorkItem {
                    dep: PeDep {
                        name: module,
                        attrs: vec!["forwarded"],
                        imports: Vec::new(),
                    },
                    importing: entry.name.clone(),
                    redirect: item.redirect.clone(),
                    // The forwarded module is a dependency of the module
                    // already on the tree, not of the current importer.
                    depp: index,
                    level: item.level + 1,
                });
            }
            continue;
        }

        let found = match found.take() {
            Some(found) => Ok(Some(found)),
            None => find_dependency(config, &name, &mut searched),
        };
        let (info, dir, mode) = match found {
            Ok(Some(found)) => found,
            result => {
                add_not_found(config, &item, deptree, searched, result.is_err());
                continue;
            }
        };

        let resolved = pathutils::join(&dir, &file);
        if ignored(config, &resolved) {
            continue;
        }

        let depd = deptree.addnode(
            DepNode::new(Some(dir), file.clone(), mode)
                .with_alias(alias)
                .with_attrs(item.dep.attrs.clone()),
            item.depp,
        );

        if config.depth != 0 && item.level >= config.depth {
            continue;
        }
        let sxs = assembly_dirs(config, &item.redirect, &info.assemblies);
        for dep in &info.deps {
            queue.push_back(WorkItem {
                dep: dep.clone(),
                importing: file.clone(),
                redirect: sxs.clone(),
                depp: depd,
                level: item.level + 1,
            });
        }
        // An imported symbol that resolves to a forwarded export pulls in the
        // module it points at, which no import directory records.
        for module in forwarded_modules(&item.dep.imports, &info) {
            queue.push_back(WorkItem {
                dep: PeDep {
                    name: module,
                    attrs: vec!["forwarded"],
                    imports: Vec::new(),
                },
                importing: file.clone(),
                redirect: sxs.clone(),
                depp: depd,
                level: item.level + 1,
            });
        }
    }
}

// The parsed object of a module already on the tree.
fn module_exports<'a>(
    entry: &DepNode,
    cache: &'a mut HashMap<String, PeInfo>,
) -> Option<&'a PeInfo> {
    let path = entry.path.as_ref()?;
    let resolved = Path::new(path).join(&entry.name);
    let key = resolved.to_string_lossy().to_lowercase();
    if !cache.contains_key(&key) {
        cache.insert(key.clone(), open_pe_file(&resolved).ok()?);
    }
    cache.get(&key)
}

// The modules the imported symbols are forwarded to, skipping the ones the
// import directory already records.
fn forwarded_modules(imports: &[ImportName], info: &PeInfo) -> Vec<String> {
    let mut modules = Vec::<String>::new();
    for import in imports {
        let ExportLookup::Forwarded(module) = info.exports.lookup(import) else {
            continue;
        };
        if info
            .deps
            .iter()
            .any(|dep| dep.name.eq_ignore_ascii_case(module))
            || modules.iter().any(|seen| seen.eq_ignore_ascii_case(module))
        {
            continue;
        }
        modules.push(module.to_string());
    }
    modules
}

// Check that every imported symbol is exported by the module it is imported
// from, the PE equivalent of processing the ELF relocations.  DELAY_LOAD also
// checks the delay load imports, which the loader only binds on the first
// call.
//
// There is no check for unused dependencies: an import directory only records
// a module when a symbol is imported from it.
pub fn check_imports(ctx: &PeContext, deptree: &DepTree, delay_load: bool) -> Vec<UndefinedSymbol> {
    let mut undefined = Vec::new();
    let mut cache = HashMap::<String, PeExports>::new();

    for (index, node) in deptree.arena.iter().enumerate() {
        // The duplicated and the not found entries hold no imports.
        let Some(path) = &node.val.path else {
            continue;
        };
        if node.val.found {
            continue;
        }
        let Ok(info) = open_object(ctx, &Path::new(path).join(&node.val.name), index == 0) else {
            continue;
        };

        let sxs = sxs_dirs(ctx, &info.assemblies, info.machine);

        for dep in &info.deps {
            if !delay_load && dep.is_delay_load() {
                continue;
            }

            // The api set names are virtual, the imports are checked against
            // the module that implements them.
            let name = match ctx.apiset.resolve(&dep.name, &node.val.name) {
                Some(host) if !host.is_empty() => host.to_string(),
                // Already reported as not found by the resolution.
                Some(_) => continue,
                None => dep.name.clone(),
            };
            // The child node records the module this object resolved to,
            // which a side-by-side redirection may make differ from the one
            // the loaded-module list holds.  The redirection is redone when
            // the child was resolved through another object.
            let target = node
                .children
                .iter()
                .map(|child| &deptree.arena[*child].val)
                .find(|child| {
                    // A name with a path component is recorded as the alias.
                    child.name.eq_ignore_ascii_case(&name)
                        || child
                            .alias
                            .as_ref()
                            .is_some_and(|alias| alias.eq_ignore_ascii_case(&name))
                })
                .cloned()
                .or_else(|| {
                    sxs.iter()
                        .find_map(|dir| deptree.get(&pathutils::join(dir, &name)))
                })
                .or_else(|| deptree.get(&name));
            let Some(target) = target else {
                continue;
            };
            let Some(target_path) = &target.path else {
                continue;
            };

            let resolved = Path::new(target_path).join(&target.name);
            let key = resolved.to_string_lossy().to_lowercase();
            if !cache.contains_key(&key) {
                let Ok(target_info) = open_pe_file(&resolved) else {
                    continue;
                };
                cache.insert(key.clone(), target_info.exports);
            }
            let exports = &cache[&key];

            for import in &dep.imports {
                if matches!(exports.lookup(import), ExportLookup::Missing) {
                    undefined.push(UndefinedSymbol {
                        name: import.to_string(),
                        object: node.val.name.clone(),
                        version: None,
                        from: Some(target.name.clone()),
                    });
                }
            }
        }
    }

    undefined
}

fn ignored(config: &Config, path: &str) -> bool {
    pathutils::has_prefix(path, config.ignore_prefix)
}

// A dependency the load fails on, printed as not found.  A BAD_IMAGE one found
// a candidate the loader could not map, which the last SEARCHED entry names.
fn add_not_found(
    config: &Config,
    item: &WorkItem,
    deptree: &mut DepTree,
    searched: Vec<String>,
    bad_image: bool,
) {
    if ignored(config, &item.dep.name) {
        return;
    }
    let mut attrs = item.dep.attrs.clone();
    if bad_image {
        attrs.push("bad image");
    }
    deptree.addnode(
        DepNode::not_found(item.dep.name.clone(), searched).with_attrs(attrs),
        item.depp,
    );
}

// A module the search found: the parsed object, the directory it was found at,
// and the mode of that directory.
type Found = (PeInfo, String, DepMode);

// A candidate that stops the search, since the loader fails the load on it.
struct BadImage;

// The outcome of a search, Ok(None) when no directory holds the module.
type Search = Result<Option<Found>, BadImage>;

// Search NAME on each of the DIRS in order, recording every candidate path on
// SEARCHED.
fn find_in<'d>(
    config: &Config,
    name: &str,
    dirs: impl IntoIterator<Item = (&'d str, DepMode)>,
    searched: &mut Vec<String>,
) -> Search {
    for (dir, mode) in dirs {
        let candidate = Path::new(dir).join(name);
        let path = candidate.to_string_lossy().into_owned();
        match try_open(config, &candidate) {
            Candidate::Found(info) => {
                searched.push(path);
                return Ok(Some((info, dir.to_string(), mode)));
            }
            Candidate::Skipped => searched.push(path),
            Candidate::Bad(reason) => {
                searched.push(format!("{path} (bad image: {reason})"));
                return Err(BadImage);
            }
        }
    }
    Ok(None)
}

fn find_in_dirs(
    config: &Config,
    name: &str,
    dirs: &search_dirs::SearchDirs,
    searched: &mut Vec<String>,
) -> Search {
    let dirs = dirs.iter().map(|(dir, mode)| (dir.path.as_str(), *mode));
    find_in(config, name, dirs, searched)
}

// The directory and the file name PATH names, without the '.' components.
fn split_path(path: &Path) -> Option<(String, String)> {
    let path: std::path::PathBuf = path
        .components()
        .filter(|component| *component != std::path::Component::CurDir)
        .collect();
    Some((pathutils::get_path(&path)?, pathutils::get_name(&path)))
}

// Resolve NAME against the known DLLs and then the search directories, returning th
// parsed object, the directory it was found at, and the mode.  A known DLL is
// taken from the known DLLs directory whoever imports it, while any other
// module, even one a known DLL pulls in through a forwarder or a delay load
// import, follows the search order (the loader maps an application copy of
// CRYPTBASE, which advapi32 forwards SystemFunction001 to).
fn find_dependency(config: &Config, name: &str, searched: &mut Vec<String>) -> Search {
    // A recorded name with a path component is taken as it is when it starts
    // at a root or a drive, and searched below each directory of the order
    // otherwise, even when it starts with '.\'.  With 'p\my.dll' imported,
    // the loader maps app\p\my.dll, or dir\p\my.dll for a PATH directory.
    if name.contains(['\\', '/']) {
        let path = Path::new(name);
        let candidates: Vec<(std::path::PathBuf, DepMode)> = match path.components().next() {
            Some(std::path::Component::Prefix(_) | std::path::Component::RootDir) => {
                vec![(path.to_path_buf(), DepMode::Direct)]
            }
            _ => config
                .dirs
                .iter()
                .map(|(dir, mode)| (Path::new(&dir.path).join(path), *mode))
                .collect(),
        };
        for (candidate, mode) in candidates {
            let Some((dir, file)) = split_path(&candidate) else {
                continue;
            };
            if let Some(found) = find_in(config, &file, [(dir.as_str(), mode)], searched)? {
                return Ok(Some(found));
            }
        }
        return Ok(None);
    }

    if config.ctx.is_known_dll(name, Wow64::of(config.machine)) {
        let known = config.ctx.knowndll_dirs(Wow64::of(config.machine));
        let known = known.iter().map(|dir| (dir.as_str(), DepMode::LdCache));
        if let Some(found) = find_in(config, name, known, searched)? {
            return Ok(Some(found));
        }
    }

    find_in_dirs(config, name, &config.dirs, searched)
}

enum Candidate {
    Found(PeInfo),
    Skipped,
    // Why the loader fails the load on it.
    Bad(String),
}

// The loader skips a missing candidate and one built for another machine and
// keeps searching (which is what tells the System32 and SysWOW64 modules
// apart), but it fails the load on any other one: a file that is not an
// image, a truncated or an empty one, or a directory by that name stop the
// search (with STATUS_INVALID_IMAGE_NOT_MZ, STATUS_INVALID_IMAGE_FORMAT,
// STATUS_INVALID_FILE_FOR_SECTION and STATUS_FILE_IS_A_DIRECTORY on Windows
// 11 24H2), even with a valid copy further on the order.
fn try_open(config: &Config, path: &Path) -> Candidate {
    match open_pe_file(&path) {
        Ok(info) if machine::compatible(config.machine, info.machine) => Candidate::Found(info),
        Ok(_) => Candidate::Skipped,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Candidate::Skipped,
        Err(_) if path.is_dir() => Candidate::Bad("a directory".to_string()),
        Err(err) => Candidate::Bad(err.to_string()),
    }
}

// Open FILENAME, which is the object given on the command line when ROOT is
// set, and then an executable starts the process with its manifest.
fn open_object<P: AsRef<Path>>(
    ctx: &PeContext,
    filename: &P,
    root: bool,
) -> Result<PeInfo, std::io::Error> {
    let mut pei = open_pe_file(filename)?;
    if root && !pei.is_dll {
        process_manifest(ctx, filename.as_ref(), &mut pei);
    }
    // The system loads an IL only image that does not ask for a 32 bit
    // process as a native one, converting its PE32 header on the fly
    // (mageui.exe runs as a 64 bit process and maps System32\mscoree.dll).
    if root && pei.any_cpu {
        pei.machine = ctx.native_machine;
    }
    Ok(pei)
}

// The machine of the system ntdll, which is the one a native process runs as:
// ARM64 on Windows on ARM, even when rldd itself runs emulated there.
fn native_machine(windows_dir: &str) -> pe::Machine {
    let ntdll = Path::new(&search_dirs::system_dir(windows_dir, Wow64::Native)).join("ntdll.dll");
    let machine = pathutils::map_file(&ntdll).ok().and_then(|mmap| {
        let file = PeFile::<pe::ImageNtHeaders64>::parse(&*mmap).ok()?;
        Some(file.nt_headers().file_header().machine.get(LE))
    });
    machine.unwrap_or(match cfg!(target_arch = "aarch64") {
        true => pe::IMAGE_FILE_MACHINE_ARM64,
        false => pe::IMAGE_FILE_MACHINE_AMD64,
    })
}

// The manifest of the process an executable starts, which replaces the module
// one: the RT_MANIFEST resource 1, then the external '<name>.exe.manifest',
// and at last the resource 2 a module would use.  Only one of them is
// activated, so a dependency the chosen one does not declare is not taken
// from the others.  The PreferExternalManifest value puts the external file
// first, which is the Windows XP precedence.  Checked on Windows 11 with an
// executable importing comctl32 and a manifest asking for its version 6 on
// each place, alone and along with another one that does not.
fn process_manifest(ctx: &PeContext, filename: &Path, pei: &mut PeInfo) {
    let external = || {
        let external = format!("{}.manifest", filename.to_string_lossy());
        fs::read(external)
            .ok()
            .map(|manifest| sxs::parse_manifest(&manifest))
    };
    let manifest = match ctx.prefer_external_manifest {
        false => pei.process_manifest.take().or_else(external),
        true => external().or_else(|| pei.process_manifest.take()),
    };
    if let Some(assemblies) = manifest {
        pei.assemblies = assemblies;
        pei.manifest = true;
    }
}

// Open FILENAME as a module, whose manifest is only its RT_MANIFEST resource
// 2: the loader reads no external file for a DLL, and ignores the resource 1
// and 3 of one.
fn open_pe_file<P: AsRef<Path>>(filename: &P) -> Result<PeInfo, std::io::Error> {
    let mmap = pathutils::map_file(filename)?;
    parse_object(&mmap).map_err(Error::other)
}

// The modules the import directory of FILENAME names, without parsing the
// rest of the object, which is all the known DLL sections need.
fn static_import_modules(filename: &Path) -> Option<Vec<String>> {
    fn modules<Pe: ImageNtHeaders>(data: &[u8]) -> Option<Vec<String>> {
        let file = PeFile::<Pe>::parse(data).ok()?;
        let mut modules = Vec::new();
        if let Ok(Some(table)) = file.import_table() {
            if let Ok(mut descriptors) = table.descriptors() {
                while let Ok(Some(descriptor)) = descriptors.next() {
                    if let Some(name) = rva_name(&file, descriptor.name.get(LE)) {
                        modules.push(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
        }
        Some(modules)
    }

    let mmap = pathutils::map_file(&filename).ok()?;
    match FileKind::parse(&*mmap).ok()? {
        FileKind::Pe32 => modules::<pe::ImageNtHeaders32>(&mmap),
        FileKind::Pe64 => modules::<pe::ImageNtHeaders64>(&mmap),
        _ => None,
    }
}

fn parse_object(data: &[u8]) -> Result<PeInfo, &'static str> {
    match FileKind::parse(data).map_err(|_| "failed to parse the object")? {
        FileKind::Pe32 => parse_pe::<pe::ImageNtHeaders32>(data),
        FileKind::Pe64 => parse_pe::<pe::ImageNtHeaders64>(data),
        _ => Err("not a PE object"),
    }
}

fn parse_pe<Pe: ImageNtHeaders>(data: &[u8]) -> Result<PeInfo, &'static str> {
    let file = PeFile::<Pe>::parse(data).map_err(|_| "failed to parse the PE object")?;
    let headers = file.nt_headers();

    let mut pei = PeInfo {
        machine: image_machine(&file),
        subsystem: headers.optional_header().subsystem(),
        image_base: headers.optional_header().image_base(),
        is_dll: headers.file_header().characteristics.get(LE).0 & pe::IMAGE_FILE_DLL.0 != 0,
        deps: Vec::new(),
        exports: PeExports::default(),
        assemblies: Vec::new(),
        manifest: false,
        process_manifest: None,
        any_cpu: !headers.is_type_64()
            && headers.file_header().machine.get(LE) == pe::IMAGE_FILE_MACHINE_I386
            && il_any_cpu(&file),
    };

    if let Ok(Some(table)) = file.import_table() {
        if let Ok(mut descriptors) = table.descriptors() {
            while let Ok(Some(descriptor)) = descriptors.next() {
                if let Some(name) = rva_name(&file, descriptor.name.get(LE)) {
                    // The import name table holds the names, and is only
                    // absent on the old bound objects.
                    let thunks = match descriptor.original_first_thunk.get(LE) {
                        0 => descriptor.first_thunk.get(LE),
                        rva => rva,
                    };
                    // A non zero timestamp means the imports were bound at
                    // link time.
                    let mut attrs = Vec::new();
                    if descriptor.time_date_stamp.get(LE) != 0 {
                        attrs.push("bound");
                    }
                    pei.deps.push(PeDep {
                        name: String::from_utf8_lossy(name).into_owned(),
                        attrs,
                        imports: import_names::<Pe>(&file, thunks),
                    });
                }
            }
        }
    }

    // The delay load imports are only resolved on the first call.
    if let Ok(Some(table)) = file.delay_load_import_table() {
        if let Ok(mut descriptors) = table.descriptors() {
            while let Ok(Some(descriptor)) = descriptors.next() {
                if let Some(name) = rva_name(&file, descriptor.dll_name_rva.get(LE)) {
                    pei.deps.push(PeDep {
                        name: String::from_utf8_lossy(name).into_owned(),
                        attrs: vec!["delay-load"],
                        imports: import_names::<Pe>(
                            &file,
                            descriptor.import_name_table_rva.get(LE),
                        ),
                    });
                }
            }
        }
    }

    if let Ok(Some(table)) = file.export_table() {
        pei.exports = parse_exports(&table);
    }

    if let Some(manifest) = manifest_resource(&file, ISOLATIONAWARE_MANIFEST_RESOURCE_ID) {
        pei.assemblies = sxs::parse_manifest(manifest);
    }
    if !pei.is_dll {
        pei.process_manifest =
            manifest_resource(&file, CREATEPROCESS_MANIFEST_RESOURCE_ID).map(sxs::parse_manifest);
    }

    Ok(pei)
}

// Whether the CLR header flags an IL only image that does not ask for a 32 bit
// process: the 'Any CPU' platform target of a .NET program, without 'Prefer
// 32-bit', whose PE32 header records i386 all the same.
fn il_any_cpu<Pe: ImageNtHeaders>(file: &PeFile<Pe>) -> bool {
    let Some(directory) = file
        .data_directories()
        .get(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
    else {
        return false;
    };
    let Ok(data) = directory.data(file.data(), &file.section_table()) else {
        return false;
    };
    let Ok((header, _)) = object::pod::from_bytes::<pe::ImageCor20Header>(data) else {
        return false;
    };
    let flags = header.flags.get(LE).0;
    let wants_32bit = pe::COMIMAGE_FLAGS_32BITREQUIRED.0 | pe::COMIMAGE_FLAGS_32BITPREFERRED.0;
    flags & pe::COMIMAGE_FLAGS_ILONLY.0 != 0 && flags & wants_32bit == 0
}

// An ARM64X object holds an ARM64 and an x86_64 view at once, and the file
// header only records the primary one. Most of System32 records ARM64, while
// a handful of modules (the .NET shim and the x64 redistributables among
// them) record AMD64.  On both cases the second view only shows on the CHPE
// metadata, so reading it is what lets the machine check take the module from
// both sides.
fn image_machine<Pe: ImageNtHeaders>(file: &PeFile<Pe>) -> pe::Machine {
    let machine = file.nt_headers().file_header().machine.get(LE);
    let hybrid = matches!(
        machine,
        pe::IMAGE_FILE_MACHINE_ARM64 | pe::IMAGE_FILE_MACHINE_AMD64
    );
    if hybrid && has_chpe_metadata(file) {
        return pe::IMAGE_FILE_MACHINE_ARM64X;
    }
    machine
}

// Whether the load configuration directory points at the CHPE metadata.  The
// directory grew over the Windows releases and its first field records how
// much of it the object holds, so the pointer is only read when it covers it.
// Only the 64 bit layout is read, which is the one both the ARM64 and the
// x86_64 objects have; a 32 bit directory never reaches the offset below, so
// it reports no metadata.
fn has_chpe_metadata<Pe: ImageNtHeaders>(file: &PeFile<Pe>) -> bool {
    const OFFSET: usize =
        std::mem::offset_of!(pe::ImageLoadConfigDirectory64, chpe_metadata_pointer);
    const END: usize = OFFSET + std::mem::size_of::<u64>();

    let sections = file.section_table();
    let Some(directory) = file
        .data_directories()
        .get(pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
    else {
        return false;
    };
    let Ok(data) = directory.data(file.data(), &sections) else {
        return false;
    };
    let Some(size) = data.get(..4) else {
        return false;
    };
    let size = u32::from_le_bytes(size.try_into().unwrap()) as usize;
    if size < END {
        return false;
    }
    let Some(pointer) = data.get(OFFSET..END) else {
        return false;
    };
    u64::from_le_bytes(pointer.try_into().unwrap()) != 0
}

// The embedded RT_MANIFEST resource ID, which declares the side-by-side
// assemblies the object depends on.
fn manifest_resource<'data, Pe: ImageNtHeaders>(
    file: &PeFile<'data, Pe>,
    id: u16,
) -> Option<&'data [u8]> {
    let sections = file.section_table();
    let directory = file
        .data_directories()
        .resource_directory(file.data(), &sections)
        .ok()??;

    // The resource tree is indexed by type, then by name, then by language.
    let types = directory.root().ok()?;
    let manifests = types
        .entries
        .iter()
        .find(|entry| entry.name_or_id().id() == Some(pe::RT_MANIFEST))?
        .data(directory)
        .ok()?
        .table()?;
    let languages = manifests
        .entries
        .iter()
        .find(|entry| entry.name_or_id().id() == Some(id))?
        .data(directory)
        .ok()?
        .table()?;
    let entry = languages.entries.first()?.data(directory).ok()?.data()?;

    let data = sections.pe_data_at(file.data(), entry.offset_to_data.get(LE))?;
    data.get(..entry.size.get(LE) as usize)
}

// The name and the thunk array a descriptor points at do not need to live on
// the section the directory itself does (the delay load descriptors on .didat
// with the names on .rdata are the usual case), so the addresses are resolved
// against the whole image.
fn rva_data<'data, Pe: ImageNtHeaders>(file: &PeFile<'data, Pe>, rva: u32) -> Option<&'data [u8]> {
    file.section_table().pe_data_at(file.data(), rva)
}

fn rva_name<'data, Pe: ImageNtHeaders>(file: &PeFile<'data, Pe>, rva: u32) -> Option<&'data [u8]> {
    let data = rva_data(file, rva)?;
    let end = data.iter().position(|byte| *byte == 0)?;
    Some(&data[..end])
}

fn import_names<Pe: ImageNtHeaders>(file: &PeFile<Pe>, rva: u32) -> Vec<ImportName> {
    let mut names = Vec::new();
    let Some(mut data) = rva_data(file, rva) else {
        return names;
    };
    while let Ok((thunk, rest)) = object::pod::from_bytes::<Pe::ImageThunkData>(data) {
        data = rest;
        if thunk.raw() == 0 {
            break;
        }
        if thunk.is_ordinal() {
            names.push(ImportName::Ordinal(thunk.ordinal()));
            continue;
        }
        // The thunk points at the hint/name entry, with the name following the
        // two bytes hint.
        let Some(name) = rva_name(file, thunk.address().wrapping_add(2)) else {
            break;
        };
        names.push(ImportName::Name(String::from_utf8_lossy(name).into_owned()));
    }
    names
}

fn parse_exports(table: &ExportTable) -> PeExports {
    let mut exports = PeExports::default();
    let Ok(list) = table.exports() else {
        return exports;
    };
    for export in list {
        let forward = match export.target {
            ExportTarget::ForwardByName(module, _) | ExportTarget::ForwardByOrdinal(module, _) => {
                Some(forward_module(module))
            }
            ExportTarget::Address(_) => None,
        };
        if let Some(name) = export.name {
            exports
                .names
                .insert(String::from_utf8_lossy(name).into_owned(), forward.clone());
        }
        exports.ordinals.insert(export.ordinal.0, forward);
    }
    exports
}

// The module of a forwarder string is recorded without the '.dll' suffix.  The
// suffix is checked on the bytes, which may not be valid UTF-8.
fn forward_module(module: &[u8]) -> String {
    let suffixed = module.len() > 4 && module[module.len() - 4..].eq_ignore_ascii_case(b".dll");
    let module = String::from_utf8_lossy(module).into_owned();
    match suffixed {
        true => module,
        false => format!("{module}.dll"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(depth: usize, ignore_prefix: &[String]) -> DepTree {
        let exe = std::env::current_exe().unwrap();
        let mut ctx = PeContext {
            depth,
            ignore_prefix: ignore_prefix.to_vec(),
            ..PeContext::new(true)
        };
        resolve_binary(&mut ctx, exe.to_str().unwrap()).unwrap()
    }

    // Resolving the test binary exercises the whole pipeline: the import
    // directory, the api set schema, the known DLLs, and the search order.
    #[test]
    fn resolve_test_binary() {
        let deptree = resolve(1, &[]);

        assert!(deptree.arena.len() > 1, "no dependency was resolved");
        for node in &deptree.arena {
            assert_ne!(node.val.mode, DepMode::NotFound, "{}", node.val.name);
            assert!(node.val.path.is_some(), "{} has no path", node.val.name);
        }

        // An object that runs resolves every dependency from the system.
        let system =
            search_dirs::system_dir(&search_dirs::windows_dir(), Wow64::Native).to_lowercase();
        assert!(
            deptree.arena[1..].iter().any(|node| node
                .val
                .path
                .as_ref()
                .is_some_and(|path| path.to_lowercase() == system)),
            "no dependency came from the system directory"
        );
    }

    #[test]
    fn depth_limits_the_tree() {
        let direct = resolve(1, &[]).arena.len();
        assert!(resolve(2, &[]).arena.len() >= direct);
        assert!(resolve(0, &[]).arena.len() >= direct);
    }

    #[test]
    fn ignore_prefix_prunes_the_tree() {
        let windows = search_dirs::windows_dir();
        let pruned = resolve(1, &[windows]);
        assert!(pruned.arena.len() < resolve(1, &[]).arena.len());
    }

    // Every symbol the test binary imports must be exported by the module it
    // is imported from, delay load ones included.
    #[test]
    fn imports_are_resolved() {
        let exe = std::env::current_exe().unwrap();
        let mut ctx = PeContext::new(true);
        let deptree = resolve_binary(&mut ctx, exe.to_str().unwrap()).unwrap();

        let undefined: Vec<String> = check_imports(&ctx, &deptree, true)
            .iter()
            .map(|undef| format!("{undef} ({})", undef.object))
            .collect();
        assert!(undefined.is_empty(), "{undefined:?}");
    }

    #[test]
    fn parse_the_test_binary() {
        let pei = open_pe_file(&std::env::current_exe().unwrap()).unwrap();
        assert!(!pei.is_dll);
        assert_ne!(pei.machine, pe::IMAGE_FILE_MACHINE_UNKNOWN);
        assert!(!pei.deps.is_empty());
        assert!(pei.deps.iter().all(|dep| !dep.name.is_empty()));
        assert!(pei.deps.iter().any(|dep| !dep.imports.is_empty()));
    }

    #[test]
    fn parse_a_system_library() {
        let system = search_dirs::system_dir(&search_dirs::windows_dir(), Wow64::Native);
        let pei = open_pe_file(&Path::new(&system).join("kernel32.dll")).unwrap();
        assert!(pei.is_dll);
        assert!(!pei.exports.names.is_empty());
        // A good part of the kernel32 exports is forwarded to ntdll.
        assert!(pei.exports.names.values().any(|module| module.is_some()));
    }

    // Windows on ARM builds the system modules as ARM64X, and reading the
    // hybrid metadata is what tells them from the plain ARM64 ones.
    // TODO: maybe change it if/when Windows does not sure ARM64X.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn system_modules_are_hybrid() {
        let system = search_dirs::system_dir(&search_dirs::windows_dir(), Wow64::Native);
        let pei = open_pe_file(&Path::new(&system).join("kernel32.dll")).unwrap();
        assert_eq!(pei.machine, pe::IMAGE_FILE_MACHINE_ARM64X);
        assert!(machine::compatible(
            pe::IMAGE_FILE_MACHINE_AMD64,
            pei.machine
        ));

        // A few hybrid modules record AMD64 on the file header instead of
        // ARM64, and an ARM64 image loads them all the same.
        if let Ok(pei) = open_pe_file(&Path::new(&system).join("mscoree.dll")) {
            assert_eq!(pei.machine, pe::IMAGE_FILE_MACHINE_ARM64X);
            assert!(machine::compatible(
                pe::IMAGE_FILE_MACHINE_ARM64,
                pei.machine
            ));
        }

        // No hybrid view on rldd itself.
        let pei = open_pe_file(&std::env::current_exe().unwrap()).unwrap();
        assert_eq!(pei.machine, pe::IMAGE_FILE_MACHINE_ARM64);
    }

    #[test]
    fn known_dlls_from_the_registry() {
        let ctx = PeContext::new(true);
        for wow64 in [Wow64::Native, Wow64::X86] {
            assert!(ctx.is_known_dll("KERNEL32.dll", wow64));
            // Not on the registry list, but imported by kernel32.
            assert!(ctx.is_known_dll("ntdll.dll", wow64));
            assert!(ctx.is_known_dll("KernelBase.dll", wow64));
            assert!(!ctx.is_known_dll("rldd-not-a-known.dll", wow64));
        }
        // The WOW64 layer only exists as 64 bit modules.
        let system = search_dirs::system_dir(&search_dirs::windows_dir(), Wow64::Native);
        if Path::new(&system).join("wow64.dll").exists() {
            assert!(ctx.is_known_dll("wow64.dll", Wow64::Native));
            assert!(!ctx.is_known_dll("wow64.dll", Wow64::X86));
        }
    }

    #[test]
    fn api_set_schema_from_the_system() {
        let system = search_dirs::system_dir(&search_dirs::windows_dir(), Wow64::Native);
        let schema = apiset::load(&system);
        assert!(!schema.is_empty());
        assert_eq!(schema.version(), 6);
        // A core set every supported Windows implements.
        let host = schema.resolve("api-ms-win-core-processthreads-l1-1-0.dll", "test.exe");
        assert!(matches!(host, Some(host) if !host.is_empty()), "{host:?}");
    }

    // The '.local' redirection points at the directory when one exists, and
    // at the application directory when it is a plain file.
    #[test]
    fn dot_local_redirection() {
        let dir = crate::tempdir::TempDir::new().unwrap();
        let exe = dir.path().join("app.exe");
        fs::write(&exe, b"").unwrap();
        let application = dir.path().to_string_lossy().into_owned();

        assert!(dot_local_dirs(&exe, Some(application.as_str())).is_empty());

        let local = dir.path().join("app.exe.local");
        fs::write(&local, b"").unwrap();
        let dirs = dot_local_dirs(&exe, Some(application.as_str()));
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].1, DepMode::DllRedirection);
        assert!(dirs[0].0.path.eq_ignore_ascii_case(&application));

        fs::remove_file(&local).unwrap();
        fs::create_dir(&local).unwrap();
        let dirs = dot_local_dirs(&exe, Some(application.as_str()));
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].0.path.to_lowercase().ends_with("app.exe.local"));
    }

    // A manifest asking for the NAME assembly.
    fn manifest(name: &str) -> Vec<u8> {
        format!(
            r#"<assembly><dependency><dependentAssembly>
            <assemblyIdentity name="{name}" version="1.0.0.0"/>
            </dependentAssembly></dependency></assembly>"#
        )
        .into_bytes()
    }

    // The assembly names the loader activates for the object FILE builds, laid
    // out as NAME with an external manifest asking for the 'external' one.
    fn activated(ctx: &PeContext, image: &testimage::Image, external: bool) -> Vec<String> {
        let dir = crate::tempdir::TempDir::new().unwrap();
        let name = if image.characteristics & pe::IMAGE_FILE_DLL.0 != 0 {
            "test.dll"
        } else {
            "test.exe"
        };
        let path = dir.path().join(name);
        fs::write(&path, image.build()).unwrap();
        if external {
            fs::write(
                dir.path().join(format!("{name}.manifest")),
                manifest("external"),
            )
            .unwrap();
        }
        let pei = open_object(ctx, &path, true).unwrap();
        pei.assemblies.into_iter().map(|a| a.name).collect()
    }

    // A DLL only has the RT_MANIFEST resource 2 activated, never the 1 or the
    // 3 one, nor an external file.
    #[test]
    fn module_manifest() {
        let ctx = PeContext::new(true);
        let one = manifest("one");
        let two = manifest("two");
        let three = manifest("three");

        let mut image = testimage::Image::dll(pe::IMAGE_FILE_MACHINE_AMD64, true);
        image.manifests(&[(1, &one), (2, &two), (3, &three)]);
        assert_eq!(activated(&ctx, &image, true), ["two"]);

        let mut image = testimage::Image::dll(pe::IMAGE_FILE_MACHINE_AMD64, true);
        image.manifests(&[(1, &one), (3, &three), (123, &three)]);
        assert!(activated(&ctx, &image, false).is_empty());
        assert!(activated(&ctx, &image, true).is_empty());
    }

    // An executable has the manifest of its process activated: the resource
    // 1, then the external file, then the resource 2.
    #[test]
    fn process_manifest_precedence() {
        let mut ctx = PeContext::new(true);
        let one = manifest("one");
        let two = manifest("two");
        let three = manifest("three");
        let exe = |manifests: &[(u16, &[u8])]| {
            let mut image = testimage::Image::exe(pe::IMAGE_FILE_MACHINE_AMD64, true);
            image.manifests(manifests);
            image
        };

        let both = exe(&[(1, &one), (2, &two)]);
        assert_eq!(activated(&ctx, &both, false), ["one"]);
        assert_eq!(activated(&ctx, &both, true), ["one"]);

        let module = exe(&[(2, &two)]);
        assert_eq!(activated(&ctx, &module, false), ["two"]);
        assert_eq!(activated(&ctx, &module, true), ["external"]);

        let isolation = exe(&[(3, &three)]);
        assert!(activated(&ctx, &isolation, false).is_empty());
        assert_eq!(activated(&ctx, &isolation, true), ["external"]);

        ctx.prefer_external_manifest = true;
        assert_eq!(activated(&ctx, &both, true), ["external"]);
        assert_eq!(activated(&ctx, &both, false), ["one"]);
    }

    // The '.local' redirection is ignored when the process starts with a
    // manifest, the resource 1 or the external file, unless DevOverrideEnable
    // is set.  The resource 2 of the executable does not count.
    #[test]
    fn dot_local_with_manifest() {
        let mut ctx = PeContext::new(true);
        ctx.dev_override = false;
        let plain = manifest("plain");
        let dir = crate::tempdir::TempDir::new().unwrap();
        let exe = dir.path().join("app.exe");
        let external = dir.path().join("app.exe.manifest");
        fs::create_dir(dir.path().join("app.exe.local")).unwrap();
        let application = dir.path().to_string_lossy().into_owned();

        let redirected = |ctx: &PeContext, manifests: &[(u16, &[u8])], with_external: bool| {
            let mut image = testimage::Image::exe(pe::IMAGE_FILE_MACHINE_AMD64, true);
            image.manifests(manifests);
            fs::write(&exe, image.build()).unwrap();
            match with_external {
                true => fs::write(&external, &plain).unwrap(),
                false => _ = fs::remove_file(&external),
            }
            let pei = open_object(ctx, &exe, true).unwrap();
            !dot_local(ctx, &exe, Some(application.as_str()), &pei).is_empty()
        };

        assert!(redirected(&ctx, &[], false));
        assert!(redirected(&ctx, &[(2, &plain)], false));
        assert!(redirected(&ctx, &[(3, &plain)], false));
        assert!(!redirected(&ctx, &[(1, &plain)], false));
        assert!(!redirected(&ctx, &[], true));

        ctx.dev_override = true;
        assert!(redirected(&ctx, &[(1, &plain)], false));
        assert!(redirected(&ctx, &[], true));
    }

    // A PE32 executable with a CLR header carrying FLAGS.
    fn clr_image(machine: pe::Machine, flags: u32) -> testimage::Image {
        let mut image = testimage::Image::exe(machine, false);
        let size = std::mem::size_of::<pe::ImageCor20Header>();
        let mut header = vec![0u8; size];
        header[..4].copy_from_slice(&(size as u32).to_le_bytes());
        header[16..20].copy_from_slice(&flags.to_le_bytes());
        image.directory(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &header);
        image
    }

    // Only an IL only image that asks for no 32 bit process runs as a native
    // one, and the others keep the machine their header records.
    #[test]
    fn clr_any_cpu() {
        let ctx = PeContext::new(true);
        let dir = crate::tempdir::TempDir::new().unwrap();
        let path = dir.path().join("app.exe");
        let machine = |image: testimage::Image| {
            fs::write(&path, image.build()).unwrap();
            open_object(&ctx, &path, true).unwrap().machine
        };
        let ilonly = pe::COMIMAGE_FLAGS_ILONLY.0;
        let required = pe::COMIMAGE_FLAGS_32BITREQUIRED.0;
        let preferred = pe::COMIMAGE_FLAGS_32BITPREFERRED.0;
        let i386 = pe::IMAGE_FILE_MACHINE_I386;

        assert_eq!(machine(clr_image(i386, ilonly)), ctx.native_machine);
        assert_eq!(Wow64::of(ctx.native_machine), Wow64::Native);
        assert_eq!(machine(clr_image(i386, ilonly | required)), i386);
        assert_eq!(
            machine(clr_image(i386, ilonly | required | preferred)),
            i386
        );
        assert_eq!(machine(clr_image(i386, ilonly | preferred)), i386);
        // A mixed mode image holds native code for its machine.
        assert_eq!(machine(clr_image(i386, 0)), i386);
        assert_eq!(
            machine(testimage::Image::exe(i386, false)),
            i386,
            "no CLR header"
        );

        // A dependency is not converted, only the object that starts the
        // process.
        fs::write(&path, clr_image(i386, ilonly).build()).unwrap();
        assert_eq!(open_pe_file(&path).unwrap().machine, i386);
    }

    fn config(ctx: &PeContext, machine: pe::Machine) -> Config<'_> {
        Config {
            ctx,
            dirs: search_dirs::SearchDirs::new(),
            redirect: search_dirs::SearchDirs::new(),
            machine,
            all: false,
            depth: 1,
            ignore_prefix: &[],
        }
    }

    // Only a missing candidate and one built for another machine let the
    // search go on to the next directory.
    #[test]
    fn bad_candidates() {
        let ctx = PeContext::new(true);
        let config = config(&ctx, pe::IMAGE_FILE_MACHINE_AMD64);
        let dir = crate::tempdir::TempDir::new().unwrap();
        let (first, last) = (dir.path().join("first"), dir.path().join("last"));
        fs::create_dir(&first).unwrap();
        fs::create_dir(&last).unwrap();
        let dll = |machine, pe64| testimage::Image::dll(machine, pe64).build();
        fs::write(last.join("m.dll"), dll(pe::IMAGE_FILE_MACHINE_AMD64, true)).unwrap();

        let search = |searched: &mut Vec<String>| {
            let dirs = [
                (first.to_str().unwrap(), DepMode::Application),
                (last.to_str().unwrap(), DepMode::EnvPath),
            ];
            match find_in(&config, "m.dll", dirs, searched) {
                Ok(Some((_, _, mode))) => Some(mode),
                Ok(None) => panic!("not found"),
                Err(BadImage) => None,
            }
        };
        let candidate = first.join("m.dll");

        let mut searched = Vec::new();
        assert_eq!(search(&mut searched), Some(DepMode::EnvPath));
        assert_eq!(searched.len(), 2);

        fs::write(&candidate, dll(pe::IMAGE_FILE_MACHINE_I386, false)).unwrap();
        assert_eq!(search(&mut Vec::new()), Some(DepMode::EnvPath));

        let valid = dll(pe::IMAGE_FILE_MACHINE_AMD64, true);
        for bad in [&b"not a dll"[..], &valid[..0x100], &[]] {
            fs::write(&candidate, bad).unwrap();
            let mut searched = Vec::new();
            assert_eq!(search(&mut searched), None);
            assert_eq!(searched.len(), 1);
            assert!(searched[0].contains("bad image"), "{}", searched[0]);
        }

        fs::remove_file(&candidate).unwrap();
        fs::create_dir(&candidate).unwrap();
        let mut searched = Vec::new();
        assert_eq!(search(&mut searched), None);
        assert!(
            searched[0].ends_with("(bad image: a directory)"),
            "{}",
            searched[0]
        );
    }

    // A relative recorded name is searched below each directory of the
    // order, and an absolute one taken as it is.
    #[test]
    fn names_with_a_path() {
        let ctx = PeContext::new(true);
        let mut config = config(&ctx, pe::IMAGE_FILE_MACHINE_AMD64);
        let dir = crate::tempdir::TempDir::new().unwrap();
        let (app, other) = (dir.path().join("app"), dir.path().join("other"));
        fs::create_dir_all(other.join("p")).unwrap();
        fs::create_dir(&app).unwrap();
        let dll = testimage::Image::dll(pe::IMAGE_FILE_MACHINE_AMD64, true).build();
        fs::write(other.join("p").join("m.dll"), &dll).unwrap();
        search_dirs::add(
            &mut config.dirs,
            app.to_str().unwrap(),
            DepMode::Application,
        );
        search_dirs::add(&mut config.dirs, other.to_str().unwrap(), DepMode::EnvPath);

        let find = |name: &str| match find_dependency(&config, name, &mut Vec::new()) {
            Ok(Some((_, dir, mode))) => Some((dir, mode)),
            Ok(None) => None,
            Err(BadImage) => panic!("bad image"),
        };
        let expected = other.join("p").to_string_lossy().into_owned();
        assert_eq!(find(r"p\m.dll"), Some((expected.clone(), DepMode::EnvPath)));
        assert_eq!(
            find(r".\p\m.dll"),
            Some((expected.clone(), DepMode::EnvPath))
        );
        assert_eq!(find("p/m.dll"), Some((expected.clone(), DepMode::EnvPath)));
        assert_eq!(find(r"q\m.dll"), None);
        let absolute = other.join("p").join("m.dll");
        assert_eq!(
            find(absolute.to_str().unwrap()),
            Some((expected, DepMode::Direct))
        );
        // Not searched along the order.
        assert_eq!(find(&format!(r"\{}", r"p\m.dll")), None);
    }

    #[test]
    fn forwarder_module_names() {
        assert_eq!(forward_module(b"NTDLL"), "NTDLL.dll");
        assert_eq!(forward_module(b"ntdll.dll"), "ntdll.dll");
        assert_eq!(forward_module(b"NTDLL.DLL"), "NTDLL.DLL");
        // A multi-byte character right before the suffix, and a name that is
        // not UTF-8 at all.
        assert_eq!(forward_module("ñoñ".as_bytes()), "ñoñ.dll");
        assert_eq!(forward_module("abñ.dll".as_bytes()), "abñ.dll");
        assert_eq!(forward_module(b"\xf1o\xf1"), "\u{fffd}o\u{fffd}.dll");
    }

    #[test]
    fn import_display() {
        assert_eq!(
            ImportName::Name("HeapAlloc".to_string()).to_string(),
            "HeapAlloc"
        );
        assert_eq!(ImportName::Ordinal(42).to_string(), "#42");
    }

    fn exports() -> PeExports {
        PeExports {
            names: HashMap::from([
                ("Local".to_string(), None),
                ("Forwarded".to_string(), Some("target.dll".to_string())),
                ("Recorded".to_string(), Some("RECORDED.DLL".to_string())),
            ]),
            ordinals: HashMap::from([(7, None)]),
        }
    }

    #[test]
    fn export_lookup() {
        let exports = exports();
        assert!(matches!(
            exports.lookup(&ImportName::Name("Local".to_string())),
            ExportLookup::Local
        ));
        assert!(matches!(
            exports.lookup(&ImportName::Name("Forwarded".to_string())),
            ExportLookup::Forwarded("target.dll")
        ));
        assert!(matches!(
            exports.lookup(&ImportName::Name("Missing".to_string())),
            ExportLookup::Missing
        ));
        assert!(matches!(
            exports.lookup(&ImportName::Ordinal(7)),
            ExportLookup::Local
        ));
        assert!(matches!(
            exports.lookup(&ImportName::Ordinal(8)),
            ExportLookup::Missing
        ));
    }

    // Only the forwarders of the imported symbols count, and the modules the
    // import directory already records are left out.
    #[test]
    fn forwarded_dependencies() {
        let info = PeInfo {
            deps: vec![PeDep {
                name: "recorded.dll".to_string(),
                attrs: Vec::new(),
                imports: Vec::new(),
            }],
            exports: exports(),
            ..Default::default()
        };
        let imports = [
            ImportName::Name("Local".to_string()),
            ImportName::Name("Missing".to_string()),
            ImportName::Name("Recorded".to_string()),
            ImportName::Name("Forwarded".to_string()),
            ImportName::Name("Forwarded".to_string()),
        ];
        assert_eq!(forwarded_modules(&imports, &info), vec!["target.dll"]);
        assert!(forwarded_modules(&[], &info).is_empty());
    }
}
