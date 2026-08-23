use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::Error;
use std::path::Path;
use std::{fs, str};

use object::pe;
use object::read::pe::ExportTarget;
use object::read::pe::{
    DelayLoadImportTable, ExportTable, ImageNtHeaders, ImageOptionalHeader, Import, ImportTable,
    PeFile,
};
use object::{FileKind, LittleEndian as LE};

use crate::deptree::*;
use crate::pathutils;
use crate::search_path;

mod apiset;
mod knowndlls;
mod machine;
mod search_dirs;
mod sxs;

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
    // The dependent assemblies of the embedded manifest, which the loader
    // searches before the standard order.
    assemblies: Vec<sxs::Assembly>,
}

// The resolution context: the system state the loader consults before the search order.
pub struct PeContext {
    apiset: apiset::ApiSetMap,
    knowndlls: knowndlls::KnownDlls,
    winsxs: sxs::WinSxs,
    windows_dir: String,
    safe_search: bool,
}

pub fn create_context(safe_search: bool) -> PeContext {
    let windows_dir = search_dirs::windows_dir();
    let apiset = apiset::load(&search_dirs::system_dir(&windows_dir, false));
    PeContext {
        apiset,
        knowndlls: knowndlls::load(),
        winsxs: sxs::WinSxs::load(&windows_dir),
        windows_dir,
        safe_search,
    }
}

impl PeContext {
    // The directory the known DLLs are resolved from.  The registry values
    // are gone on the recent Windows versions, where the loader creates the
    // known DLLs from the system directory.
    fn knowndll_dir(&self, is_32bit: bool) -> String {
        match self.knowndlls.directory(is_32bit) {
            Some(dir) => dir.to_string(),
            None => search_dirs::system_dir(&self.windows_dir, is_32bit),
        }
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

pub fn resolve_binary(
    ctx: &mut PeContext,
    dll_directory: &search_path::SearchPathVec,
    all: bool,
    verbose: bool,
    depth: usize,
    ignore_prefix: &[String],
    arg: &str,
) -> Result<DepTree, std::io::Error> {
    let canonical = Path::new(arg).canonicalize()?;
    let filename = pathutils::strip_verbatim(&canonical.to_string_lossy());
    let filename = Path::new(&filename);
    let pei = open_pe_file(&filename)?;

    let application = pathutils::get_path(&filename);
    let dirs = search_dirs::build(
        application.as_deref(),
        dll_directory,
        &ctx.windows_dir,
        machine::is_32bit(pei.machine),
        ctx.safe_search,
    );

    if verbose {
        print_object_information(ctx, filename, &pei, &dirs);
    }

    let redirect = dot_local_dirs(filename, application.as_deref());

    let mut deptree = DepTree::new();
    let depp = deptree.addroot(DepNode {
        path: application,
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
        dirs,
        redirect,
        machine: pei.machine,
        all,
        depth,
        ignore_prefix,
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
    lines.push(format!("  machine: {}", machine::name(pei.machine)));
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
    lines.push(format!("  known dlls: {} modules", ctx.knowndlls.len()));
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
    for (dir, mode) in dirs {
        lines.push(format!("  search path: {} {mode}", dir.path));
    }
    println!("{}", lines.join("\n"));
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
    // Whether the importer is a known DLL, whose own dependencies the loader
    // also takes from the known DLLs directory.
    known: bool,
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
        .filter_map(|assembly| ctx.winsxs.resolve(assembly, machine::is_32bit(machine)))
        .collect()
}

// Resolve the dependencies in breadth-first orde: a module is loaded once
// and attributed to the first importer, and the search order is the one of
// the application (not of the importing module).
fn resolve_dependencies(config: &Config, root: &PeInfo, deptree: &mut DepTree, root_depp: usize) {
    let root_name = deptree.arena[root_depp].val.name.clone();
    let root_sxs = assembly_dirs(config, &config.redirect, &root.assemblies);

    let mut queue = VecDeque::new();
    for dep in &root.deps {
        queue.push_back(WorkItem {
            dep: dep.clone(),
            importing: root_name.clone(),
            redirect: root_sxs.clone(),
            known: false,
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
                );
                continue;
            }
            None => (item.dep.name.clone(), None),
        };

        if ignored(config, &name) {
            continue;
        }

        // The side-by-side redirection comes before the loaded-module list,
        // so the same name may be loaded from more than one assembly.
        let mut searched = Vec::new();
        let redirect = find_redirected(config, &name, &item.redirect, &mut searched);
        let lookup = match &redirect {
            Some((_, dir, _)) => format!("{dir}{}{name}", std::path::MAIN_SEPARATOR),
            None => name.clone(),
        };

        if let Some(entry) = deptree.get(&lookup) {
            if config.all {
                deptree.addnode(
                    DepNode {
                        path: entry.path,
                        name: entry.name,
                        mode: entry.mode,
                        found: true,
                        alias,
                        attrs: item.dep.attrs.clone(),
                        version: None,
                        searched: Vec::new(),
                    },
                    item.depp,
                );
            }
            continue;
        }

        let found = match redirect {
            Some(found) => Some(found),
            None => find_dependency(config, &name, item.known, &mut searched),
        };
        let Some((info, dir, mode)) = found else {
            add_not_found(config, &item, deptree, searched);
            continue;
        };

        let resolved = format!("{dir}{}{name}", std::path::MAIN_SEPARATOR);
        if ignored(config, &resolved) {
            continue;
        }

        let depd = deptree.addnode(
            DepNode {
                path: Some(dir),
                name: name.clone(),
                mode,
                found: false,
                alias,
                attrs: item.dep.attrs.clone(),
                version: None,
                searched: Vec::new(),
            },
            item.depp,
        );

        if config.depth != 0 && item.level >= config.depth {
            continue;
        }
        let sxs = assembly_dirs(config, &item.redirect, &info.assemblies);
        let known = item.known || mode == DepMode::LdCache;
        for dep in &info.deps {
            queue.push_back(WorkItem {
                dep: dep.clone(),
                importing: name.clone(),
                redirect: sxs.clone(),
                known,
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
                importing: name.clone(),
                redirect: sxs.clone(),
                known,
                depp: depd,
                level: item.level + 1,
            });
        }
    }
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

// An imported symbol that no loaded module exports.
pub struct UndefinedSymbol {
    pub name: String,
    // The module holding the import.
    pub object: String,
    // The module it is imported from.
    pub from: String,
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

    for node in &deptree.arena {
        // The duplicated and the not found entries hold no imports.
        let Some(path) = &node.val.path else {
            continue;
        };
        if node.val.found {
            continue;
        }
        let Ok(info) = open_pe_file(&Path::new(path).join(&node.val.name)) else {
            continue;
        };

        let sxs = sxs_dirs(ctx, &info.assemblies, info.machine);

        for dep in &info.deps {
            if !delay_load && dep.attrs.contains(&"delay-load") {
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
                .find(|child| child.name.eq_ignore_ascii_case(&name))
                .cloned()
                .or_else(|| {
                    sxs.iter().find_map(|dir| {
                        deptree.get(&format!("{dir}{}{name}", std::path::MAIN_SEPARATOR))
                    })
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
                        from: target.name.clone(),
                    });
                }
            }
        }
    }

    undefined
}

// The paths are compared in case-insensite mode (as the filesystem).
fn ignored(config: &Config, path: &str) -> bool {
    config.ignore_prefix.iter().any(|prefix| {
        path.len() >= prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(prefix)
    })
}

fn add_not_found(config: &Config, item: &WorkItem, deptree: &mut DepTree, searched: Vec<String>) {
    if ignored(config, &item.dep.name) {
        return;
    }
    deptree.addnode(
        DepNode {
            path: None,
            name: item.dep.name.clone(),
            mode: DepMode::NotFound,
            found: false,
            alias: None,
            attrs: item.dep.attrs.clone(),
            version: None,
            searched,
        },
        item.depp,
    );
}

fn find_redirected(
    config: &Config,
    name: &str,
    dirs: &search_dirs::SearchDirs,
    searched: &mut Vec<String>,
) -> Option<(PeInfo, String, DepMode)> {
    for (dir, mode) in dirs {
        let candidate = Path::new(&dir.path).join(name);
        searched.push(candidate.to_string_lossy().into_owned());
        if let Some(info) = try_open(config, &candidate) {
            return Some((info, dir.path.clone(), *mode));
        }
    }
    None
}

// Resolve NAME against the known DLLs and then the search directories, returning th
// parsed object, the directory it was found at, and the mode.
fn find_dependency(
    config: &Config,
    name: &str,
    known: bool,
    searched: &mut Vec<String>,
) -> Option<(PeInfo, String, DepMode)> {
    // A recorded name with a path component is taken as is.
    if name.contains(['\\', '/']) {
        let path = Path::new(name);
        searched.push(name.to_string());
        let info = try_open(config, path)?;
        return Some((info, pathutils::get_path(&path)?, DepMode::Direct));
    }

    if known || config.ctx.knowndlls.contains(name) {
        let dir = config.ctx.knowndll_dir(machine::is_32bit(config.machine));
        let candidate = Path::new(&dir).join(name);
        searched.push(candidate.to_string_lossy().into_owned());
        if let Some(info) = try_open(config, &candidate) {
            return Some((info, dir, DepMode::LdCache));
        }
    }

    for (dir, mode) in &config.dirs {
        let candidate = Path::new(&dir.path).join(name);
        searched.push(candidate.to_string_lossy().into_owned());
        if let Some(info) = try_open(config, &candidate) {
            return Some((info, dir.path.clone(), *mode));
        }
    }

    None
}

// The loader skips a candidate built for another machine and keeps searching,
// which is what tells the System32 and SysWOW64 modules apart.
fn try_open(config: &Config, path: &Path) -> Option<PeInfo> {
    let info = open_pe_file(&path).ok()?;
    machine::compatible(config.machine, info.machine).then_some(info)
}

fn open_pe_file<P: AsRef<Path>>(filename: &P) -> Result<PeInfo, std::io::Error> {
    let file = fs::File::open(filename)?;

    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return Err(Error::other("Failed to map file")),
    };

    parse_object(&mmap).map_err(Error::other)
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
        machine: headers.file_header().machine.get(LE),
        subsystem: headers.optional_header().subsystem(),
        image_base: headers.optional_header().image_base(),
        is_dll: headers.file_header().characteristics.get(LE).0 & pe::IMAGE_FILE_DLL.0 != 0,
        deps: Vec::new(),
        exports: PeExports::default(),
        assemblies: Vec::new(),
    };

    if let Ok(Some(table)) = file.import_table() {
        if let Ok(mut descriptors) = table.descriptors() {
            while let Ok(Some(descriptor)) = descriptors.next() {
                if let Ok(name) = table.name(descriptor.name.get(LE)) {
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
                        imports: import_names::<Pe>(&table, thunks),
                    });
                }
            }
        }
    }

    // The delay load imports are only resolved on the first call.
    if let Ok(Some(table)) = file.delay_load_import_table() {
        if let Ok(mut descriptors) = table.descriptors() {
            while let Ok(Some(descriptor)) = descriptors.next() {
                if let Ok(name) = table.name(descriptor.dll_name_rva.get(LE)) {
                    pei.deps.push(PeDep {
                        name: String::from_utf8_lossy(name).into_owned(),
                        attrs: vec!["delay-load"],
                        imports: delay_import_names::<Pe>(
                            &table,
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

    if let Some(manifest) = parse_manifest(&file) {
        pei.assemblies = sxs::parse_manifest(&manifest);
    }

    Ok(pei)
}

// The embedded RT_MANIFEST resource, which declares the side-by-side
// assemblies the object depends on.
fn parse_manifest<Pe: ImageNtHeaders>(file: &PeFile<Pe>) -> Option<String> {
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
    let languages = manifests.entries.first()?.data(directory).ok()?.table()?;
    let entry = languages.entries.first()?.data(directory).ok()?.data()?;

    let data = sections.pe_data_at(file.data(), entry.offset_to_data.get(LE))?;
    let data = data.get(..entry.size.get(LE) as usize)?;
    Some(String::from_utf8_lossy(data).into_owned())
}

fn import_names<Pe: ImageNtHeaders>(table: &ImportTable, rva: u32) -> Vec<ImportName> {
    let mut names = Vec::new();
    let Ok(mut thunks) = table.thunks(rva) else {
        return names;
    };
    while let Ok(Some(thunk)) = thunks.next::<Pe>() {
        match table.import::<Pe>(thunk) {
            Ok(import) => names.push(import_name(import)),
            Err(_) => break,
        }
    }
    names
}

fn delay_import_names<Pe: ImageNtHeaders>(
    table: &DelayLoadImportTable,
    rva: u32,
) -> Vec<ImportName> {
    let mut names = Vec::new();
    let Ok(mut thunks) = table.thunks(rva) else {
        return names;
    };
    while let Ok(Some(thunk)) = thunks.next::<Pe>() {
        match table.import::<Pe>(thunk) {
            Ok(import) => names.push(import_name(import)),
            Err(_) => break,
        }
    }
    names
}

fn import_name(import: Import) -> ImportName {
    match import {
        Import::Name(_, name) => ImportName::Name(String::from_utf8_lossy(name).into_owned()),
        Import::Ordinal(ordinal) => ImportName::Ordinal(ordinal),
    }
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

// The module of a forwarder string is recorded without the '.dll' suffix.
fn forward_module(module: &[u8]) -> String {
    let module = String::from_utf8_lossy(module).into_owned();
    match module.len() > 4 && module[module.len() - 4..].eq_ignore_ascii_case(".dll") {
        true => module,
        false => format!("{module}.dll"),
    }
}
