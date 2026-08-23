use std::collections::VecDeque;
use std::io::Error;
use std::path::Path;
use std::{fs, str};

use object::pe;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use object::{FileKind, LittleEndian as LE};

use crate::deptree::*;
use crate::pathutils;
use crate::search_path;

mod apiset;
mod knowndlls;
mod machine;
mod search_dirs;

// A dependency recorded on the import or the delay load import directory.
#[derive(Clone, Debug)]
struct PeDep {
    name: String,
    attrs: Vec<&'static str>,
}

#[derive(Default, Debug)]
struct PeInfo {
    machine: pe::Machine,
    subsystem: pe::Subsystem,
    image_base: u64,
    is_dll: bool,
    deps: Vec<PeDep>,
}

// The resolution context: the system state the loader consults before the search order.
pub struct PeContext {
    apiset: apiset::ApiSetMap,
    knowndlls: knowndlls::KnownDlls,
    windows_dir: String,
    safe_search: bool,
}

pub fn create_context(safe_search: bool) -> PeContext {
    let windows_dir = search_dirs::windows_dir();
    let apiset = apiset::load(&search_dirs::system_dir(&windows_dir, false));
    PeContext {
        apiset,
        knowndlls: knowndlls::load(),
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

// A pending dependency to resolve, along the base name of the module that
// imports it (which selects the api set alias) and its tree level.
struct WorkItem {
    dep: PeDep,
    importing: String,
    depp: usize,
    level: usize,
}

// Resolve the dependencies in breadth-first orde: a module is loaded once
// and attributed to the first importer, and the search order is the one of
// the application (not of the importing module).
fn resolve_dependencies(config: &Config, root: &PeInfo, deptree: &mut DepTree, root_depp: usize) {
    let root_name = deptree.arena[root_depp].val.name.clone();

    let mut queue = VecDeque::new();
    for dep in &root.deps {
        queue.push_back(WorkItem {
            dep: dep.clone(),
            importing: root_name.clone(),
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

        if let Some(entry) = deptree.get(&name) {
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

        let mut searched = Vec::new();
        let Some((info, dir, mode)) = find_dependency(config, &name, &mut searched) else {
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
        for dep in &info.deps {
            queue.push_back(WorkItem {
                dep: dep.clone(),
                importing: name.clone(),
                depp: depd,
                level: item.level + 1,
            });
        }
    }
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

// Resolve NAME against the known DLLs and then the search directories, returning th
// parsed object, the directory it was found at, and the mode.
fn find_dependency(
    config: &Config,
    name: &str,
    searched: &mut Vec<String>,
) -> Option<(PeInfo, String, DepMode)> {
    // A recorded name with a path component is taken as is.
    if name.contains(['\\', '/']) {
        let path = Path::new(name);
        searched.push(name.to_string());
        let info = try_open(config, path)?;
        return Some((info, pathutils::get_path(&path)?, DepMode::Direct));
    }

    if config.ctx.knowndlls.contains(name) {
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
    };

    if let Ok(Some(table)) = file.import_table() {
        if let Ok(mut descriptors) = table.descriptors() {
            while let Ok(Some(descriptor)) = descriptors.next() {
                if let Ok(name) = table.name(descriptor.name.get(LE)) {
                    pei.deps.push(PeDep {
                        name: String::from_utf8_lossy(name).into_owned(),
                        attrs: Vec::new(),
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
                    });
                }
            }
        }
    }

    Ok(pei)
}
