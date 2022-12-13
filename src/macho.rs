use std::io::{Error, ErrorKind};
use std::path::Path;
use std::{fmt, fs, str};

use object::macho::*;
use object::read::macho::*;
use object::Endianness;

use crate::deptree::*;
use crate::search_path;

type DepsVec = Vec<String>;

#[derive(Debug)]
struct MachOInfo {
    deps: DepsVec,
}

pub fn resolve_binary(
    ld_preload: &search_path::SearchPathVec,
    ld_so_conf: &mut Option<search_path::SearchPathVec>,
    ld_library_path: &search_path::SearchPathVec,
    platform: Option<&String>,
    all: bool,
    arg: &str,
) -> Result<DepTree, std::io::Error> {
    let filename = Path::new(arg).canonicalize()?;

    let elc = open_macho_file(&filename)?;

    let mut deptree = DepTree::new();

    let depp = deptree.addroot(DepNode {
        path: filename
            .parent()
            .and_then(|s| s.to_str())
            .and_then(|s| Some(s.to_string())),
        name: filename
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string(),
        mode: DepMode::Executable,
        found: false,
    });

    for dep in &elc.deps {
        resolve_dependency(&dep, &elc, &mut deptree, depp);
    }

    Ok(deptree)
}

// Returned from resolve_dependency_1 with resolved information.
struct ResolvedDependency<'a> {
    elc: MachOInfo,
    path: &'a String,
    mode: DepMode,
}

fn resolve_dependency(dependency: &String, elc: &MachOInfo, deptree: &mut DepTree, depp: usize) {
    if let Some(mut dep) = resolve_dependency_1(dependency) {
        let r = if dep.mode == DepMode::Direct {
            // Decompose the direct object path in path and filename so when print the dependencies
            // only the file name is showed in default mode.
            let p = Path::new(dependency);
            (
                p.parent()
                    .and_then(|s| s.to_str())
                    .and_then(|s| Some(s.to_string())),
                p.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string(),
            )
        } else {
            (Some(dep.path.to_string()), dependency.to_string())
        };
        let c = deptree.addnode(
            DepNode {
                path: r.0,
                name: r.1,
                mode: dep.mode,
                found: false,
            },
            depp,
        );
        for sdep in &dep.elc.deps {
            resolve_dependency(&sdep, &dep.elc, deptree, c);
        }
    } else {
        deptree.addnode(
            DepNode {
                path: None,
                name: dependency.to_string(),
                mode: DepMode::NotFound,
                found: false,
            },
            depp,
        );
    }
}

fn resolve_dependency_1<'a>(dep: &'a String) -> Option<ResolvedDependency<'a>> {
    let path = Path::new(&dep);

    // If the path is absolute skip the other modes.
    if path.is_absolute() {
        if let Ok(elc) = open_macho_file(&path) {
            return Some(ResolvedDependency {
                elc: elc,
                path: dep,
                mode: DepMode::Direct,
            });
        }
        return None;
    }

    // TODO: handle @executable_path
    // TODO: @loader_path/
    // TODO: @rpath/

    None
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

    println!("kind={:?}", kind);

    match kind {
        object::FileKind::MachO32 => parse_macho32(data, 0),
        object::FileKind::MachO64 => parse_macho64(data, 0),
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

fn parse_macho32(data: &[u8], offset: u64) -> Result<MachOInfo, &'static str> {
    if let Some(macho) = MachHeader32::parse(data, offset).handle_err() {
        return parse_macho(macho, data, 0);
    }
    Err("Invalid Mach-O 32 object")
}

fn parse_macho64(data: &[u8], offset: u64) -> Result<MachOInfo, &'static str> {
    if let Some(macho) = MachHeader64::parse(data, offset).handle_err() {
        return parse_macho(macho, data, 0);
    }
    Err("Invalid Mach-O 64 object")
}

#[derive(Default)]
struct MachState {
    _section_index: usize,
}

fn parse_macho<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    data: &[u8],
    offset: u64,
) -> Result<MachOInfo, &'static str> {
    let mut deps = DepsVec::new();

    if let Ok(endian) = header.endian() {
        let mut state = MachState::default();
        if let Ok(mut commands) = header.load_commands(endian, data, offset) {
            while let Ok(Some(command)) = commands.next() {
                if let Some(dep) = parse_load_command::<Mach>(endian, command) {
                    deps.push(dep);
                }
            }
        }
    }

    Ok(MachOInfo { deps: deps })
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
