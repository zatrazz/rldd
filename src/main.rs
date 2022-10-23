use std::collections::HashMap;
use std::path::Path;
use std::{env, fmt, fs, process, str};

use object::elf::*;
use object::read::elf::*;
use object::read::StringTable;
use object::Endianness;

use clap::{command, Arg, ArgAction};

mod ld_conf;
mod printer;
mod search_path;
use printer::*;

struct Config<'a> {
    ld_library_path: &'a search_path::SearchPathVec,
    ld_so_conf: &'a search_path::SearchPathVec,
    system_dirs: search_path::SearchPathVec,
}

type DtNeededVec = Vec<String>;

struct ElfLoaderConf {
    ei_class: u8,
    ei_data: u8,
    ei_osabi: u8,
    e_machine: u16,

    soname: Option<String>,
    rpath: search_path::SearchPathVec,
    runpath: search_path::SearchPathVec,
    nodeflibs: bool,

    dtneeded: DtNeededVec,
}

#[derive(PartialEq, Clone, Copy)]
enum DtNeededMode {
    Direct,
    DtRpath,
    LdLibraryPath,
    DtRunpath,
    LdSoConf,
    SystemDirs,
}

impl fmt::Display for DtNeededMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DtNeededMode::Direct => write!(f, "[direct]"),
            DtNeededMode::DtRpath => write!(f, "[rpath]"),
            DtNeededMode::LdLibraryPath => write!(f, "[LD_LIBRARY_PATH]"),
            DtNeededMode::DtRunpath => write!(f, "[runpath]"),
            DtNeededMode::LdSoConf => write!(f, "[ld.so.conf]"),
            DtNeededMode::SystemDirs => write!(f, "[system default paths]"),
        }
    }
}

// Keep track of DT_NEEDED already found.
struct DtNeededFound {
    path: String,
    mode: DtNeededMode,
}

type DtNeededSet = HashMap<String, DtNeededFound>;

fn parse_object(data: &[u8], origin: &str) -> Result<ElfLoaderConf, &'static str> {
    let kind = match object::FileKind::parse(data) {
        Ok(file) => file,
        Err(_err) => return Err("Failed to parse file"),
    };

    match kind {
        object::FileKind::Elf32 => parse_elf32(data, origin),
        object::FileKind::Elf64 => parse_elf64(data, origin),
        _ => Err("Invalid object"),
    }
}

fn parse_elf32(data: &[u8], origin: &str) -> Result<ElfLoaderConf, &'static str> {
    if let Some(elf) = FileHeader32::<Endianness>::parse(data).handle_err() {
        return parse_elf(elf, data, origin);
    }
    Err("Invalid ELF32 object")
}

fn parse_elf64(data: &[u8], origin: &str) -> Result<ElfLoaderConf, &'static str> {
    if let Some(elf) = FileHeader64::<Endianness>::parse(data).handle_err() {
        return parse_elf(elf, data, origin);
    }
    Err("Invalid ELF64 object")
}

fn parse_elf<Elf: FileHeader<Endian = Endianness>>(
    elf: &Elf,
    data: &[u8],
    origin: &str,
) -> Result<ElfLoaderConf, &'static str> {
    let endian = match elf.endian() {
        Ok(val) => val,
        Err(_) => return Err("invalid endianess"),
    };

    match elf.e_type(endian) {
        ET_EXEC | ET_DYN => parse_header_elf(endian, elf, data, origin),
        _ => Err("Invalid ELF file"),
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

fn parse_header_elf<Elf: FileHeader<Endian = Endianness>>(
    endian: Elf::Endian,
    elf: &Elf,
    data: &[u8],
    origin: &str,
) -> Result<ElfLoaderConf, &'static str> {
    match elf.program_headers(endian, data) {
        Ok(segments) => parse_elf_program_headers(endian, data, elf, segments, origin),
        Err(_) => Err("invalid segment"),
    }
}

fn parse_elf_program_headers<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segments: &[Elf::ProgramHeader],
    origin: &str,
) -> Result<ElfLoaderConf, &'static str> {
    match segments
        .iter()
        .find(|&&seg| seg.p_type(endian) == PT_DYNAMIC)
    {
        Some(seg) => parse_elf_segment_dynamic(endian, data, elf, segments, seg, origin),
        None => Err("No dynamic segments found"),
    }
}

fn parse_elf_segment_dynamic<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segments: &[Elf::ProgramHeader],
    segment: &Elf::ProgramHeader,
    origin: &str,
) -> Result<ElfLoaderConf, &'static str> {
    if let Ok(Some(dynamic)) = segment.dynamic(endian, data) {
        let mut strtab = 0;
        let mut strsz = 0;

        // To obtain the DT_NEEDED name we first need to find the DT_STRTAB/DT_STRSZ.
        dynamic.iter().for_each(|d| {
            let tag = d.d_tag(endian).into();
            if tag == DT_STRTAB.into() {
                strtab = d.d_val(endian).into();
            } else if tag == DT_STRSZ.into() {
                strsz = d.d_val(endian).into();
            }
        });

        let dynstr = match parse_elf_stringtable(endian, data, elf, segments, strtab, strsz) {
            Some(dynstr) => dynstr,
            None => return Err("Failure to parse the string table"),
        };

        let df_1_nodeflib = u64::from(DF_1_NODEFLIB);
        let dt_flags_1 = parse_elf_dyn_flags::<Elf>(endian, DT_FLAGS_1, dynamic);
        let nodeflibs = dt_flags_1 & df_1_nodeflib == df_1_nodeflib;

        return match parse_elf_dtneeded::<Elf>(endian, dynamic, dynstr) {
            Ok(dtneeded) => Ok(ElfLoaderConf {
                ei_class: elf.e_ident().class,
                ei_data: elf.e_ident().data,
                ei_osabi: elf.e_ident().os_abi,
                e_machine: elf.e_machine(endian),
                soname: parse_elf_dyn_str::<Elf>(endian, DT_SONAME, dynamic, dynstr),
                rpath: parse_elf_dyn_searchpath(endian, elf, DT_RPATH, dynamic, dynstr, origin),
                runpath: parse_elf_dyn_searchpath(endian, elf, DT_RUNPATH, dynamic, dynstr, origin),
                nodeflibs: nodeflibs,
                dtneeded: dtneeded,
            }),
            Err(e) => Err(e),
        };
    }
    Err("Failure to parse dynamic segment")
}

fn parse_elf_stringtable<'a, Elf: FileHeader>(
    endian: Elf::Endian,
    data: &'a [u8],
    _elf: &Elf,
    segments: &'a [Elf::ProgramHeader],
    strtab: u64,
    strsz: u64,
) -> Option<StringTable<'a>> {
    for s in segments {
        if let Ok(Some(data)) = s.data_range(endian, data, strtab, strsz) {
            return Some(StringTable::new(data, 0, data.len() as u64));
        }
    }
    None
}

fn parse_elf_dyn_str<Elf: FileHeader>(
    endian: Elf::Endian,
    tag: u32,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
) -> Option<String> {
    for d in dynamic {
        if d.d_tag(endian).into() == DT_NULL.into() {
            break;
        }

        if d.tag32(endian).is_none() || d.d_tag(endian).into() != tag.into() {
            continue;
        }

        if let Ok(s) = d.string(endian, dynstr) {
            if let Ok(s) = str::from_utf8(s) {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn parse_elf_dyn_searchpath<Elf: FileHeader>(
    endian: Elf::Endian,
    elf: &Elf,
    tag: u32,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
    origin: &str,
) -> search_path::SearchPathVec {
    if let Some(dynstr) = parse_elf_dyn_str::<Elf>(endian, tag, dynamic, dynstr) {
        // Replace $ORIGIN and $LIB
        // TODO: Add $PLATFORM support.
        let newdynstr = dynstr.replace("$ORIGIN", origin);

        let libdir = search_path::get_slibdir(elf.e_machine(endian), elf.e_ident().class).unwrap();
        let newdynstr = newdynstr.replace("$LIB", libdir);

        return search_path::from_string(newdynstr.as_str());
    }
    search_path::SearchPathVec::new()
}

fn parse_elf_dtneeded<Elf: FileHeader>(
    endian: Elf::Endian,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
) -> Result<DtNeededVec, &'static str> {
    let mut dtneeded = DtNeededVec::new();
    for d in dynamic {
        if d.d_tag(endian).into() == DT_NULL.into() {
            break;
        }

        if d.tag32(endian).is_none()
            || !d.is_string(endian)
            || d.d_tag(endian).into() != DT_NEEDED.into()
        {
            continue;
        }

        match d.string(endian, dynstr) {
            Err(_) => continue,
            Ok(s) => {
                if let Ok(s) = str::from_utf8(s) {
                    dtneeded.push(s.to_string());
                }
            }
        }
    }
    Ok(dtneeded)
}

fn parse_elf_dyn_flags<Elf: FileHeader>(
    endian: Elf::Endian,
    tag: u32,
    dynamic: &[Elf::Dyn],
) -> u64 {
    for d in dynamic {
        if d.d_tag(endian).into() == DT_NULL.into() {
            break;
        }

        if d.tag32(endian).is_none() || d.d_tag(endian).into() != tag.into() {
            continue;
        }

        return d.d_val(endian).into();
    }
    0
}

fn print_binary(p: &Printer, filename: &Path, config: &Config, elc: &ElfLoaderConf) {
    p.print_executable(filename);
    print_dependencies(p, &config, &elc, &mut DtNeededSet::new(), 1)
}

fn print_dependencies(
    p: &Printer,
    config: &Config,
    elc: &ElfLoaderConf,
    dtneededset: &mut DtNeededSet,
    idx: usize,
) {
    for entry in &elc.dtneeded {
        resolve_dependency(p, &entry, &config, &elc, dtneededset, idx);
    }
}

struct ResolvedDependency<'a> {
    elc: ElfLoaderConf,
    path: &'a String,
    mode: DtNeededMode,
}

fn resolve_dependency(
    p: &Printer,
    dtneeded: &String,
    config: &Config,
    elc: &ElfLoaderConf,
    dtneededset: &mut DtNeededSet,
    depth: usize,
) {
    // If DF_1_NODEFLIB is set ignore the search cache in the case a dependency could
    // resolve the library.
    if !elc.nodeflibs {
        if let Some(entry) = dtneededset.get(dtneeded) {
            p.print_already_found(dtneeded, &entry.path, &entry.mode.to_string(), depth);
            return;
        }
    }

    if let Some(dep) = resolve_dependency_1(dtneeded, config, elc) {
        dtneededset.insert(
            //dtneeded.to_string(),
            dtneeded.to_string(),
            DtNeededFound {
                path: dep.path.clone(),
                mode: dep.mode,
            },
        );

        p.print_dependency(dtneeded, &dep.path, &dep.mode.to_string(), depth);
        let depth = depth + 1;
        print_dependencies(p, &config, &dep.elc, dtneededset, depth);
    } else {
        p.print_not_found(dtneeded, depth);
    }
}

fn resolve_dependency_1<'a>(
    dtneeded: &'a String,
    config: &'a Config,
    elc: &'a ElfLoaderConf,
) -> Option<ResolvedDependency<'a>> {
    let path = Path::new(&dtneeded);
    // If the path is absolute skip the other tests.
    if path.is_absolute() {
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
            //return (Some(elc), Some(dtneeded), DtNeededMode::Direct);
            return Some(ResolvedDependency {
                elc: elc,
                path: dtneeded,
                mode: DtNeededMode::Direct,
            });
        }
        return None;
    }

    // Consider DT_RPATH iff DT_RUNPATH is not set
    if elc.runpath.is_empty() {
        for searchpath in &elc.rpath {
            let path = Path::new(&searchpath.path).join(dtneeded);
            if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
                return Some(ResolvedDependency {
                    elc: elc,
                    path: &searchpath.path,
                    mode: DtNeededMode::DtRpath,
                });
            }
        }
    }

    // Check LD_LIBRARY_PATH paths.
    for searchpath in config.ld_library_path {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: DtNeededMode::LdLibraryPath,
            });
        }
    }

    // Check DT_RUNPATH.
    for searchpath in &elc.runpath {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: DtNeededMode::DtRunpath,
            });
        }
    }

    // Skip system paths if DF_1_NODEFLIB is set.
    if elc.nodeflibs {
        return None;
    }

    // Check the cached search paths from ld.so.conf
    for searchpath in config.ld_so_conf {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: DtNeededMode::LdSoConf,
            });
        }
    }

    // Finally the system directories.
    for searchpath in &config.system_dirs {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = open_elf_file(&path, Some(elc), Some(dtneeded)) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: DtNeededMode::SystemDirs,
            });
        }
    }

    None
}

fn open_elf_file<P: AsRef<Path>>(
    filename: &P,
    melc: Option<&ElfLoaderConf>,
    dtneeded: Option<&String>,
) -> Result<ElfLoaderConf, &'static str> {
    let file = match fs::File::open(&filename) {
        Ok(file) => file,
        Err(_) => return Err("Failed to open file"),
    };

    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return Err("Failed to map file"),
    };

    let parent = match filename.as_ref().parent().and_then(Path::to_str) {
        Some(parent) => parent,
        None => "",
    };

    match parse_object(&*mmap, parent) {
        Ok(elc) => {
            if let Some(melc) = melc {
                if !match_elf_name(melc, dtneeded, &elc) {
                    return Err("Error parsing ELF object");
                }
            }
            Ok(elc)
        }
        Err(e) => Err(e),
    }
}

fn match_elf_name(melc: &ElfLoaderConf, dtneeded: Option<&String>, elc: &ElfLoaderConf) -> bool {
    if !check_elf_header(&elc) || !match_elf_header(&melc, &elc) {
        return false;
    }

    // If DT_SONAME is defined compare against it.
    if let Some(dtneeded) = dtneeded {
        return match_elf_soname(dtneeded, elc);
    };

    true
}

fn check_elf_header(elc: &ElfLoaderConf) -> bool {
    // TODO: ARM also accepts ELFOSABI_SYSV
    elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_GNU
}

fn match_elf_header(a1: &ElfLoaderConf, a2: &ElfLoaderConf) -> bool {
    a1.ei_class == a2.ei_class && a1.ei_data == a2.ei_data && a1.e_machine == a2.e_machine
}

fn match_elf_soname(dtneeded: &String, elc: &ElfLoaderConf) -> bool {
    let soname = &elc.soname;
    if let Some(soname) = soname {
        return dtneeded == soname;
    }
    true
}

fn print_binary_dependencies(
    p: &Printer,
    ld_so_conf: &search_path::SearchPathVec,
    ld_library_path: &search_path::SearchPathVec,
    arg: &str,
) {
    // On glibc/Linux the RTLD_DI_ORIGIN for the executable itself (used for $ORIGIN
    // expansion) is obtained by first following the '/proc/self/exe' symlink and if
    // it is not available the loader also checks the 'LD_ORIGIN_PATH' environment
    // variable.
    // The '/proc/self/exec' is an absolute path and to mimic loader behavior we first
    // try to canocalize the input filename to remove any symlinks.  There is not much
    // sense in trying LD_ORIGIN_PATH, since it is only checked by the loader if
    // the binary can not dereference the procfs entry.
    let filename = match Path::new(arg).canonicalize() {
        Ok(filename) => filename,
        Err(err) => {
            eprintln!("Failed to read file {}: {}", arg, err,);
            process::exit(1);
        }
    };

    let elc = match open_elf_file(&filename, None, None) {
        Ok(elc) => elc,
        Err(err) => {
            eprintln!("Failed to parse file {}: {}", arg, err,);
            process::exit(1);
        }
    };

    let system_dirs = match search_path::get_system_dirs(elc.e_machine, elc.ei_class) {
        Some(r) => r,
        None => {
            eprintln!("Invalid ELF architcture");
            process::exit(1);
        }
    };

    let config = Config {
        ld_library_path: ld_library_path,
        ld_so_conf: ld_so_conf,
        system_dirs: system_dirs,
    };

    print_binary(p, &filename, &config, &elc)
}

fn main() {
    let matches = command!()
        .arg(
            Arg::new("file")
                .required(true)
                .help("binary to print the depedencies")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("path")
                .short('p')
                .action(ArgAction::SetTrue)
                .help("Show the resolved path instead of the library soname"),
        )
        .arg(
            Arg::new("ld_library_path")
                .short('l')
                .long("ld-library-path")
                .help("Assume the LD_LIBRATY_PATH is set")
                .default_value(""),
        )
        .get_matches();

    let args = matches
        .get_many::<String>("file")
        .unwrap_or_default()
        .map(|v| v.as_str())
        .collect::<Vec<_>>();

    let pp = matches.get_flag("path");
    let mut printer = printer::create(pp);

    let ld_so_conf = match ld_conf::parse_ld_so_conf(&Path::new("/etc/ld.so.conf")) {
        Ok(ld_so_conf) => ld_so_conf,
        Err(err) => {
            eprintln!("Failed to read loader cache config: {}", err);
            process::exit(1);
        }
    };

    let ld_library_path = search_path::from_string(
        matches
            .get_one::<String>("ld_library_path")
            .expect("ld_library_path should be always set"),
    );

    for arg in args {
        print_binary_dependencies(&mut printer, &ld_so_conf, &ld_library_path, arg)
    }
}
