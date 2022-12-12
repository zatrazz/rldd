use std::path::Path;
use std::{process, str};

use argparse::{ArgumentParser, List, Store, StoreTrue};

mod arenatree;
#[cfg(target_os = "linux")]
mod interp;
#[cfg(target_os = "linux")]
mod ld_conf;
#[cfg(target_os = "freebsd")]
mod ld_hints_freebsd;
#[cfg(target_os = "openbsd")]
mod ld_hints_openbsd;
mod platform;
mod printer;
mod search_path;
mod system_dirs;
use printer::*;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
mod elf;

// Global configuration used on program dynamic resolution:
// - ld_preload: Search path parser from ld.so.preload
// - ld_library_path: Search path parsed from --ld-library-path.
// - ld_so_conf: paths parsed from the ld.so.conf in the system.
// - system_dirs: system defaults deirectories based on binary architecture.
struct Config<'a> {
    ld_preload: &'a search_path::SearchPathVec,
    ld_library_path: &'a search_path::SearchPathVec,
    ld_so_conf: &'a Option<search_path::SearchPathVec>,
    system_dirs: search_path::SearchPathVec,
    platform: Option<&'a String>,
    all: bool,
}

// Function that mimic the dynamic loader resolution.
#[cfg(target_os = "linux")]
fn resolve_binary_arch(elc: &elf::ElfInfo, deptree: &mut elf::DepTree, depp: usize) {
    // musl loader and libc is on the same shared object, so adds a synthetic dependendy for
    // the binary so it is also shown and to be returned in case a objects has libc.so
    // as needed.
    if elc.is_musl {
        deptree.addnode(
            elf::DepNode {
                path: interp::get_interp_path(&elc.interp),
                name: interp::get_interp_name(&elc.interp).unwrap().to_string(),
                mode: elf::DepMode::SystemDirs,
                found: true,
            },
            depp,
        );
    }
}
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
fn resolve_binary_arch(_elc: &elf::ElfInfo, _deptree: &mut elf::DepTree, _depp: usize) {}

fn resolve_binary(filename: &Path, config: &Config, elc: &elf::ElfInfo) -> elf::DepTree {
    let mut deptree = elf::DepTree::new();

    let depp = deptree.addroot(elf::DepNode {
        path: filename
            .parent()
            .and_then(|s| s.to_str())
            .and_then(|s| Some(s.to_string())),
        name: filename
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string(),
        mode: elf::DepMode::Executable,
        found: false,
    });

    resolve_binary_arch(elc, &mut deptree, depp);

    for ld_preload in config.ld_preload {
        resolve_dependency(&config, &ld_preload.path, elc, &mut deptree, depp, true);
    }

    for dep in &elc.deps {
        resolve_dependency(&config, &dep, elc, &mut deptree, depp, false);
    }

    deptree
}

// Returned from resolve_dependency_1 with resolved information.
struct ResolvedDependency<'a> {
    elc: elf::ElfInfo,
    path: &'a String,
    mode: elf::DepMode,
}

fn resolve_dependency(
    config: &Config,
    dependency: &String,
    elc: &elf::ElfInfo,
    deptree: &mut elf::DepTree,
    depp: usize,
    preload: bool,
) {
    if elc.is_musl && dependency == "libc.so" {
        return;
    }

    // If DF_1_NODEFLIB is set ignore the search cache in the case a dependency could
    // resolve the library.
    if !elc.nodeflibs {
        if let Some(entry) = deptree.get(dependency) {
            if config.all {
                deptree.addnode(
                    elf::DepNode {
                        path: entry.path,
                        name: dependency.to_string(),
                        mode: entry.mode.clone(),
                        found: true,
                    },
                    depp,
                );
            }
            return;
        }
    }

    if let Some(mut dep) = resolve_dependency_1(dependency, config, elc, preload) {
        let r = if dep.mode == elf::DepMode::Direct {
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
            elf::DepNode {
                path: r.0,
                name: r.1,
                mode: dep.mode,
                found: false,
            },
            depp,
        );

        // Use parent R_PATH if dependency does not define it.
        if dep.elc.rpath.is_empty() {
            dep.elc.rpath.extend(elc.rpath.clone());
        }

        for sdep in &dep.elc.deps {
            resolve_dependency(&config, &sdep, &dep.elc, deptree, c, preload);
        }
    } else {
        deptree.addnode(
            elf::DepNode {
                path: None,
                name: dependency.to_string(),
                mode: elf::DepMode::NotFound,
                found: false,
            },
            depp,
        );
    }
}

fn resolve_dependency_1<'a>(
    dtneeded: &'a String,
    config: &'a Config,
    elc: &'a elf::ElfInfo,
    preload: bool,
) -> Option<ResolvedDependency<'a>> {
    let path = Path::new(&dtneeded);

    // If the path is absolute skip the other modes.
    if path.is_absolute() {
        if let Ok(elc) = elf::open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
            return Some(ResolvedDependency {
                elc: elc,
                path: dtneeded,
                mode: if preload {
                    elf::DepMode::Preload
                } else {
                    elf::DepMode::Direct
                },
            });
        }
        return None;
    }

    // Consider DT_RPATH iff DT_RUNPATH is not set.
    if elc.runpath.is_empty() {
        for searchpath in &elc.rpath {
            let path = Path::new(&searchpath.path).join(dtneeded);
            if let Ok(elc) = elf::open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
                return Some(ResolvedDependency {
                    elc: elc,
                    path: &searchpath.path,
                    mode: elf::DepMode::DtRpath,
                });
            }
        }
    }

    // Check LD_LIBRARY_PATH paths.
    for searchpath in config.ld_library_path {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = elf::open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: elf::DepMode::LdLibraryPath,
            });
        }
    }

    // Check DT_RUNPATH.
    for searchpath in &elc.runpath {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = elf::open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: elf::DepMode::DtRunpath,
            });
        }
    }

    // Skip system paths if DF_1_NODEFLIB is set.
    if elc.nodeflibs {
        return None;
    }

    // Check the cached search paths from ld.so.conf
    if let Some(ld_so_conf) = config.ld_so_conf {
        for searchpath in ld_so_conf {
            let path = Path::new(&searchpath.path).join(dtneeded);
            if let Ok(elc) = elf::open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
                return Some(ResolvedDependency {
                    elc: elc,
                    path: &searchpath.path,
                    mode: elf::DepMode::LdSoConf,
                });
            }
        }
    }

    // Finally the system directories.
    for searchpath in &config.system_dirs {
        let path = Path::new(&searchpath.path).join(dtneeded);
        if let Ok(elc) = elf::open_elf_file(&path, Some(elc), Some(dtneeded), config.platform) {
            return Some(ResolvedDependency {
                elc: elc,
                path: &searchpath.path,
                mode: elf::DepMode::SystemDirs,
            });
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn load_so_conf(interp: &Option<String>) -> Option<search_path::SearchPathVec> {
    if interp::is_glibc(interp) {
        match ld_conf::parse_ld_so_conf(&Path::new("/etc/ld.so.conf")) {
            Ok(ld_so_conf) => return Some(ld_so_conf),
            Err(err) => {
                eprintln!("Failed to read loader cache config: {}", err);
                process::exit(1);
            }
        }
    }
    None
}
#[cfg(target_os = "freebsd")]
fn load_so_conf(_interp: &Option<String>) -> Option<search_path::SearchPathVec> {
    ld_hints_freebsd::parse_ld_so_hints(&Path::new("/var/run/ld-elf.so.hints")).ok()
}
#[cfg(target_os = "openbsd")]
fn load_so_conf(_interp: &Option<String>) -> Option<search_path::SearchPathVec> {
    ld_hints_openbsd::parse_ld_so_hints(&Path::new("/var/run/ld.so.hints")).ok()
}

#[cfg(target_os = "linux")]
fn load_ld_so_preload(interp: &Option<String>) -> search_path::SearchPathVec {
    if interp::is_glibc(interp) {
        return ld_conf::parse_ld_so_preload(&Path::new("/etc/ld.so.preload"));
    }
    search_path::SearchPathVec::new()
}
#[cfg(target_os = "freebsd")]
fn load_ld_so_preload(_interp: &Option<String>) -> search_path::SearchPathVec {
    search_path::SearchPathVec::new()
}
#[cfg(target_os = "openbsd")]
fn load_ld_so_preload(_interp: &Option<String>) -> search_path::SearchPathVec {
    search_path::SearchPathVec::new()
}

// Printing functions.

fn print_deps(p: &Printer, deps: &elf::DepTree) {
    let bin = deps.arena.first().unwrap();
    p.print_executable(&bin.val.path, &bin.val.name);

    let mut deptrace = Vec::<bool>::new();
    print_deps_children(p, deps, &bin.children, &mut deptrace);
}

fn print_deps_children(
    p: &Printer,
    deps: &elf::DepTree,
    children: &Vec<usize>,
    deptrace: &mut Vec<bool>,
) {
    let mut iter = children.iter().peekable();
    while let Some(c) = iter.next() {
        let dep = &deps.arena[*c];
        deptrace.push(children.len() > 1);
        if dep.val.mode == elf::DepMode::NotFound {
            p.print_not_found(&dep.val.name, &deptrace);
        } else if dep.val.found {
            p.print_already_found(
                &dep.val.name,
                dep.val.path.as_ref().unwrap(),
                &dep.val.mode.to_string(),
                &deptrace,
            );
        } else {
            p.print_dependency(
                &dep.val.name,
                dep.val.path.as_ref().unwrap(),
                &dep.val.mode.to_string(),
                &deptrace,
            );
        }
        deptrace.pop();

        deptrace.push(children.len() > 1 && !iter.peek().is_none());
        print_deps_children(p, deps, &dep.children, deptrace);
        deptrace.pop();
    }
}

fn print_binary_dependencies(
    p: &Printer,
    ld_preload: &search_path::SearchPathVec,
    ld_so_conf: &mut Option<search_path::SearchPathVec>,
    ld_library_path: &search_path::SearchPathVec,
    platform: Option<&String>,
    all: bool,
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

    let elc = match elf::open_elf_file(&filename, None, None, platform) {
        Ok(elc) => elc,
        Err(err) => {
            eprintln!("Failed to parse file {}: {}", arg, err,);
            process::exit(1);
        }
    };

    if ld_so_conf.is_none() {
        *ld_so_conf = load_so_conf(&elc.interp);
    }

    let mut preload = ld_preload.to_vec();
    // glibc first parses LD_PRELOAD and then ld.so.preload.
    // We need a new vector for the case of binaries with different interpreters.
    preload.extend(load_ld_so_preload(&elc.interp));

    let system_dirs = match system_dirs::get_system_dirs(elc.e_machine, elc.ei_class) {
        Some(r) => r,
        None => {
            eprintln!("Invalid ELF architcture");
            process::exit(1);
        }
    };

    let config = Config {
        ld_preload: &preload,
        ld_library_path: ld_library_path,
        ld_so_conf: ld_so_conf,
        system_dirs: system_dirs,
        platform: platform,
        all: all,
    };

    let mut deptree = resolve_binary(&filename, &config, &elc);

    print_deps(p, &mut deptree);
}

fn main() {
    let mut showpath = false;
    let mut ld_library_path = String::new();
    let mut ld_preload = String::new();
    let mut platform = String::new();
    let mut all = false;
    let mut ldd = false;
    let mut args: Vec<String> = vec![];

    {
        let mut ap = ArgumentParser::new();
        ap.refer(&mut showpath).add_option(
            &["-p"],
            StoreTrue,
            "Show the resolved path instead of the library soname",
        );
        ap.refer(&mut ld_library_path).add_option(
            &["--ld-library-path"],
            Store,
            "Assume the LD_LIBRATY_PATH is set",
        );
        ap.refer(&mut ld_preload).add_option(
            &["--ld-preload"],
            Store,
            "Assume the LD_PRELOAD is set",
        );
        ap.refer(&mut platform).add_option(
            &["--platform"],
            Store,
            "Set the value of $PLATFORM in rpath/runpath expansion",
        );
        ap.refer(&mut all).add_option(
            &["-a", "--all"],
            StoreTrue,
            "Print already resolved dependencies",
        );
        ap.refer(&mut ldd).add_option(
            &["-l", "--ldd"],
            StoreTrue,
            "Output similar to lld (unique dependencies, one per line)",
        );
        ap.refer(&mut args)
            .add_argument("binary", List, "binaries to print the dependencies");
        ap.stop_on_first_argument(true);
        ap.parse_args_or_exit();
    }

    let mut printer = printer::create(showpath, ldd, args.len() == 1);

    let ld_library_path = search_path::from_string(&ld_library_path.as_str(), &[':']);
    let ld_preload = search_path::from_preload(&ld_preload.as_str());

    // The loader search cache is lazy loaded if the binary has a loader that
    // actually supports it.
    let mut ld_so_conf: Option<search_path::SearchPathVec> = None;
    let plat = if platform.is_empty() {
        None
    } else {
        Some(&platform)
    };

    for arg in args {
        print_binary_dependencies(
            &mut printer,
            &ld_preload,
            &mut ld_so_conf,
            &ld_library_path,
            plat,
            all,
            arg.as_str(),
        )
    }
}
