use argh::FromArgs;

mod printer;
use printer::*;
mod deptree;
mod pathutils;
mod search_path;
use deptree::*;

#[cfg(all(target_family = "unix", not(target_os = "macos")))]
mod elf;
#[cfg(all(target_family = "unix", not(target_os = "macos")))]
use elf::*;

#[cfg(target_os = "macos")]
mod macho;
#[cfg(target_os = "macos")]
use macho::*;

fn print_deps(p: &Printer, deps: &DepTree) {
    let bin = deps.arena.first().unwrap();
    p.print_executable(&bin.val.path, &bin.val.name);

    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    if bin.children.is_empty() {
        p.print_statically_linked();
        return;
    }

    let mut deptrace = Vec::<bool>::new();
    print_deps_children(p, deps, &bin.children, &mut deptrace);
}

fn print_deps_children(p: &Printer, deps: &DepTree, children: &[usize], deptrace: &mut Vec<bool>) {
    let mut iter = children.iter().peekable();
    while let Some(c) = iter.next() {
        let dep = &deps.arena[*c];
        deptrace.push(children.len() > 1);
        let mut mode = if dep.val.attrs.is_empty() {
            dep.val.mode.to_string()
        } else {
            format!("[{}] {}", dep.val.attrs.join(" "), dep.val.mode)
        };
        // The load command versions (Mach-O only), shown in verbose mode the
        // way otool -L reports them.
        if p.is_verbose() {
            if let Some(version) = &dep.val.version {
                mode = format!("{mode} ({version})");
            }
        }
        if dep.val.mode == deptree::DepMode::NotFound {
            p.print_not_found(&dep.val.name, &dep.val.attrs, &dep.val.searched, deptrace);
        } else if dep.val.found {
            p.print_already_found(
                &dep.val.name,
                dep.val.path.as_ref().unwrap(),
                &mode,
                deptrace,
            );
        } else {
            p.print_dependency(
                &dep.val.name,
                dep.val.path.as_ref().unwrap(),
                &mode,
                deptrace,
            );
        }
        deptrace.pop();

        deptrace.push(children.len() > 1 && iter.peek().is_some());
        print_deps_children(p, deps, &dep.children, deptrace);
        deptrace.pop();
    }
}

#[derive(FromArgs)]
/// Print shared objects dependencies
struct Options {
    /// assume the LD_LIBRARY_PATH is set.
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    #[argh(option, default = "\"\".to_string()")]
    library_path: String,

    /// only use the specified architecture instead of the host one.
    #[cfg(target_os = "macos")]
    #[argh(option)]
    arch: Option<String>,

    /// limit the dependency tree to the given number of levels, with 0
    /// meaning no limit..
    #[cfg(target_os = "macos")]
    #[argh(option, default = "1")]
    depth: usize,

    /// assume the DYLD_LIBRARY_PATH is set.
    #[cfg(target_os = "macos")]
    #[argh(option, default = "\"\".to_string()")]
    library_path: String,

    /// assume the DYLD_FRAMEWORK_PATH is set.
    #[cfg(target_os = "macos")]
    #[argh(option, default = "\"\".to_string()")]
    framework_path: String,

    /// assume the DYLD_FALLBACK_LIBRARY_PATH is set.
    #[cfg(target_os = "macos")]
    #[argh(option, default = "\"\".to_string()")]
    fallback_library_path: String,

    /// assume the DYLD_FALLBACK_FRAMEWORK_PATH is set.
    #[cfg(target_os = "macos")]
    #[argh(option, default = "\"\".to_string()")]
    fallback_framework_path: String,

    /// assume the DYLD_IMAGE_SUFFIX is set.
    #[cfg(target_os = "macos")]
    #[argh(option)]
    image_suffix: Option<String>,

    /// skip dependencies whose load path starts with the prefix (may be
    /// used multiple times).
    #[cfg(target_os = "macos")]
    #[argh(option)]
    ignore_prefix: Vec<String>,

    /// assume the LD_PRELOAD is set.
    #[argh(option, default = "\"\".to_string()")]
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    preload: String,

    /// assume the DYLD_INSERT_LIBRARIES is set.
    #[cfg(target_os = "macos")]
    #[argh(option, default = "\"\".to_string()")]
    preload: String,

    /// set the value of $PLATFORM in rpath/runpath expansion.
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    #[argh(option)]
    platform: Option<String>,

    /// process data relocations and report undefined symbols.
    #[cfg(target_os = "linux")]
    #[argh(switch, short = 'd')]
    data_relocs: bool,

    /// process data and function relocations and report undefined symbols.
    #[cfg(target_os = "linux")]
    #[argh(switch, short = 'r')]
    function_relocs: bool,

    /// print unused direct dependencies.
    #[cfg(target_os = "linux")]
    #[argh(switch, short = 'u')]
    unused: bool,

    /// print search path and object information.
    #[argh(switch, short = 'v')]
    verbose: bool,

    /// show the resolved path instead of the library SONAME.
    #[argh(switch, short = 'p')]
    path: bool,

    /// print already resolved dependencies.
    #[argh(switch, short = 'a')]
    all: bool,

    /// output similar to lld (unique dependencies, one per line).
    #[argh(switch, short = 'l')]
    ldd: bool,

    #[argh(positional, greedy)]
    args: Vec<String>,
}

#[cfg(target_os = "linux")]
fn print_version_errors(arg: &str, errors: &[elf::VersionError]) {
    for error in errors {
        println!(
            "{arg}: {}: version `{}' not found (required by {})",
            error.object, error.version, error.required_by
        );
    }
}

fn print_error(arg: &String, err: std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::NotFound => format!("{arg}: no such file or directory"),
        std::io::ErrorKind::PermissionDenied => format!("{arg}: permission denied"),
        _ => format!("{arg}: {err}"),
    }
}

fn main() {
    let opts: Options = argh::from_env();

    // On macOS the dependencies are always shown with their full resolved path.
    let printer = printer::create(
        opts.path || cfg!(target_os = "macos"),
        opts.ldd,
        opts.args.len() == 1,
        opts.verbose,
    );

    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    let ld_library_path = search_path::from_string(&opts.library_path, &[':']);
    let ld_preload = search_path::from_preload(&opts.preload);

    #[cfg(target_os = "macos")]
    let dyld_env = macho::DyldEnv {
        library_path: search_path::from_string(&opts.library_path, &[':']),
        framework_path: search_path::from_string(&opts.framework_path, &[':']),
        fallback_library_path: search_path::from_string(&opts.fallback_library_path, &[':']),
        fallback_framework_path: search_path::from_string(&opts.fallback_framework_path, &[':']),
        image_suffix: opts.image_suffix.clone(),
    };

    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    let mut ctx = create_context();
    #[cfg(target_os = "macos")]
    let mut ctx = match create_context(opts.arch.as_deref()) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("{}: {err}", env!("CARGO_PKG_NAME"));
            std::process::exit(1);
        }
    };

    if opts.args.is_empty() {
        eprintln!(
            "{progname}: missing file arguments\n\
            Try `{progname} --help' for more information.",
            progname = env!("CARGO_PKG_NAME")
        );
        std::process::exit(1);
    };

    let mut exitcode = 0;

    for arg in opts.args {
        #[cfg(all(target_family = "unix", not(target_os = "macos")))]
        let resolved = resolve_binary(
            &mut ctx,
            &ld_preload,
            &ld_library_path,
            &opts.platform,
            opts.all,
            opts.verbose,
            arg.as_str(),
        );
        #[cfg(target_os = "macos")]
        let resolved = resolve_binary(
            &mut ctx,
            &ld_preload,
            &dyld_env,
            opts.all,
            opts.verbose,
            opts.depth,
            &opts.ignore_prefix,
            arg.as_str(),
        );
        match resolved {
            Ok(deptree) => {
                // Mimic ldd, where --unused suppress both the dependency listing
                // and the undefined symbols report.
                #[cfg(target_os = "linux")]
                if opts.unused {
                    let relocs = check_relocations(&deptree, true, true);
                    print_version_errors(&arg, &relocs.version_errors);
                    if !relocs.unused.is_empty() {
                        println!("Unused direct dependencies:");
                        for path in relocs.unused {
                            println!("\t{path}");
                        }
                        exitcode = 1;
                    }
                    continue;
                }

                #[cfg(target_os = "linux")]
                if opts.data_relocs || opts.function_relocs {
                    let relocs = check_relocations(&deptree, opts.function_relocs, false);
                    // The loader prints the version check errors before the
                    // dependency listing.
                    print_version_errors(&arg, &relocs.version_errors);
                    print_deps(&printer, &deptree);
                    for undef in relocs.undefined {
                        let version = match undef.version {
                            Some(version) => format!(", version {version}"),
                            None => String::new(),
                        };
                        println!(
                            "undefined symbol: {}{version}\t({})",
                            undef.name, undef.object
                        );
                    }
                    continue;
                }

                print_deps(&printer, &deptree);
            }
            Err(e) => {
                eprintln!("error: {}", print_error(&arg, e));
                exitcode = 1;
            }
        }
    }

    std::process::exit(exitcode);
}
