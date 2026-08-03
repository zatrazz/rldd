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

    let mut deptrace = Vec::<bool>::new();
    print_deps_children(p, deps, &bin.children, &mut deptrace);
}

fn print_deps_children(p: &Printer, deps: &DepTree, children: &[usize], deptrace: &mut Vec<bool>) {
    let mut iter = children.iter().peekable();
    while let Some(c) = iter.next() {
        let dep = &deps.arena[*c];
        deptrace.push(children.len() > 1);
        if dep.val.mode == deptree::DepMode::NotFound {
            p.print_not_found(&dep.val.name, &dep.val.searched, deptrace);
        } else if dep.val.found {
            p.print_already_found(
                &dep.val.name,
                dep.val.path.as_ref().unwrap(),
                &dep.val.mode.to_string(),
                deptrace,
            );
        } else {
            p.print_dependency(
                &dep.val.name,
                dep.val.path.as_ref().unwrap(),
                &dep.val.mode.to_string(),
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

    /// assume the DYLD_FRAMEWORK_PATH is set.
    #[cfg(target_os = "macos")]
    #[argh(option, default = "\"\".to_string()")]
    library_path: String,

    /// assume the LD_PRELOAD is set.
    #[argh(option, default = "\"\".to_string()")]
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    preload: String,

    /// assume the DYLD_INSERT_LIBRARIES is set.
    #[cfg(target_os = "macos")]
    #[argh(option, default = "\"\".to_string()")]
    preload: String,

    /// set the value of $PLATFORM in rpath/runpath expansion.
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

    /// print search path information.
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

fn print_error(arg: &String, err: std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::NotFound => format!("{arg}: no such file or directory"),
        std::io::ErrorKind::PermissionDenied => format!("{arg}: permission denied"),
        _ => format!("{arg}: {err}"),
    }
}

fn main() {
    let opts: Options = argh::from_env();

    let printer = printer::create(opts.path, opts.ldd, opts.args.len() == 1, opts.verbose);

    let ld_library_path = search_path::from_string(&opts.library_path, &[':']);
    let ld_preload = search_path::from_preload(&opts.preload);

    let mut ctx = create_context();

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
        match resolve_binary(
            &mut ctx,
            &ld_preload,
            &ld_library_path,
            &opts.platform,
            opts.all,
            opts.verbose,
            arg.as_str(),
        ) {
            Ok(deptree) => {
                // Mimic ldd, where --unused suppress both the dependency listing
                // and the undefined symbols report.
                #[cfg(target_os = "linux")]
                if opts.unused {
                    let unused = check_unused_dependencies(&deptree);
                    if !unused.is_empty() {
                        println!("Unused direct dependencies:");
                        for path in unused {
                            println!("\t{path}");
                        }
                        exitcode = 1;
                    }
                    continue;
                }

                print_deps(&printer, &deptree);

                #[cfg(target_os = "linux")]
                if opts.data_relocs || opts.function_relocs {
                    for undef in check_undefined_symbols(&deptree, opts.function_relocs) {
                        println!("undefined symbol: {}\t({})", undef.name, undef.object);
                    }
                }
            }
            Err(e) => {
                eprintln!("error: {}", print_error(&arg, e));
                exitcode = 1;
            }
        }
    }

    std::process::exit(exitcode);
}
