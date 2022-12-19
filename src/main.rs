use argparse::{ArgumentParser, List, Store, StoreTrue};

mod printer;
use printer::*;
mod deptree;
mod pathutils;
mod search_path;
use deptree::*;
#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
mod elf;
#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
use elf::*;
#[cfg(any(target_os = "macos"))]
mod macho;
#[cfg(any(target_os = "macos"))]
use macho::*;

fn print_deps(p: &Printer, deps: &DepTree) {
    let bin = deps.arena.first().unwrap();
    p.print_executable(&bin.val.path, &bin.val.name);

    let mut deptrace = Vec::<bool>::new();
    print_deps_children(p, deps, &bin.children, &mut deptrace);
}

fn print_deps_children(
    p: &Printer,
    deps: &DepTree,
    children: &Vec<usize>,
    deptrace: &mut Vec<bool>,
) {
    let mut iter = children.iter().peekable();
    while let Some(c) = iter.next() {
        let dep = &deps.arena[*c];
        deptrace.push(children.len() > 1);
        if dep.val.mode == deptree::DepMode::NotFound {
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

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
const LIBRARY_PATH_OPTION: &str = "Assume the LD_LIBRARY_PATH is set";
#[cfg(any(target_os = "macos"))]
const LIBRARY_PATH_OPTION: &str = "Assume the DYLD_FRAMEWORK_PATH is set";

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
        ap.refer(&mut ld_library_path)
            .add_option(&["--library-path"], Store, LIBRARY_PATH_OPTION);
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

    let plat = if platform.is_empty() {
        None
    } else {
        Some(&platform)
    };

    let mut ctx = create_context();

    for arg in args {
        if let Ok(mut deptree) = resolve_binary(
            &mut ctx,
            &ld_preload,
            &ld_library_path,
            plat,
            all,
            arg.as_str(),
        ) {
            print_deps(&mut printer, &mut deptree);
        }
    }
}
