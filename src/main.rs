use std::ffi::{OsStr, OsString};
use std::io::{Error, ErrorKind};

use argh::{ArgsInfo, FromArgs};

// Only the systems whose loader is emulated are supported, and any other
// would fail to build with obscure errors (such as the missing loader type
// of the ELF backend).
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "macos",
    windows
)))]
compile_error!(
    "unsupported target: rldd builds for the linux, android, freebsd, netbsd, \
     openbsd, illumos, solaris, macos, and windows target_os only"
);

#[macro_use]
mod output;

#[cfg(test)]
mod tempdir;

mod deptree;
mod pathutils;
mod printer;
mod search_path;

#[cfg(all(target_family = "unix", not(target_os = "macos")))]
mod elf;
#[cfg(all(target_family = "unix", not(target_os = "macos")))]
use elf::*;

#[cfg(target_os = "macos")]
mod macho;
#[cfg(target_os = "macos")]
use macho::*;

#[cfg(windows)]
mod pe;
#[cfg(windows)]
use pe::*;

#[derive(FromArgs, ArgsInfo)]
/// Print shared object dependencies
// A 'help' trigger would take a file named help as the request for the usage.
#[argh(help_triggers("-h", "--help"))]
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
    /// meaning no limit (default 1).
    #[cfg(any(target_os = "macos", windows))]
    #[argh(option, default = "1")]
    depth: usize,

    /// assume the directories are set with SetDllDirectory (semicolon
    /// separated).
    #[cfg(windows)]
    #[argh(option, default = "\"\".to_string()")]
    library_path: String,

    /// assume the SafeDllSearchMode is disabled, which searches the current
    /// directory before the system ones.
    #[cfg(windows)]
    #[argh(switch)]
    no_safe_search: bool,

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

    /// skip dependencies whose resolved path starts with the prefix (may be
    /// used multiple times).
    #[cfg(windows)]
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

    /// check the imports and report the ones no dependency exports.
    #[cfg(windows)]
    #[argh(switch, short = 'd')]
    data_relocs: bool,

    /// also check the delay load imports.
    #[cfg(windows)]
    #[argh(switch, short = 'r')]
    function_relocs: bool,

    /// print unused direct dependencies.
    #[cfg(target_os = "linux")]
    #[argh(switch, short = 'u')]
    unused: bool,

    /// print search path and object information.
    #[argh(switch, short = 'v')]
    verbose: bool,

    /// show the resolved path instead of the library name.
    #[argh(switch, short = 'p')]
    path: bool,

    /// print already resolved dependencies.
    #[argh(switch, short = 'a')]
    all: bool,

    /// output similar to ldd (unique dependencies, one per line).
    #[argh(switch, short = 'l')]
    ldd: bool,

    #[argh(positional, greedy)]
    args: Vec<String>,
}

#[cfg(target_os = "linux")]
fn print_version_errors(arg: &str, errors: &[elf::VersionError]) {
    for error in errors {
        outln!(
            "{arg}: {}: version `{}' not found (required by {})",
            error.object,
            error.version,
            error.required_by
        );
    }
}

fn print_error(arg: &str, err: std::io::Error) -> String {
    let message = match err.kind() {
        ErrorKind::NotFound => "no such file or directory".to_string(),
        ErrorKind::PermissionDenied => "permission denied".to_string(),
        ErrorKind::IsADirectory => "is a directory".to_string(),
        ErrorKind::NotADirectory => "not a directory".to_string(),
        _ => lowercase_first(&err.to_string()),
    };
    format!("{arg}: {message}")
}

// MESSAGE starting in lower case, like the other file errors, unless its first
// word is an acronym (such as ELF).  The system messages and some of the
// backend ones are capitalized.
fn lowercase_first(message: &str) -> String {
    let mut chars = message.chars();
    match (chars.next(), chars.next()) {
        (Some(first), Some(second)) if first.is_uppercase() && second.is_lowercase() => first
            .to_lowercase()
            .chain(message.chars().skip(1))
            .collect(),
        _ => message.to_string(),
    }
}

// The object format this build inspects, which is the host one, along with
// its article.
fn host_format() -> (&'static str, &'static str) {
    if cfg!(target_os = "macos") {
        ("a", "Mach-O")
    } else if cfg!(windows) {
        ("a", "PE")
    } else {
        ("an", "ELF")
    }
}

// The object format of the files of KIND, for the ones a build inspects.
fn object_format(kind: object::FileKind) -> Option<&'static str> {
    use object::FileKind;
    match kind {
        FileKind::Elf32 | FileKind::Elf64 => Some("ELF"),
        FileKind::MachO32 | FileKind::MachO64 | FileKind::MachOFat32 | FileKind::MachOFat64 => {
            Some("Mach-O")
        }
        FileKind::Pe32 | FileKind::Pe64 => Some("PE"),
        _ => None,
    }
}

// Check that the ARG file is an object of the format this build inspects, so
// that a directory, or an object of the format another build inspects, is
// reported the same way everywhere.
fn check_format(arg: &str) -> std::io::Result<()> {
    let mmap = match pathutils::map_file(&arg) {
        Ok(mmap) => mmap,
        // A Mach-O system library may exist only in the dyld shared cache,
        // which the backend looks up.
        Err(err) if cfg!(target_os = "macos") && err.kind() == ErrorKind::NotFound => {
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    check_object(&mmap)
}

fn check_object(data: &[u8]) -> std::io::Result<()> {
    let (article, host) = host_format();
    match object::FileKind::parse(data).ok().and_then(object_format) {
        Some(format) if format == host => Ok(()),
        Some(_) => Err(Error::new(
            ErrorKind::InvalidData,
            format!("not {article} {host} object (this build inspects {host} objects only)"),
        )),
        None => Err(Error::new(
            ErrorKind::InvalidData,
            format!("not {article} {host} object"),
        )),
    }
}

// The command line split in the options, which argh parses, and the files.
struct CommandLine {
    options: Vec<String>,
    files: Vec<OsString>,
}

// Split ARGS, the command line without the program name, the way argh parses
// it: the files start after '--' or at the first argument that is neither an
// option nor an option value, and every argument from there on is a file (the
// files are greedy).  argh requires valid UTF-8 for the whole command line,
// while the files are kept here as given, so a file name that is not valid
// UTF-8 fails for that file only.  An option in the '--option=value' form,
// which argh does not accept, is split in the option and the value.
fn split_command_line(
    args: impl IntoIterator<Item = OsString>,
    flags: &[argh::FlagInfo],
) -> Result<CommandLine, String> {
    // Whether OPTION takes a value, which is the argument following it.
    let takes_value = |option: &str| {
        flags.iter().any(|flag| {
            let short = flag.short.map(|short| format!("-{short}"));
            matches!(flag.kind, argh::FlagInfoKind::Option { .. })
                && (flag.long == option || short.as_deref() == Some(option))
        })
    };

    let mut options = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        if !arg.as_encoded_bytes().starts_with(b"-") {
            let files = std::iter::once(arg).chain(args).collect();
            return Ok(CommandLine { options, files });
        }

        // argh has no '--option=value' form, which is split here.
        if let Some((option, value)) = split_option(&arg).filter(|(option, _)| takes_value(option))
        {
            let value = std::str::from_utf8(value).map_err(|_| {
                let lossy = arg.to_string_lossy();
                invalid_value(option, &lossy[option.len() + 1..])
            })?;
            options.push(option.to_string());
            options.push(value.to_string());
            continue;
        }

        let option = arg
            .into_string()
            .map_err(|arg| format!("Unrecognized argument: {}\n", arg.to_string_lossy()))?;
        let value = match takes_value(&option).then(|| args.next()).flatten() {
            Some(value) => Some(
                value
                    .into_string()
                    .map_err(|value| invalid_value(&option, &value.to_string_lossy()))?,
            ),
            // A missing value is left for argh to report.
            None => None,
        };
        options.push(option);
        options.extend(value);
    }
    let files = args.collect();
    Ok(CommandLine { options, files })
}

// The option and the value of ARG in the '--option=value' form.
fn split_option(arg: &OsStr) -> Option<(&str, &[u8])> {
    let arg = arg.as_encoded_bytes();
    let eq = arg.iter().position(|&c| c == b'=')?;
    let option = std::str::from_utf8(&arg[..eq]).ok()?;
    option.starts_with("--").then_some((option, &arg[eq + 1..]))
}

fn invalid_value(option: &str, value: &str) -> String {
    format!("Error parsing option '{option}' with value '{value}': not valid UTF-8\n")
}

// Parse ARGS, the command line without the program name, returning the
// options along with the files as given.
fn parse(
    cmd: &str,
    args: impl IntoIterator<Item = OsString>,
) -> Result<(Options, Vec<OsString>), argh::EarlyExit> {
    let command_line = split_command_line(args, Options::get_args_info().flags)?;

    // After a '--', argh takes every argument as a file, even one that looks
    // like an option.
    let files: Vec<String> = command_line
        .files
        .iter()
        .map(|file| file.to_string_lossy().into_owned())
        .collect();
    let mut args: Vec<&str> = command_line.options.iter().map(String::as_str).collect();
    if !files.is_empty() {
        args.push("--");
        args.extend(files.iter().map(String::as_str));
    }

    let opts = Options::from_args(&[cmd], &args)?;
    Ok((opts, command_line.files))
}

// Report a command line error the way argh does, and exit.
fn usage_error(cmd: &str, message: &str) -> ! {
    errln!("{message}\nRun {cmd} --help for more information.");
    std::process::exit(1);
}

// Parse the command line.  Unlike argh::from_env, which prints with println!
// and eprintln!, the usage and the errors go through the output helpers,
// which do not panic when the output is closed.
fn parse_args() -> (Options, Vec<OsString>) {
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_default();
    let cmd = std::path::Path::new(&program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(env!("CARGO_PKG_NAME"));

    match parse(cmd, args) {
        Ok(parsed) => parsed,
        Err(early_exit) => match early_exit.status {
            Ok(()) => {
                outln!("{}", early_exit.output);
                std::process::exit(0);
            }
            Err(()) => usage_error(cmd, &early_exit.output),
        },
    }
}

fn main() {
    let (opts, files) = parse_args();

    // On macOS the dependencies are always shown with their full resolved path.
    let printer = printer::create(
        opts.path || cfg!(target_os = "macos"),
        opts.ldd,
        opts.args.len() == 1,
        opts.verbose,
    );

    let mut ctx = match create_context(&opts) {
        Ok(ctx) => ctx,
        Err(err) => {
            errln!("{}: {err}", env!("CARGO_PKG_NAME"));
            std::process::exit(1);
        }
    };

    if opts.args.is_empty() {
        errln!(
            "{progname}: missing file arguments\n\
            Try `{progname} --help' for more information.",
            progname = env!("CARGO_PKG_NAME")
        );
        std::process::exit(1);
    };

    // ARG is the file name as argh parsed it, which is lossy for a name that
    // is not valid UTF-8.
    for (arg, file) in opts.args.iter().zip(&files) {
        // The backends take the file name as a string.
        if file.to_str().is_none() {
            errln!("error: {arg}: path is not valid UTF-8");
            output::set_exit_status(1);
            continue;
        }

        match check_format(arg).and_then(|()| resolve_binary(&mut ctx, arg)) {
            Ok(deptree) => {
                // Mimic ldd, where --unused suppress both the dependency listing
                // and the undefined symbols report.
                #[cfg(target_os = "linux")]
                if opts.unused {
                    let relocs = check_relocations(&deptree, true, true);
                    print_version_errors(arg, &relocs.version_errors);
                    if !relocs.unused.is_empty() {
                        outln!("Unused direct dependencies:");
                        for path in relocs.unused {
                            outln!("\t{path}");
                        }
                        output::set_exit_status(1);
                    }
                    continue;
                }

                #[cfg(any(target_os = "linux", windows))]
                if opts.data_relocs || opts.function_relocs {
                    #[cfg(target_os = "linux")]
                    let undefined = {
                        let relocs = check_relocations(&deptree, opts.function_relocs, false);
                        // The loader prints the version check errors before the
                        // dependency listing.
                        print_version_errors(arg, &relocs.version_errors);
                        relocs.undefined
                    };
                    #[cfg(windows)]
                    let undefined = check_imports(&ctx, &deptree, opts.function_relocs);
                    printer.print_deps(&deptree);
                    for undef in undefined {
                        outln!("undefined symbol: {undef}\t({})", undef.object);
                    }
                    continue;
                }

                printer.print_deps(&deptree);

                // The musl ldd always processes the relocations (musl has no
                // lazy binding), reporting the unresolved references after
                // the listing and failing with the loader exit status.
                #[cfg(target_os = "linux")]
                if let Some(undefined) = check_musl_relocations(&deptree) {
                    if !undefined.is_empty() {
                        for undef in &undefined {
                            errln!(
                                "Error relocating {}: {}: symbol not found",
                                undef.object,
                                undef.name
                            );
                        }
                        output::set_exit_status(127);
                    }
                }
            }
            Err(e) => {
                errln!("error: {}", print_error(arg, e));
                output::set_exit_status(1);
            }
        }
    }

    std::process::exit(output::exit_status());
}

#[cfg(test)]
mod tests {
    use super::*;

    // An option with a value and a switch, whatever the target options are.
    const FLAGS: &[argh::FlagInfo] = &[
        argh::FlagInfo {
            kind: argh::FlagInfoKind::Option { arg_name: "depth" },
            optionality: argh::Optionality::Optional,
            long: "--depth",
            short: Some('D'),
            description: "",
            hidden: false,
        },
        argh::FlagInfo {
            kind: argh::FlagInfoKind::Switch,
            optionality: argh::Optionality::Optional,
            long: "--verbose",
            short: Some('v'),
            description: "",
            hidden: false,
        },
    ];

    fn split(args: &[&str]) -> (Vec<String>, Vec<OsString>) {
        let command_line = split_command_line(args.iter().map(OsString::from), FLAGS).unwrap();
        (command_line.options, command_line.files)
    }

    fn parse_ok(args: &[&str]) -> (Options, Vec<OsString>) {
        parse("rldd", args.iter().map(OsString::from)).unwrap()
    }

    #[test]
    fn options_and_files() {
        assert_eq!(
            split(&["-v", "a", "b"]),
            (vec!["-v".into()], vec!["a".into(), "b".into()])
        );
        assert_eq!(
            split(&["--depth", "0", "-v"]),
            (vec!["--depth".into(), "0".into(), "-v".into()], vec![])
        );
        assert_eq!(
            split(&["-D", "0", "a"]),
            (vec!["-D".into(), "0".into()], vec!["a".into()])
        );
        // An option value is not a file, even when it looks like an option.
        assert_eq!(
            split(&["--depth", "-v", "a"]),
            (vec!["--depth".into(), "-v".into()], vec!["a".into()])
        );
        // A missing value is left for argh to report.
        assert_eq!(split(&["--depth"]), (vec!["--depth".into()], vec![]));
        // The files start after '--', and take every argument that follows.
        assert_eq!(
            split(&["a", "-v", "--"]),
            (vec![], vec!["a".into(), "-v".into(), "--".into()])
        );
        assert_eq!(
            split(&["-v", "--", "-v", "--"]),
            (vec!["-v".into()], vec!["-v".into(), "--".into()])
        );
        // An unknown option is left for argh to report.
        assert_eq!(
            split(&["--other", "a"]),
            (vec!["--other".into()], vec!["a".into()])
        );
    }

    #[test]
    fn file_errors() {
        let error = |err| print_error("a", err);
        assert_eq!(
            error(Error::from(ErrorKind::NotFound)),
            "a: no such file or directory"
        );
        assert_eq!(
            error(Error::from(ErrorKind::IsADirectory)),
            "a: is a directory"
        );
        assert_eq!(
            error(Error::other("Invalid ELF64 object")),
            "a: invalid ELF64 object"
        );
        assert_eq!(
            error(Error::other("ELF object too small")),
            "a: ELF object too small"
        );
        assert_eq!(error(Error::other("not a PE object")), "a: not a PE object");
        assert_eq!(error(Error::other("")), "a: ");
    }

    #[test]
    fn format_check() {
        let dir = tempdir::TempDir::new().unwrap();
        let path = |name| dir.path().join(name).to_str().unwrap().to_string();
        std::fs::write(path("text"), "text\n").unwrap();

        let (article, host) = host_format();
        assert_eq!(
            check_format(&path("text")).unwrap_err().to_string(),
            format!("not {article} {host} object")
        );
        assert_eq!(
            check_format(&path("")).unwrap_err().kind(),
            ErrorKind::IsADirectory
        );
        // A missing file is left for the Mach-O backend, which also looks up
        // the dyld shared cache.
        let missing = check_format(&path("missing"));
        if cfg!(target_os = "macos") {
            assert!(missing.is_ok());
        } else {
            assert_eq!(missing.unwrap_err().kind(), ErrorKind::NotFound);
        }
    }

    #[test]
    fn object_formats() {
        let mut elf = [0; 16];
        elf[..5].copy_from_slice(b"\x7fELF\x02");
        let mut macho = [0; 16];
        macho[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        // The DOS header, pointing to the NT headers right after it, which
        // hold the PE32+ optional header magic.
        let mut pe = [0; 0x40 + 248];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        pe[0x58..0x5a].copy_from_slice(&[0x0b, 0x02]);

        let (article, host) = host_format();
        for (data, format) in [(&elf[..], "ELF"), (&macho, "Mach-O"), (&pe, "PE")] {
            match check_object(data) {
                Ok(()) => assert_eq!(format, host),
                Err(err) => {
                    assert_ne!(format, host);
                    assert_eq!(
                        err.to_string(),
                        format!(
                            "not {article} {host} object (this build inspects {host} objects only)"
                        )
                    );
                }
            }
        }
        assert_eq!(
            check_object(b"text\n").unwrap_err().to_string(),
            format!("not {article} {host} object")
        );
    }

    #[test]
    fn option_equals_value() {
        assert_eq!(
            split(&["--depth=0", "a"]),
            (vec!["--depth".into(), "0".into()], vec!["a".into()])
        );
        assert_eq!(
            split(&["--depth="]),
            (vec!["--depth".into(), "".into()], vec![])
        );
        assert_eq!(
            split(&["--depth=a=b"]),
            (vec!["--depth".into(), "a=b".into()], vec![])
        );
        // Only an option that takes a value is split, and only in its long
        // form.
        assert_eq!(
            split(&["--verbose=1"]),
            (vec!["--verbose=1".into()], vec![])
        );
        assert_eq!(split(&["--other=1"]), (vec!["--other=1".into()], vec![]));
        assert_eq!(split(&["-D=0"]), (vec!["-D=0".into()], vec![]));
        // Nor is an option value or a file.
        assert_eq!(
            split(&["--depth", "--depth=0"]),
            (vec!["--depth".into(), "--depth=0".into()], vec![])
        );
        assert_eq!(
            split(&["a", "--depth=0"]),
            (vec![], vec!["a".into(), "--depth=0".into()])
        );
        assert_eq!(
            split(&["--", "--depth=0"]),
            (vec![], vec!["--depth=0".into()])
        );
    }

    #[test]
    fn option_values() {
        let (opts, files) = parse_ok(&["--library-path=/x:/y", "a"]);
        assert_eq!(opts.library_path, "/x:/y");
        assert_eq!(files, ["a"]);
        #[cfg(any(target_os = "macos", windows))]
        {
            assert_eq!(parse_ok(&["a"]).0.depth, 1);
            assert_eq!(parse_ok(&["--depth=0", "a"]).0.depth, 0);
            let early_exit = parse("rldd", ["--depth=x", "a"].map(OsString::from))
                .err()
                .unwrap();
            assert_eq!(early_exit.status, Err(()));
        }
    }

    #[test]
    fn help_triggers() {
        for help in ["-h", "--help"] {
            let early_exit = parse("rldd", [OsString::from(help)]).err().unwrap();
            assert_eq!(early_exit.status, Ok(()));
        }
        // A file named help is inspected.
        let (opts, files) = parse_ok(&["help"]);
        assert_eq!(opts.args, ["help"]);
        assert_eq!(files, ["help"]);
        // So is a file named like a help trigger, after the first file or '--'.
        assert_eq!(parse_ok(&["a", "--help"]).0.args, ["a", "--help"]);
        assert_eq!(parse_ok(&["--", "-h"]).0.args, ["-h"]);
    }

    #[test]
    fn argh_errors() {
        for args in [
            &["--other", "a"][..],
            &["--library-path"],
            &["-h", "--other"],
        ] {
            let early_exit = parse("rldd", args.iter().map(OsString::from))
                .err()
                .unwrap();
            assert_eq!(early_exit.status, Err(()));
        }
    }

    // A name that is not valid UTF-8: a lone continuation byte on unix, and
    // an unpaired surrogate on Windows.
    #[cfg(unix)]
    fn invalid(prefix: &str) -> OsString {
        use std::os::unix::ffi::OsStringExt;
        let mut name = prefix.as_bytes().to_vec();
        name.push(0xff);
        OsString::from_vec(name)
    }

    #[cfg(windows)]
    fn invalid(prefix: &str) -> OsString {
        use std::os::windows::ffi::OsStringExt;
        let mut name: Vec<u16> = prefix.encode_utf16().collect();
        name.push(0xd800);
        OsString::from_wide(&name)
    }

    #[test]
    fn invalid_utf8() {
        let lossy = invalid("bin").to_string_lossy().into_owned();

        // A file name is kept as given, and only fails for that file.
        let (opts, files) = parse("rldd", [OsString::from("a"), invalid("bin")]).unwrap();
        assert_eq!(opts.args, ["a".to_string(), lossy.clone()]);
        assert_eq!(files, [OsString::from("a"), invalid("bin")]);

        // An option or an option value is an error.
        let error = |args: Vec<OsString>| split_command_line(args, FLAGS).err().unwrap();
        assert_eq!(
            error(vec!["--depth".into(), invalid("bin")]),
            format!("Error parsing option '--depth' with value '{lossy}': not valid UTF-8\n")
        );
        assert_eq!(
            error(vec![invalid("--depth=bin")]),
            format!("Error parsing option '--depth' with value '{lossy}': not valid UTF-8\n")
        );
        assert_eq!(
            error(vec![invalid("-")]),
            format!(
                "Unrecognized argument: {}\n",
                invalid("-").to_string_lossy()
            )
        );
    }
}
