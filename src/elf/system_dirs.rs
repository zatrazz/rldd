#[cfg(any(
    target_os = "linux",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "android"
))]
use object::elf::*;

use crate::search_path;

#[allow(dead_code)]
fn return_error<T>() -> Result<T, std::io::Error> {
    Err(std::io::Error::other("failed to get default system dir"))
}

// Return the default system directory for the architectures and class.  It is hard
// wired on glibc install for each triplet (the $slibdir).
#[cfg(target_os = "linux")]
pub fn get_slibdir(
    e_machine: Machine,
    ei_class: FileClass,
    e_flags: FileFlags,
) -> Result<&'static str, std::io::Error> {
    // Not all machines are supported by object crate.
    const EM_ARCV2: Machine = Machine(195);

    match e_machine {
        EM_AARCH64 | EM_PPC64 | EM_SPARCV9 => Ok("/lib64"),
        EM_ALPHA | EM_ARCV2 | EM_ARM | EM_CSKY | EM_PARISC | EM_386 | EM_68K | EM_MICROBLAZE
        | EM_ALTERA_NIOS2 | EM_OPENRISC | EM_PPC | EM_SH => Ok("/lib"),
        EM_S390 | EM_SPARC | EM_SPARC32PLUS => match ei_class {
            ELFCLASS32 => Ok("/lib"),
            ELFCLASS64 => Ok("/lib64"),
            _ => return_error(),
        },
        // The N32 objects (EF_MIPS_ABI2) use a separate directory.
        EM_MIPS | EM_MIPS_RS3_LE => match ei_class {
            ELFCLASS32 => {
                if e_flags.contains(EF_MIPS_ABI2) {
                    Ok("/lib32")
                } else {
                    Ok("/lib")
                }
            }
            ELFCLASS64 => Ok("/lib64"),
            _ => return_error(),
        },
        // The non double-float ABIs use a suffixed directory.
        EM_LOONGARCH => {
            let double =
                e_flags & FileFlags(EF_LARCH_ABI_MODIFIER_MASK) == EF_LARCH_ABI_DOUBLE_FLOAT;
            match ei_class {
                ELFCLASS32 => Ok(if double { "/lib32" } else { "/lib32/sf" }),
                ELFCLASS64 => Ok(if double { "/lib64" } else { "/lib64/sf" }),
                _ => return_error(),
            }
        }
        EM_RISCV => {
            let double = e_flags & FileFlags(EF_RISCV_FLOAT_ABI) == EF_RISCV_FLOAT_ABI_DOUBLE;
            match ei_class {
                ELFCLASS32 => Ok(if double {
                    "/lib32/ilp32d"
                } else {
                    "/lib32/ilp32"
                }),
                ELFCLASS64 => Ok(if double {
                    "/lib64/lp64d"
                } else {
                    "/lib64/lp64"
                }),
                _ => return_error(),
            }
        }
        EM_X86_64 => match ei_class {
            ELFCLASS32 => Ok("/libx32"),
            ELFCLASS64 => Ok("/lib64"),
            _ => return_error(),
        },
        _ => return_error(),
    }
}

// The musl loader search path comes from the /etc/ld-musl-$(ARCH).path file
// (colon or newline separated), with a compiled-in default.  The ARCH is
// taken from the loader name, or from the installed loader config when the
// object does not have a PT_INTERP segment (shared libraries).
#[cfg(target_os = "linux")]
fn get_musl_path_file(interp: &Option<String>) -> Option<String> {
    use std::path::Path;
    if let Some(interp) = interp {
        let name = crate::pathutils::get_name(&Path::new(interp));
        let arch = name.strip_prefix("ld-musl-")?.strip_suffix(".so.1")?;
        return Some(format!("/etc/ld-musl-{arch}.path"));
    }
    for entry in std::fs::read_dir("/etc").ok()?.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with("ld-musl-") && name.ends_with(".path") {
                return Some(format!("/etc/{name}"));
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_musl_system_dirs(interp: &Option<String>) -> search_path::SearchPathVec {
    if let Some(path_file) = get_musl_path_file(interp) {
        if let Ok(contents) = std::fs::read_to_string(&path_file) {
            let dirs: search_path::SearchPathVec = contents
                .split([':', '\n'])
                .filter(|p| !p.is_empty())
                .map(|p| search_path::SearchPath {
                    path: p.to_string(),
                    dev: 0,
                    ino: 0,
                })
                .collect();
            if !dirs.is_empty() {
                return dirs;
            }
        }
    }
    ["/lib", "/usr/local/lib", "/usr/lib"]
        .iter()
        .map(|p| search_path::SearchPath {
            path: p.to_string(),
            dev: 0,
            ino: 0,
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub fn get_system_dirs(
    interp: &Option<String>,
    is_musl: bool,
    e_machine: Machine,
    ei_class: FileClass,
    e_flags: FileFlags,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    if is_musl {
        return Ok(get_musl_system_dirs(interp));
    }
    let path = get_slibdir(e_machine, ei_class, e_flags)?;
    Ok(vec![
        search_path::SearchPath {
            path: path.to_string(),
            dev: 0,
            ino: 0,
        },
        // The '/usr' part is configurable on glibc install, however there is no direct
        // way to obtain it on runtime.
        // TODO: Add an option to override it.
        search_path::SearchPath {
            path: format!("/usr{path}"),
            dev: 0,
            ino: 0,
        },
    ])
}

// The bionic loader default search paths, used when no ld.config.txt applies:
// the system, odm, and vendor library directories, each one preceded by the
// sanitizer specific variant for an instrumented binary.  The /odm partition
// was only added on Android 9.
#[cfg(target_os = "android")]
pub fn get_system_dirs(
    interp: &Option<String>,
    _is_musl: bool,
    _e_machine: Machine,
    ei_class: FileClass,
    _e_flags: FileFlags,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    use crate::elf::android;

    let release = android::get_release()?;
    let interp = interp.as_deref();
    let is_asan = android::is_asan(interp);
    let is_hwasan = android::is_hwasan(interp);

    let lib = android::libpath(ei_class);

    // Android 8 moved the asan directories below /data/asan, the older
    // releases use /data/$(LIB) for the system one and /data/vendor/$(LIB)
    // for the vendor one.
    let asan_dir = |partition: &str| {
        if release < android::AndroidRelease::R26 {
            match partition {
                "/system" => format!("/data/{lib}"),
                _ => format!("/data{partition}/{lib}"),
            }
        } else {
            format!("/data/asan{partition}/{lib}")
        }
    };

    let mut r = search_path::SearchPathVec::new();
    let mut push = |path: String| {
        r.push(search_path::SearchPath {
            path,
            dev: 0,
            ino: 0,
        })
    };

    for partition in ["/system", "/odm", "/vendor"] {
        // The /odm partition was added on Android 9.
        if partition == "/odm" && release < android::AndroidRelease::R28 {
            continue;
        }
        if is_asan {
            push(asan_dir(partition));
        } else if is_hwasan {
            push(format!("{partition}/{lib}/hwasan"));
        }
        push(format!("{partition}/{lib}"));
    }
    Ok(r)
}

#[cfg(target_os = "freebsd")]
pub fn get_system_dirs(
    _interp: &Option<String>,
    _is_musl: bool,
    _e_machine: object::elf::Machine,
    ei_class: object::elf::FileClass,
    _e_flags: object::elf::FileFlags,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    // The rtld STANDARD_LIBRARY_PATH, with the COMPAT_libcompat suffix for
    // the 32-bit compat objects.
    let dirs: &[&str] = if cfg!(target_pointer_width = "64") && ei_class == object::elf::ELFCLASS32
    {
        &["/lib/casper", "/lib32", "/usr/lib32"]
    } else {
        &["/lib/casper", "/lib", "/usr/lib"]
    };
    Ok(dirs
        .iter()
        .map(|path| search_path::SearchPath {
            path: path.to_string(),
            dev: 0,
            ino: 0,
        })
        .collect())
}

#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub fn get_system_dirs(
    _interp: &Option<String>,
    _is_musl: bool,
    _e_machine: object::elf::Machine,
    _ei_class: object::elf::FileClass,
    _e_flags: object::elf::FileFlags,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    Ok(vec![search_path::SearchPath {
        path: "/usr/lib".to_string(),
        dev: 0,
        ino: 0,
    }])
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
pub fn get_system_dirs(
    _interp: &Option<String>,
    _is_musl: bool,
    e_machine: Machine,
    _ei_class: FileClass,
    _e_flags: FileFlags,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    match e_machine {
        EM_386 => Ok(vec![
            search_path::SearchPath {
                path: "/lib".to_string(),
                dev: 0,
                ino: 0,
            },
            search_path::SearchPath {
                path: "/usr/lib".to_string(),
                dev: 0,
                ino: 0,
            },
        ]),
        EM_X86_64 => Ok(vec![
            search_path::SearchPath {
                path: "/lib64".to_string(),
                dev: 0,
                ino: 0,
            },
            search_path::SearchPath {
                path: "/usr/lib/64".to_string(),
                dev: 0,
                ino: 0,
            },
        ]),
        _ => return_error(),
    }
}
