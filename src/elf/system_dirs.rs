#[cfg(any(target_os = "linux", target_os = "illumos", target_os = "solaris"))]
use object::elf::*;

use super::ElfInfo;
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
                .map(search_path::SearchPath::fixed)
                .collect();
            if !dirs.is_empty() {
                return dirs;
            }
        }
    }
    search_path::fixed_list(["/lib", "/usr/local/lib", "/usr/lib"])
}

// The loader keep the configured system directories in a static array of NUL
// separated absolute directories each ending with a slash.  The result is kep
// for the next object using the same loader.
#[cfg(target_os = "linux")]
fn loader_system_dirs(loader: &str) -> Option<Vec<String>> {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CACHE: Mutex<Option<HashMap<String, Option<Vec<String>>>>> = Mutex::new(None);
    let mut cache = CACHE.lock().ok()?;
    let cache = cache.get_or_insert_with(HashMap::new);
    if let Some(dirs) = cache.get(loader) {
        return dirs.clone();
    }
    let dirs = read_loader_system_dirs(loader);
    cache.insert(loader.to_string(), dirs.clone());
    dirs
}

#[cfg(target_os = "linux")]
fn read_loader_system_dirs(loader: &str) -> Option<Vec<String>> {
    use object::{Object, ObjectSection};

    let mmap = crate::pathutils::map_file(&loader).ok()?;
    let object = object::File::parse(&*mmap).ok()?;
    let section = object.section_by_name(".rodata")?;
    system_dirs_in(section.data().ok()?)
}

// Extract the longest run of consecutive NUL terminated strings which
// are absolute directories ending with a slash, at least two of them
// (the upstream default has two), with the trailing slash dropped.
#[cfg(target_os = "linux")]
fn system_dirs_in(data: &[u8]) -> Option<Vec<String>> {
    fn is_directory(s: &[u8]) -> bool {
        s.len() >= 2
            && s[0] == b'/'
            && s[s.len() - 1] == b'/'
            && s.iter().all(|b| (0x20..=0x7e).contains(b))
    }
    let mut best: Vec<String> = Vec::new();
    let mut run: Vec<String> = Vec::new();
    for s in data.split(|&b| b == 0) {
        if is_directory(s) {
            let s = std::str::from_utf8(s).unwrap();
            run.push(match s.trim_end_matches('/') {
                "" => "/".to_string(),
                dir => dir.to_string(),
            });
            continue;
        }
        if run.len() > best.len() {
            best = std::mem::take(&mut run);
        }
        run.clear();
    }
    if run.len() > best.len() {
        best = run;
    }
    if best.len() >= 2 {
        Some(best)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
pub fn get_system_dirs(
    loader: Option<&str>,
    elc: &ElfInfo,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    if elc.is_musl {
        return Ok(get_musl_system_dirs(&elc.interp));
    }
    if let Some(dirs) = loader.and_then(loader_system_dirs) {
        use crate::search_path::SearchPathVecExt;
        let mut r = search_path::SearchPathVec::new();
        for dir in dirs {
            r.add_path(&dir);
        }
        return Ok(r);
    }
    // Without a loader to read, the upstream default of the slibdir and its
    // /usr counterpart.
    let path = get_slibdir(elc.e_machine, elc.ei_class, elc.e_flags)?;
    // The '/usr' part is configurable on glibc install, however there is no direct
    // way to obtain it on runtime.
    // TODO: Add an option to override it.
    Ok(search_path::fixed_list([
        path.to_string(),
        format!("/usr{path}"),
    ]))
}

// The bionic loader default search paths, used when no ld.config.txt applies:
// the system, odm, and vendor library directories, each one preceded by the
// sanitizer specific variant for an instrumented binary.  The /odm partition
// was only added on Android 9.
#[cfg(target_os = "android")]
pub fn get_system_dirs(elc: &ElfInfo) -> Result<search_path::SearchPathVec, std::io::Error> {
    use crate::elf::android;

    let release = android::get_release()?;
    let interp = elc.interp.as_deref();
    let is_asan = android::is_asan(interp);
    let is_hwasan = android::is_hwasan(interp);

    let lib = android::libpath(elc.ei_class);

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
    let mut push = |path: String| r.push(search_path::SearchPath::fixed(path));

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
pub fn get_system_dirs(elc: &ElfInfo) -> Result<search_path::SearchPathVec, std::io::Error> {
    // The rtld STANDARD_LIBRARY_PATH, with the COMPAT_libcompat suffix for
    // the 32-bit compat objects.
    let dirs: &[&str] =
        if cfg!(target_pointer_width = "64") && elc.ei_class == object::elf::ELFCLASS32 {
            &["/lib/casper", "/lib32", "/usr/lib32"]
        } else {
            &["/lib/casper", "/lib", "/usr/lib"]
        };
    Ok(search_path::fixed_list(dirs.iter().copied()))
}

#[cfg(target_os = "openbsd")]
pub fn get_system_dirs(_elc: &ElfInfo) -> Result<search_path::SearchPathVec, std::io::Error> {
    Ok(search_path::fixed_list(["/usr/lib"]))
}

// The NetBSD compat loaders (ld.elf_so-$(MLIBDIR) search the
// RTLD_DEFAULT_LIBRARY_PATH/$(MLIBDIR) directoryafter the default one.
// The subdirectory name follows the compat directories the system
// provides for each host architecture.
#[cfg(target_os = "netbsd")]
pub fn netbsd_compat_subdir(
    e_machine: object::elf::Machine,
    ei_class: object::elf::FileClass,
    e_flags: object::elf::FileFlags,
) -> Option<&'static str> {
    use object::elf::*;
    if cfg!(target_arch = "x86_64") && e_machine == EM_386 {
        Some("i386")
    } else if cfg!(target_arch = "sparc64") && matches!(e_machine, EM_SPARC | EM_SPARC32PLUS) {
        Some("sparc")
    } else if cfg!(target_arch = "powerpc64") && e_machine == EM_PPC {
        Some("powerpc")
    } else if cfg!(target_arch = "riscv64") && e_machine == EM_RISCV && ei_class == ELFCLASS32 {
        Some("rv32")
    } else if cfg!(target_arch = "aarch64") && e_machine == EM_ARM {
        if e_flags.contains(FileFlags(EF_ARM_ABI_FLOAT_HARD)) {
            Some("eabihf")
        } else {
            Some("eabi")
        }
    } else if cfg!(target_arch = "mips64") && e_machine == EM_MIPS && ei_class == ELFCLASS32 {
        if e_flags.contains(EF_MIPS_ABI2) {
            Some("n32")
        } else {
            Some("o32")
        }
    } else {
        None
    }
}

#[cfg(target_os = "netbsd")]
pub fn get_system_dirs(elc: &ElfInfo) -> Result<search_path::SearchPathVec, std::io::Error> {
    let mut dirs = vec!["/usr/lib".to_string()];
    if let Some(subdir) = netbsd_compat_subdir(elc.e_machine, elc.ei_class, elc.e_flags) {
        dirs.push(format!("/usr/lib/{subdir}"));
    }
    Ok(search_path::fixed_list(dirs))
}

#[cfg(all(test, target_os = "netbsd"))]
mod tests {
    use super::*;
    use object::elf::*;

    #[test]
    fn compat_subdir() {
        let native = netbsd_compat_subdir(EM_X86_64, ELFCLASS64, FileFlags(0));
        assert_eq!(native, None);
        if cfg!(target_arch = "x86_64") {
            assert_eq!(
                netbsd_compat_subdir(EM_386, ELFCLASS32, FileFlags(0)),
                Some("i386")
            );
        }
    }
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
pub fn get_system_dirs(elc: &ElfInfo) -> Result<search_path::SearchPathVec, std::io::Error> {
    match elc.e_machine {
        EM_386 => Ok(search_path::fixed_list(["/lib", "/usr/lib"])),
        EM_X86_64 => Ok(search_path::fixed_list(["/lib64", "/usr/lib/64"])),
        _ => return_error(),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod system_dirs_tests {
    use super::system_dirs_in;

    #[test]
    fn run_of_directories() {
        let data = b"foo\0/etc/ld.so.cache\0/lib/x86_64-linux-gnu/\0/usr/lib/x86_64-linux-gnu/\0\
            /lib/\0/usr/lib/\0\0\0/tmp/\0lib/x86_64-linux-gnu\0";
        assert_eq!(
            system_dirs_in(data),
            Some(vec![
                "/lib/x86_64-linux-gnu".to_string(),
                "/usr/lib/x86_64-linux-gnu".to_string(),
                "/lib".to_string(),
                "/usr/lib".to_string()
            ])
        );
    }

    #[test]
    fn longest_run_wins() {
        let data = b"/lib64/\0/usr/lib64/\0x\0/a/\0/b/\0/c/\0";
        assert_eq!(
            system_dirs_in(data),
            Some(vec!["/a".to_string(), "/b".to_string(), "/c".to_string()])
        );
    }

    #[test]
    fn single_directory_is_not_the_list() {
        assert_eq!(system_dirs_in(b"/dev/\0\0/proc/\0/\xff/\0"), None);
        assert_eq!(system_dirs_in(b"/\0/\0"), None);
    }
}
