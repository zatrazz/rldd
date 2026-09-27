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

// The musl loader search path comes from the $(PREFIX)/etc/ld-musl-$(ARCH).path
// file, where the ARCH is the one of the LOADER name and the PREFIX is the
// LOADER path without its last two components (so /etc for /lib), see
// load_library.
#[cfg(target_os = "linux")]
fn get_musl_path_file(loader: &str) -> Option<String> {
    let name = crate::pathutils::get_name(&std::path::Path::new(loader));
    let arch = name.strip_prefix("ld-musl-")?.strip_suffix(".so.1")?;
    let prefix = match loader.rmatch_indices('/').nth(1) {
        Some((z, _)) if loader.starts_with('/') => &loader[..z],
        _ => "",
    };
    Some(format!("{prefix}/etc/ld-musl-{arch}.path"))
}

// The file entries are split on colons and newlines, skipping the empty ones,
// and a file without any entry means no default directory at all.  Only a
// missing file falls back to the compiled-in default, while a file that can
// not be read for any other reason also means no default directory.
#[cfg(target_os = "linux")]
fn get_musl_system_dirs(loader: Option<&str>) -> search_path::SearchPathVec {
    let default = || search_path::fixed_list(["/lib", "/usr/local/lib", "/usr/lib"]);
    let Some(path_file) = loader.and_then(get_musl_path_file) else {
        return default();
    };
    match std::fs::read(&path_file) {
        Ok(contents) => String::from_utf8_lossy(&contents)
            .split([':', '\n'])
            .filter(|p| !p.is_empty())
            .map(search_path::SearchPath::fixed)
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => default(),
        Err(_) => search_path::SearchPathVec::new(),
    }
}

// The configuration built into a glibc loader, read from its file.
#[cfg(target_os = "linux")]
#[derive(Clone, Default)]
struct LoaderStrings {
    // The system directories.
    system_dirs: Option<Vec<String>>,
    // The $LIB expansion (DL_DST_LIB).
    dst_lib: Option<String>,
    // The glibc release.
    release: Option<GlibcRelease>,
}

// The loader keep the configured system directories in a static array of NUL
// separated absolute directories each ending with a slash.  The result is kep
// for the next object using the same loader.
#[cfg(target_os = "linux")]
fn loader_strings(loader: &str) -> LoaderStrings {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CACHE: Mutex<Option<HashMap<String, LoaderStrings>>> = Mutex::new(None);
    let Ok(mut cache) = CACHE.lock() else {
        return LoaderStrings::default();
    };
    let cache = cache.get_or_insert_with(HashMap::new);
    cache
        .entry(loader.to_string())
        .or_insert_with(|| read_loader_strings(loader).unwrap_or_default())
        .clone()
}

#[cfg(target_os = "linux")]
fn read_loader_strings(loader: &str) -> Option<LoaderStrings> {
    use object::{Object, ObjectSection};

    let mmap = crate::pathutils::map_file(&loader).ok()?;
    let object = object::File::parse(&*mmap).ok()?;
    let section = object.section_by_name(".rodata")?;
    let data = section.data().ok()?;
    let system_dirs = system_dirs_in(data);
    // The first system directory is the slibdir the loader was built with.
    let dst_lib = system_dirs
        .as_ref()
        .and_then(|dirs| dirs.first())
        .and_then(|slibdir| dst_lib_in(data, slibdir));
    let release = match super::ld_so_cache::glibc_release_in(&mmap) {
        Some((major, minor)) => GlibcRelease::Release(major, minor),
        None => GlibcRelease::Before233,
    };
    Some(LoaderStrings {
        system_dirs,
        dst_lib,
        release: Some(release),
    })
}

// The glibc release of a loader, from the version banner it has since glibc
// 2.33 ("ld.so (GNU libc) stable release version 2.39."), older without one.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GlibcRelease {
    Before233,
    Release(u32, u32),
}

// The subdirectories the glibc LOADER tries in each directory it searches
// before the directory itself, best first, for the ELC input object and on
// this machine (the capstr list of _dl_important_hwcaps): the glibc-hwcaps
// ones the CPU supports, since glibc 2.33.  A loader of an unknown release
// (none to read) is taken as a current one.
#[cfg(target_os = "linux")]
pub fn get_search_subdirs(loader: Option<&str>, elc: &ElfInfo) -> Vec<String> {
    use super::ld_so_cache::hwcap;

    let release = loader.and_then(|loader| loader_strings(loader).release);
    let mut r: Vec<String> = Vec::new();
    if release.is_none_or(|release| release >= GlibcRelease::Release(2, 33)) {
        r.extend(
            hwcap::glibc_hwcaps_subdirs(elc.e_machine, elc.ei_class, elc.ei_data)
                .iter()
                .map(|subdir| format!("glibc-hwcaps/{subdir}")),
        );
    }
    r
}

// The glibc build sets the $LIB expansion (DL_DST_LIB) to the last component
// of the slibdir (lib64, or lp64d for /lib64/lp64d on RISC-V), while some
// distributions set their own one (lib/x86_64-linux-gnu on Debian).  Find the
// longest trailing part of SLIBDIR that DATA holds as a string of its own.
#[cfg(target_os = "linux")]
fn dst_lib_in(data: &[u8], slibdir: &str) -> Option<String> {
    let dir = slibdir.trim_matches('/');
    let mut candidates = vec![dir];
    candidates.extend(dir.match_indices('/').map(|(i, _)| &dir[i + 1..]));
    candidates
        .into_iter()
        .filter(|candidate| !candidate.is_empty())
        .find(|candidate| data.split(|&b| b == 0).any(|s| s == candidate.as_bytes()))
        .map(str::to_string)
}

// The $LIB expansion of the glibc LOADER for the ELC object, or without a
// loader to read the upstream default for its architecture (the last
// component of the slibdir).
#[cfg(target_os = "linux")]
pub fn get_dst_lib(loader: Option<&str>, elc: &ElfInfo) -> Option<String> {
    if let Some(dst_lib) = loader.and_then(|loader| loader_strings(loader).dst_lib) {
        return Some(dst_lib);
    }
    let slibdir = get_slibdir(elc.e_machine, elc.ei_class, elc.e_flags).ok()?;
    slibdir.rsplit('/').next().map(str::to_string)
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
        return Ok(get_musl_system_dirs(
            super::musl_loader_path(elc).as_deref(),
        ));
    }
    if let Some(dirs) = loader.and_then(|loader| loader_strings(loader).system_dirs) {
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

// The rtld STANDARD_LIBRARY_PATH (rtld_paths.h) for an object of the EI_CLASS
// class.  The 32-bit compat loader of a 64-bit system (ld-elf32.so.1, built
// with the "32" COMPAT_libcompat suffix) appends the suffix to both /lib and
// /usr/lib, and has no /lib/casper.
#[cfg(any(target_os = "freebsd", all(test, target_os = "linux")))]
fn freebsd_standard_dirs(ei_class: object::elf::FileClass) -> &'static [&'static str] {
    if cfg!(target_pointer_width = "64") && ei_class == object::elf::ELFCLASS32 {
        &["/lib32", "/usr/lib32"]
    } else {
        &["/lib/casper", "/lib", "/usr/lib"]
    }
}

#[cfg(target_os = "freebsd")]
pub fn get_system_dirs(elc: &ElfInfo) -> Result<search_path::SearchPathVec, std::io::Error> {
    Ok(search_path::fixed_list(
        freebsd_standard_dirs(elc.ei_class).iter().copied(),
    ))
}

#[cfg(all(test, any(target_os = "freebsd", target_os = "linux")))]
mod freebsd_tests {
    use super::freebsd_standard_dirs;
    use object::elf::*;

    #[test]
    fn standard_dirs() {
        assert_eq!(
            freebsd_standard_dirs(ELFCLASS64),
            ["/lib/casper", "/lib", "/usr/lib"]
        );
        if cfg!(target_pointer_width = "64") {
            assert_eq!(freebsd_standard_dirs(ELFCLASS32), ["/lib32", "/usr/lib32"]);
        }
    }
}

#[cfg(target_os = "openbsd")]
pub fn get_system_dirs(_elc: &ElfInfo) -> Result<search_path::SearchPathVec, std::io::Error> {
    Ok(search_path::fixed_list(["/usr/lib"]))
}

// The NetBSD compat loaders (ld.elf_so-$(MLIBDIR) search the
// RTLD_DEFAULT_LIBRARY_PATH/$(MLIBDIR) directoryafter the default one.
// The subdirectory name follows the compat directories the system
// provides for each host architecture.
#[cfg(any(target_os = "netbsd", all(test, target_os = "linux")))]
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

#[cfg(all(test, any(target_os = "netbsd", target_os = "linux")))]
mod netbsd_tests {
    use super::netbsd_compat_subdir;
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

// The ld.so.1 default directories (_elf_def_dirs), which only depend on the
// class the loader is built for, whatever the architecture: /lib/64 and
// /usr/lib/64 for the 64-bit one.
#[cfg(any(
    target_os = "illumos",
    target_os = "solaris",
    all(test, target_os = "linux")
))]
fn solaris_default_dirs(ei_class: FileClass) -> Result<[&'static str; 2], std::io::Error> {
    match ei_class {
        ELFCLASS32 => Ok(["/lib", "/usr/lib"]),
        ELFCLASS64 => Ok(["/lib/64", "/usr/lib/64"]),
        _ => return_error(),
    }
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
pub fn get_system_dirs(elc: &ElfInfo) -> Result<search_path::SearchPathVec, std::io::Error> {
    Ok(search_path::fixed_list(solaris_default_dirs(elc.ei_class)?))
}

#[cfg(all(
    test,
    any(target_os = "illumos", target_os = "solaris", target_os = "linux")
))]
mod solaris_tests {
    use super::*;

    #[test]
    fn default_dirs() {
        assert_eq!(
            solaris_default_dirs(ELFCLASS32).unwrap(),
            ["/lib", "/usr/lib"]
        );
        assert_eq!(
            solaris_default_dirs(ELFCLASS64).unwrap(),
            ["/lib/64", "/usr/lib/64"]
        );
        assert!(solaris_default_dirs(ELFCLASSNONE).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod system_dirs_tests {
    use super::{dst_lib_in, get_musl_path_file, system_dirs_in, GlibcRelease};

    #[test]
    fn musl_path_file() {
        assert_eq!(
            get_musl_path_file("/lib/ld-musl-x86_64.so.1").as_deref(),
            Some("/etc/ld-musl-x86_64.path")
        );
        assert_eq!(
            get_musl_path_file("/usr/local/musl/lib/ld-musl-mips-sf.so.1").as_deref(),
            Some("/usr/local/musl/etc/ld-musl-mips-sf.path")
        );
        assert_eq!(
            get_musl_path_file("ld-musl-aarch64.so.1").as_deref(),
            Some("/etc/ld-musl-aarch64.path")
        );
        assert_eq!(get_musl_path_file("/lib/ld-linux.so.2"), None);
    }

    #[test]
    fn glibc_release_order() {
        assert!(GlibcRelease::Before233 < GlibcRelease::Release(2, 33));
        assert!(GlibcRelease::Release(2, 36) < GlibcRelease::Release(2, 37));
        assert!(GlibcRelease::Release(2, 39) < GlibcRelease::Release(3, 0));
    }

    #[test]
    fn dst_lib_of_the_loader() {
        // The Debian loader: the whole relative slibdir, which also holds
        // the architecture triplet as its tail.
        let data = b"ORIGIN\0PLATFORM\0LIB\0lib/x86_64-linux-gnu\0/lib/x86_64-linux-gnu/\0";
        assert_eq!(
            dst_lib_in(data, "/lib/x86_64-linux-gnu").as_deref(),
            Some("lib/x86_64-linux-gnu")
        );
        // The upstream build: the last component of the slibdir.
        let data = b"ORIGIN\0PLATFORM\0LIB\0lp64d\0/lib64/lp64d/\0/usr/lib64/lp64d/\0";
        assert_eq!(dst_lib_in(data, "/lib64/lp64d").as_deref(), Some("lp64d"));
        let data = b"LIB\0lib64\0/lib64/\0/usr/lib64/\0";
        assert_eq!(dst_lib_in(data, "/lib64").as_deref(), Some("lib64"));
        // Only a string of its own matches.
        assert_eq!(dst_lib_in(b"/lib64/\0xlib64\0", "/lib64"), None);
        assert_eq!(dst_lib_in(b"\0\0", "/"), None);
    }

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
