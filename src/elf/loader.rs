// The run-time linker rules that differ between the systems.  Each system
// implements Loader, where the default methods are the rules most of them
// share, and the resolution calls the one for the target through Rtld.

use std::io::Error;
use std::path::{Path, PathBuf};

use object::read::elf::FileHeader;

use super::*;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "netbsd")]
mod netbsd;
#[cfg(target_os = "openbsd")]
mod openbsd;
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
mod solaris;

#[cfg(target_os = "android")]
pub(super) use android::Android as Rtld;
#[cfg(target_os = "freebsd")]
pub(super) use freebsd::FreeBsd as Rtld;
#[cfg(target_os = "linux")]
pub(super) use linux::Linux as Rtld;
#[cfg(target_os = "netbsd")]
pub(super) use netbsd::NetBsd as Rtld;
#[cfg(target_os = "openbsd")]
pub(super) use openbsd::OpenBsd as Rtld;
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
pub(super) use solaris::Solaris as Rtld;

pub(super) trait Loader {
    // The loader search cache (ld.so.cache, ld.config.txt, the hints files).
    type Cache: SearchCache;

    // The search order for a dependency name.  Most loaders search the object
    // DT_RPATH, the LD_LIBRARY_PATH directories, the object DT_RUNPATH, the
    // loader cache/hints, and at last the default directories.
    const SEARCH_ORDER: &'static [SearchStep] = &[
        SearchStep::Rpath,
        SearchStep::LibraryPath,
        SearchStep::Runpath,
        SearchStep::Cache,
        SearchStep::SystemDirs,
    ];

    // Load the loader search cache for BINARY.  The cache/hints/config file is
    // usually an optional file and failing to open it does not incur on a
    // resolution failure.
    fn load_so_cache<P: AsRef<Path>>(
        _ld_cache: &mut Option<Self::Cache>,
        _binary: &P,
        _elc: &ElfInfo,
    ) {
    }

    // Whether the default system directories are searched with CACHE loaded.
    fn load_system_dirs(_ld_cache: &Option<Self::Cache>) -> bool {
        true
    }

    // The objects the loader preloads for the INTERP loader on its own
    // (besides the --preload entries).
    fn load_ld_so_preload(_interp: &Option<String>) -> Vec<String> {
        Vec::new()
    }

    // Record the loader specific flavor of the parsed object.
    fn handle_loader(_elc: &mut ElfInfo) {}

    // Adjust the DT_RPATH and DT_RUNPATH of the parsed object.
    fn handle_search_paths(_elc: &mut ElfInfo) {}

    // Expand the $LIB token of a DT_RPATH/DT_RUNPATH entry.
    fn parse_elf_dyn_searchpath_lib<Elf: FileHeader>(
        _endian: Elf::Endian,
        _elf: &Elf,
        _dynstr: &mut String,
    ) {
    }

    // The directory the $ORIGIN token expands to for the object being opened.
    // The glibc loader uses the directory of the path the object was loaded
    // through (the executable one is canonicalized beforehand).
    fn origin_directory<P: AsRef<Path>>(filename: &P, _melc: Option<&ElfInfo>) -> String {
        filename
            .as_ref()
            .parent()
            .and_then(Path::to_str)
            .unwrap_or("")
            .to_string()
    }

    // Check the ELF header OS ABI fields, which for the GNU loaders (glibc and
    // bionic) depend on the architecture.
    fn check_elf_header(elc: &ElfInfo) -> bool {
        let maxver = match elc.e_machine {
            EM_MIPS | EM_MIPS_RS3_LE => 6,
            EM_PPC | EM_PPC64 | EM_SPARC | EM_X86_64 | EM_RISCV => 5,
            _ => 4,
        };

        let check_elf_osabi = match elc.e_machine {
            EM_ARM => |osabi: OsAbi| {
                osabi == ELFOSABI_SYSV || osabi == ELFOSABI_GNU || osabi == ELFOSABI_ARM_AEABI
            },
            _ => |osabi: OsAbi| osabi == ELFOSABI_SYSV || osabi == ELFOSABI_GNU,
        };

        let check_elf_abiversion = match elc.e_machine {
            EM_MIPS => |osabi: OsAbi, ver: u8, maxver: u8| {
                ver == 0
                    || (osabi == ELFOSABI_SYSV && ver < 6)
                    || (osabi == ELFOSABI_GNU && ver < maxver)
            },
            _ => |osabi: OsAbi, ver: u8, maxver: u8| {
                ver == 0 || (osabi == ELFOSABI_GNU && ver < maxver)
            },
        };

        check_elf_osabi(elc.ei_osabi) && check_elf_abiversion(elc.ei_osabi, elc.ei_abiver, maxver)
    }

    // Remap the dependency name for the referencing object path.
    fn libmap_dependency(_config: &Config, _refpath: &str, dependency: &String) -> String {
        dependency.to_string()
    }

    // The input file actually inspected, which the loader might redirect.
    fn redirect_root(
        filename: PathBuf,
        elc: ElfInfo,
        _platform: Option<&String>,
    ) -> (PathBuf, ElfInfo) {
        (filename, elc)
    }

    // Add the nodes the loader adds on its own before the dependencies.
    fn resolve_binary_arch(
        _elc: &ElfInfo,
        _deptree: &mut DepTree,
        _depp: usize,
    ) -> Result<(), Error> {
        Ok(())
    }

    // Add the loader itself once the dependencies are resolved.
    fn add_loader_dependency(
        _config: &Config,
        _elc: &ElfInfo,
        _deptree: &mut DepTree,
        _root_depp: usize,
    ) {
    }

    // The path candidate for a dependency on a search directory.
    fn dependency_path(dir: &str, dtneeded: &str) -> PathBuf {
        Path::new(dir).join(dtneeded)
    }

    // Whether the object DT_RPATH is searched.
    fn rpath_search(_elc: &ElfInfo) -> bool {
        true
    }
}

// The operations that depend on the loader cache format.
pub(super) trait SearchCache {
    // The namespace an object is loaded in, used to resolve its own
    // dependencies.  Only the Android linker has them.
    type Namespace: Clone + std::fmt::Debug + Default;

    // The summary shown on the search path information.
    fn summary(&self) -> String;

    // Resolve DTNEEDED through the cache.
    fn resolve<'a>(
        &'a self,
        dtneeded: &'a String,
        platform: Option<&String>,
        elc: &'a ElfInfo,
        namespace: &Self::Namespace,
    ) -> Option<ResolvedDependency<'a>>;
}

// The loaders without linker namespaces.
#[derive(Clone, Debug, Default)]
pub(super) struct NoNamespace;

// The hints and configuration files holding a directory list (the BSD and the
// Solaris loaders).
impl SearchCache for search_path::SearchPathVec {
    type Namespace = NoNamespace;

    fn summary(&self) -> String {
        search_path::format_list(self)
    }

    fn resolve<'a>(
        &'a self,
        dtneeded: &'a String,
        platform: Option<&String>,
        elc: &'a ElfInfo,
        _namespace: &NoNamespace,
    ) -> Option<ResolvedDependency<'a>> {
        search_dirs(
            self,
            dtneeded,
            elc,
            platform,
            DepMode::LdCache,
            &Default::default(),
        )
    }
}

// The FreeBSD and OpenBSD loaders canonicalize the object path first
// (realpath), so a symlink or a '..' component on a search path does not leak
// into the $ORIGIN expansion.
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
fn canonical_origin_directory<P: AsRef<Path>>(filename: &P) -> String {
    let path = fs::canonicalize(filename).unwrap_or_else(|_| filename.as_ref().to_path_buf());
    path.parent()
        .and_then(Path::to_str)
        .unwrap_or("")
        .to_string()
}
