// The run-time linker rules that differ between the systems.  Each system
// implements Loader, where the default methods are the rules most of them
// share, and the resolution calls the one for the target through Rtld.

use std::io::Error;
use std::path::{Path, PathBuf};

use super::*;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "netbsd")]
mod netbsd;
// Also built for the Linux tests, which check its dependency matching.
#[cfg(any(target_os = "openbsd", all(test, target_os = "linux")))]
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

    // The entries of the --preload LIST (LD_PRELOAD) for the ELC input
    // object.  Most loaders separate them with colons or whitespace.
    fn preload_list(list: &str, _elc: &ElfInfo) -> Vec<String> {
        search_path::from_preload(list)
    }

    // Record the loader specific flavor of the parsed object, handed down
    // from MELC, the object loading it (None for the input object).
    fn handle_loader(_elc: &mut ElfInfo, _melc: Option<&ElfInfo>) {}

    // Adjust the DT_RPATH and DT_RUNPATH of the parsed object.
    fn handle_search_paths(_elc: &mut ElfInfo) {}

    // The entries of LIST, a search list of the SITE kind for the ELC object,
    // with the dynamic string tokens expanded: each directory, or the entry as
    // written when the loader drops it because of a token without a value.
    // Most loaders split the list on colons and skip the empty entries.
    fn search_list(
        list: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Vec<Result<String, String>> {
        list.split(':')
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                Self::expand_tokens(entry, site, elc, platform).ok_or_else(|| entry.to_string())
            })
            .collect()
    }

    // Expand the dynamic string tokens of INPUT, an entry of the SITE kind
    // for the ELC object, or None when the loader drops the entry because a
    // token has no value.  Most loaders replace $ORIGIN and $PLATFORM, with
    // or without braces, wherever they appear on the search lists and the
    // dependency names of an object.
    fn expand_tokens(
        input: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Option<String> {
        if matches!(site, TokenSite::LibraryPath | TokenSite::Preload) {
            return Some(input.to_string());
        }
        let mut r = input.to_string();
        if r.contains("$ORIGIN") || r.contains("${ORIGIN}") {
            r = replace_token(&r, "ORIGIN", elc.origin.as_deref()?);
        }
        let platform = platform
            .map(String::as_str)
            .or_else(|| platform::get(elc.e_machine, elc.ei_data))
            .unwrap_or("");
        Some(replace_token(&r, "PLATFORM", platform))
    }

    // The directory the $ORIGIN token expands to for the object being opened,
    // None when it is not valid UTF-8.  The glibc loader uses the directory of
    // the path the object was loaded through (the executable one is
    // canonicalized beforehand).
    fn origin_directory<P: AsRef<Path>>(filename: &P, _melc: Option<&ElfInfo>) -> Option<String> {
        filename
            .as_ref()
            .parent()
            .and_then(Path::to_str)
            .map(str::to_string)
    }

    // The directory the $ORIGIN token expands to for the ELC input object,
    // opened as FILENAME, the canonical path of the GIVEN one.  The kernel
    // resolves the path of an executable before the loader runs
    // (/proc/self/exe on Linux), so the loaders see the canonical path.
    fn root_origin_directory(_given: &Path, filename: &Path, _elc: &ElfInfo) -> Option<String> {
        Self::origin_directory(&filename, None)
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
        dtneeded: &str,
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
        dtneeded: &str,
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

// Replace the $TOKEN and ${TOKEN} occurrences of INPUT with VALUE.
fn replace_token(input: &str, token: &str, value: &str) -> String {
    input
        .replace(&format!("${token}"), value)
        .replace(&format!("${{{token}}}"), value)
}

// The FreeBSD and OpenBSD loaders canonicalize the object path first
// (realpath), so a symlink or a '..' component on a search path does not leak
// into the $ORIGIN expansion.
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    all(test, target_os = "linux")
))]
fn canonical_origin_directory<P: AsRef<Path>>(filename: &P) -> Option<String> {
    let path = fs::canonicalize(filename).unwrap_or_else(|_| filename.as_ref().to_path_buf());
    path.parent().and_then(Path::to_str).map(str::to_string)
}
