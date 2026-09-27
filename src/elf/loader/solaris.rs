// The illumos and Solaris run-time linker.

use super::*;

pub(in crate::elf) struct Solaris;

impl Loader for Solaris {
    type Cache = search_path::SearchPathVec;

    // The illumos loader searches the LD_LIBRARY_PATH directories, then the
    // requesting object DT_RUNPATH or DT_RPATH (both handled the same way), and
    // at last the default directories: the get_next_dir search_rules, without
    // the crle(1) configuration ones.
    const SEARCH_ORDER: &'static [SearchStep] = &[
        SearchStep::LibraryPath,
        SearchStep::Runpath,
        SearchStep::Rpath,
        SearchStep::SystemDirs,
    ];

    fn check_elf_header(elc: &ElfInfo) -> bool {
        elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_SOLARIS
    }
}
