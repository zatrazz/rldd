// The illumos and Solaris run-time linker.

use super::*;

pub(in crate::elf) struct Solaris;

impl Loader for Solaris {
    type Cache = search_path::SearchPathVec;

    // The illumos loader searches the LD_LIBRARY_PATH directories, then the
    // requesting object DT_RUNPATH or DT_RPATH, and at last the default
    // directories: the get_next_dir search_rules, without the crle(1)
    // configuration ones.
    const SEARCH_ORDER: &'static [SearchStep] = &[
        SearchStep::LibraryPath,
        SearchStep::Rpath,
        SearchStep::SystemDirs,
    ];

    // The illumos loader records DT_RPATH and DT_RUNPATH in the same slot
    // (RPATH), so the last entry of either wins (elf_new_lmp), searched as the
    // object rpath.
    fn handle_search_paths(elc: &mut ElfInfo) {
        single_search_list(elc);
    }

    fn check_elf_header(elc: &ElfInfo) -> bool {
        elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_SOLARIS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A single rpath list, from the last of the DT_RPATH and DT_RUNPATH
    // entries, searched after the LD_LIBRARY_PATH directories.
    #[test]
    fn last_search_list_entry_wins() {
        let mut elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        elc.rpath = search_path::fixed_list(["/r"]);
        elc.runpath = search_path::fixed_list(["/u"]);
        elc.has_runpath = true;
        elc.runpath_last = false;
        Solaris::handle_search_paths(&mut elc);
        assert_eq!(elc.rpath, search_path::fixed_list(["/r"]));
        assert!(elc.runpath.is_empty() && !elc.has_runpath);
        assert!(matches!(
            Solaris::SEARCH_ORDER,
            [
                SearchStep::LibraryPath,
                SearchStep::Rpath,
                SearchStep::SystemDirs
            ]
        ));
    }
}
