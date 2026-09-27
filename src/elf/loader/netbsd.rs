// The NetBSD run-time linker.

use super::*;

pub(in crate::elf) struct NetBsd;

impl Loader for NetBsd {
    type Cache = search_path::SearchPathVec;

    // The NetBSD loader searches the LD_LIBRARY_PATH directories, then the
    // ld.so.conf ones, then the requesting object DT_RPATH/DT_RUNPATH, and at last
    // the default directories.
    const SEARCH_ORDER: &'static [SearchStep] = &[
        SearchStep::LibraryPath,
        SearchStep::Cache,
        SearchStep::Rpath,
        SearchStep::SystemDirs,
    ];

    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        _binary: &P,
        _ecl: &ElfInfo,
    ) {
        if ld_cache.is_none() {
            *ld_cache = ld_so_conf_netbsd::parse_ld_so_conf(&Path::new("/etc/ld.so.conf")).ok()
        }
    }

    // The NetBSD loader records DT_RPATH and DT_RUNPATH in the same slot, so
    // the last entry of either wins (_rtld_digest_dynamic), searched as the
    // object rpath.
    fn handle_search_paths(elc: &mut ElfInfo) {
        single_search_list(elc);
    }

    // The NetBSD loader expands the $ORIGIN token to the executable directory for
    // every object, so the requesting object value is propagated.
    fn origin_directory<P: AsRef<Path>>(filename: &P, melc: Option<&ElfInfo>) -> Option<String> {
        match melc {
            Some(melc) => melc.origin.clone(),
            None => filename
                .as_ref()
                .parent()
                .and_then(Path::to_str)
                .map(str::to_string),
        }
    }

    // The NetBSD loader does not check the EI_OSABI field.
    fn check_elf_header(_elc: &ElfInfo) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(rpath: &[&str], runpath: &[&str], runpath_last: bool) -> ElfInfo {
        let mut elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        elc.rpath = search_path::fixed_list(rpath.iter().copied());
        elc.runpath = search_path::fixed_list(runpath.iter().copied());
        elc.has_runpath = !runpath.is_empty();
        elc.runpath_last = runpath_last;
        elc
    }

    // A single rpath list, from the last of the DT_RPATH and DT_RUNPATH
    // entries.
    #[test]
    fn last_search_list_entry_wins() {
        for (mut elc, rpath) in [
            (object(&["/r"], &["/u"], true), "/u"),
            (object(&["/r"], &["/u"], false), "/r"),
            (object(&[], &["/u"], true), "/u"),
            (object(&["/r"], &[], false), "/r"),
        ] {
            NetBsd::handle_search_paths(&mut elc);
            assert_eq!(elc.rpath, search_path::fixed_list([rpath]));
            assert!(elc.runpath.is_empty());
            assert!(!elc.has_runpath);
        }
    }
}
