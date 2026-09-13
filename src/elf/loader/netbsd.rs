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

    // The NetBSD loader handles DT_RPATH and DT_RUNPATH the same way, where both
    // are recorded as the object rpath (the last tag wins).
    fn handle_search_paths(elc: &mut ElfInfo) {
        if elc.has_runpath {
            elc.rpath = std::mem::take(&mut elc.runpath);
            elc.has_runpath = false;
        }
    }

    // The NetBSD loader expands the $ORIGIN token to the executable directory for
    // every object, so the requesting object value is propagated.
    fn origin_directory<P: AsRef<Path>>(filename: &P, melc: Option<&ElfInfo>) -> String {
        match melc {
            Some(melc) => melc.origin.clone(),
            None => filename
                .as_ref()
                .parent()
                .and_then(Path::to_str)
                .unwrap_or("")
                .to_string(),
        }
    }

    // The NetBSD loader does not check the EI_OSABI field.
    fn check_elf_header(_elc: &ElfInfo) -> bool {
        true
    }
}
