// The FreeBSD run-time linker.

use super::*;

pub(in crate::elf) struct FreeBsd;

impl Loader for FreeBsd {
    type Cache = search_path::SearchPathVec;

    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        _binary: &P,
        elc: &ElfInfo,
    ) {
        // The 32-bit compat objects use a separate hints file (the rtld
        // COMPAT_libcompat suffix), so the cache is reloaded for each binary.
        let hints = if cfg!(target_pointer_width = "64") && elc.ei_class == ELFCLASS32 {
            "/var/run/ld-elf32.so.hints"
        } else {
            "/var/run/ld-elf.so.hints"
        };
        *ld_cache = ld_hints_freebsd::parse_ld_so_hints(&Path::new(hints)).ok();
    }

    fn origin_directory<P: AsRef<Path>>(filename: &P, _melc: Option<&ElfInfo>) -> String {
        canonical_origin_directory(filename)
    }

    fn check_elf_header(elc: &ElfInfo) -> bool {
        elc.ei_osabi == ELFOSABI_FREEBSD
    }

    // Remap the dependency name using the libmap.conf mappings for the referencing
    // object path.
    fn libmap_dependency(config: &Config, refpath: &str, dependency: &String) -> String {
        match &config.libmap {
            Some(libmap) => libmap
                .lookup(refpath, dependency)
                .map(|target| target.to_string())
                .unwrap_or_else(|| dependency.to_string()),
            None => dependency.to_string(),
        }
    }
}
