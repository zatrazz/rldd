// The illumos and Solaris run-time linker.

use super::*;

pub(in crate::elf) struct Solaris;

impl Loader for Solaris {
    type Cache = search_path::SearchPathVec;

    fn check_elf_header(elc: &ElfInfo) -> bool {
        elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_SOLARIS
    }
}
