use crate::search_path;

// Global configuration used on program dynamic resolution:
// - ld_preload: Search path parser from ld.so.preload
// - ld_library_path: Search path parsed from --ld-library-path.
// - ld_so_conf: paths parsed from the ld.so.conf in the system.
// - system_dirs: system defaults deirectories based on binary architecture.
pub struct Config<'a> {
    pub ld_preload: &'a search_path::SearchPathVec,
    pub ld_library_path: &'a search_path::SearchPathVec,
    pub ld_so_conf: &'a Option<search_path::SearchPathVec>,
    pub system_dirs: &'a Option<search_path::SearchPathVec>,
    pub platform: Option<&'a String>,
    pub all: bool,
}
