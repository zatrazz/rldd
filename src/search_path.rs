// Provides helper function to handle search path for library resolution, for either DT_RPATH,
// DT_RUNPATH, ld.so.conf, or system directories.

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::path::Path;
use std::{fmt, fs};

// The character that separates the directories of a search path list.
#[cfg(unix)]
pub const LIST_SEPARATOR: char = ':';
#[cfg(windows)]
pub const LIST_SEPARATOR: char = ';';

#[derive(Eq, Debug, Clone)]
pub struct SearchPath {
    pub path: String,
    // The identity used to skip duplicated entries.  The unix loaders compare
    // the device and inode number, while Windows has no stable equivalent for
    // a path. So the case-folded canonical path is used instead.
    #[cfg(unix)]
    pub dev: u64,
    #[cfg(unix)]
    pub ino: u64,
    #[cfg(windows)]
    key: String,
}
impl PartialEq for SearchPath {
    #[cfg(unix)]
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.dev == other.dev && self.ino == other.ino
    }
    #[cfg(windows)]
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}
impl fmt::Display for SearchPath {
    #[cfg(unix)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({},{})", self.path, self.dev, self.ino)
    }
    #[cfg(windows)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.path)
    }
}
impl PartialEq<&str> for SearchPath {
    fn eq(&self, other: &&str) -> bool {
        self.path.as_str() == *other
    }
}

#[cfg(unix)]
fn get_search_path(entry: &str) -> Option<SearchPath> {
    let path = Path::new(entry);
    let meta = fs::metadata(path).ok()?;
    Some(SearchPath {
        path: entry.to_string(),
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(windows)]
fn get_search_path(entry: &str) -> Option<SearchPath> {
    // Also checks for existence, like the unix metadata query.
    let canonical = fs::canonicalize(entry).ok()?;
    Some(SearchPath {
        path: crate::pathutils::strip_verbatim(entry),
        key: crate::pathutils::strip_verbatim(&canonical.to_string_lossy()).to_lowercase(),
    })
}

// List of unique existent search path in the filesystem.
pub type SearchPathVec = Vec<SearchPath>;

pub trait SearchPathVecExt {
    fn add_path(&mut self, entry: &str) -> &Self;
}

impl SearchPathVecExt for SearchPathVec {
    fn add_path(&mut self, entry: &str) -> &Self {
        if let Some(searchpath) = get_search_path(entry) {
            if !self.contains(&searchpath) {
                self.push(searchpath)
            }
        }
        self
    }
}

// Not used by the Mach-O backend.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn from_string<S: AsRef<str>>(string: S, delim: &[char]) -> SearchPathVec {
    let mut r = SearchPathVec::new();
    for path in string.as_ref().split(delim) {
        r.add_path(path);
    }
    r
}

// There is no PE equivalent of LD_PRELOAD.
#[cfg(unix)]
pub fn from_preload<S: AsRef<str>>(string: S) -> SearchPathVec {
    let mut r = SearchPathVec::new();
    for path in string.as_ref().split(':') {
        let path = match Path::new(path).canonicalize() {
            Ok(path) => path,
            // Maybe print an error message.
            Err(_) => continue,
        };
        if let Some(path) = path.to_str() {
            r.add_path(path);
        }
    }
    r
}

// Format a search path list for diagnostics printing.  The PE backend prints
// each directory with its search order mode instead.
#[cfg_attr(windows, allow(dead_code))]
pub fn format_list(searchpaths: &SearchPathVec) -> String {
    if searchpaths.is_empty() {
        return "(none)".to_string();
    }
    searchpaths
        .iter()
        .map(|path| path.path.as_str())
        .collect::<Vec<&str>>()
        .join(&LIST_SEPARATOR.to_string())
}
