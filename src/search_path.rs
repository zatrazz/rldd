// Provides helper function to handle search path for library resolution, for either DT_RPATH,
// DT_RUNPATH, ld.so.conf, or system directories.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::{fmt, fs};

#[derive(Debug, PartialEq, Clone)]
pub struct SearchPath {
    pub path: String,
    pub dev: u64,
    pub ino: u64,
}
impl fmt::Display for SearchPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({},{})", self.path, self.dev, self.ino)
    }
}
impl PartialEq<&str> for SearchPath {
    fn eq(&self, other: &&str) -> bool {
        self.path.as_str() == *other
    }
}

fn get_search_path(entry: &str) -> Option<SearchPath> {
    let path = Path::new(entry);
    let meta = fs::metadata(path).ok()?;
    Some(SearchPath {
        path: entry.to_string(),
        dev: meta.dev(),
        ino: meta.ino(),
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

pub fn from_string<S: AsRef<str>>(string: S, delim: &[char]) -> SearchPathVec {
    let mut r = SearchPathVec::new();
    for path in string.as_ref().split(delim) {
        r.add_path(path);
    }
    r
}

pub fn from_preload<S: AsRef<str>>(string: S) -> SearchPathVec {
    let mut r = SearchPathVec::new();
    for path in string.as_ref().split(":") {
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
