use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::{fmt, fs};

#[derive(Debug, PartialEq)]
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

pub fn add_searchpath<P: AsMut<SearchPathVec>>(v: &mut P, entry: &str) {
    match get_search_path(entry) {
        Some(searchpath) => {
            if !v.as_mut().contains(&searchpath) {
                v.as_mut().push(searchpath);
            }
        }
        None => {}
    }
}
