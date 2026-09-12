use std::fs;
use std::io::{Error, Result};
use std::path::Path;

use memmap2::Mmap;

pub fn get_path<P: AsRef<Path>>(path: &P) -> Option<String> {
    path.as_ref()
        .parent()
        .and_then(|s| s.to_str().map(|s| s.to_string()))
}

pub fn get_name<P: AsRef<Path>>(path: &P) -> String {
    path.as_ref()
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string()
}

// Map the whole FILE in memory for reading.
pub fn map(file: &fs::File) -> Result<Mmap> {
    // SAFETY: the mapping is only read.  Another process modifying the file
    // while it is mapped changes the data underneath (and truncating it may
    // fault), which is accepted for a diagnostic tool.
    unsafe { Mmap::map(file) }.map_err(|_| Error::other("Failed to map file"))
}

// Open and map FILENAME, returning the open error as is.
// Unused by the Android and BSD backends.
#[cfg_attr(
    all(unix, not(any(target_os = "linux", target_os = "macos"))),
    allow(dead_code)
)]
pub fn map_file<P: AsRef<Path>>(filename: &P) -> Result<Mmap> {
    map(&fs::File::open(filename)?)
}

// Strip the verbatim prefix added by fs::canonicalize (for instance,
// \\?\C:\Windows\System32 -> C:\Windows\System32).
#[cfg(windows)]
pub fn strip_verbatim(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn verbatim_prefix() {
        assert_eq!(strip_verbatim(r"\\?\C:\Windows"), r"C:\Windows");
        assert_eq!(strip_verbatim(r"\\?\UNC\host\share"), r"\\host\share");
        assert_eq!(strip_verbatim(r"C:\Windows"), r"C:\Windows");
    }
}
