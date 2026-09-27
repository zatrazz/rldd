use std::fs;
use std::io::{Error, ErrorKind, Result};
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

// The NAME entry of the DIR directory, joined with the platform separator
// the way the loaders report it (unlike Path::join, NAME is appended as is).
// A DIR that already ends with a separator, such as a root directory, is not
// given a second one.
pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with(std::path::is_separator) {
        format!("{dir}{name}")
    } else {
        format!("{dir}{}{name}", std::path::MAIN_SEPARATOR)
    }
}

// Map the whole FILE in memory for reading.  A directory, which unix opens
// but does not map (the error would be ENODEV on Linux), is reported as
// such.
pub fn map(file: &fs::File) -> Result<Mmap> {
    if file.metadata()?.is_dir() {
        return Err(Error::from(ErrorKind::IsADirectory));
    }
    // SAFETY: the mapping is only read.  Another process modifying the file
    // while it is mapped changes the data underneath (and truncating it may
    // fault), which is accepted for a diagnostic tool.
    unsafe { Mmap::map(file) }
}

// Open and map FILENAME, returning the open error as is, except for a
// directory, which Windows does not open (access denied).
pub fn map_file<P: AsRef<Path>>(filename: &P) -> Result<Mmap> {
    let file = fs::File::open(filename).map_err(|err| match fs::metadata(filename) {
        Ok(metadata) if metadata.is_dir() => Error::from(ErrorKind::IsADirectory),
        _ => err,
    })?;
    map(&file)
}

// Whether PATH starts with any of PREFIXES (the --ignore-prefix option).  The
// Windows paths are compared without regard to ASCII case, the way the
// filesystem does, and take either separator, while the unix ones are
// compared exactly.
#[cfg(any(target_os = "macos", windows))]
pub fn has_prefix(path: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| {
        path.len() >= prefix.len()
            && path
                .bytes()
                .zip(prefix.bytes())
                .all(|(a, b)| same_path_byte(a, b))
    })
}

#[cfg(any(target_os = "macos", windows))]
fn same_path_byte(a: u8, b: u8) -> bool {
    if cfg!(windows) {
        let is_separator = |c: u8| std::path::is_separator(char::from(c));
        a.eq_ignore_ascii_case(&b) || (is_separator(a) && is_separator(b))
    } else {
        a == b
    }
}

// The lines of FILENAME, for the loader configuration files.
#[cfg(any(target_os = "linux", target_os = "netbsd"))]
pub fn read_lines<P: AsRef<Path>>(
    filename: P,
) -> Result<std::io::Lines<std::io::BufReader<fs::File>>> {
    use std::io::BufRead;
    Ok(std::io::BufReader::new(fs::File::open(filename)?).lines())
}

// Read a T in native layout from READER, for the loader binary cache and
// hints files.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub fn read_struct<T: object::Pod + Default, R: std::io::Read + ?Sized>(
    reader: &mut R,
) -> Result<T> {
    let mut value = T::default();
    reader.read_exact(object::pod::bytes_of_mut(&mut value))?;
    Ok(value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn join_separator() {
        assert_eq!(join("/usr/lib", "libc.so"), "/usr/lib/libc.so");
        assert_eq!(join("/usr/lib/", "libc.so"), "/usr/lib/libc.so");
        assert_eq!(join("/", "libc.so"), "/libc.so");
        assert_eq!(join("/usr/lib", ""), "/usr/lib/");
    }

    #[cfg(windows)]
    #[test]
    fn join_separator() {
        assert_eq!(join(r"C:\Windows", "x.dll"), r"C:\Windows\x.dll");
        assert_eq!(join(r"C:\", "x.dll"), r"C:\x.dll");
        assert_eq!(join("C:/", "x.dll"), "C:/x.dll");
        assert_eq!(join(r"\\host\share\", "x.dll"), r"\\host\share\x.dll");
        assert_eq!(join(r"C:\Windows", ""), r"C:\Windows\");
    }

    #[test]
    fn map_errors() {
        let dir = std::env::temp_dir();
        assert_eq!(map_file(&dir).unwrap_err().kind(), ErrorKind::IsADirectory);
        // Unlike Windows, unix opens a directory.
        #[cfg(unix)]
        assert_eq!(
            map(&fs::File::open(&dir).unwrap()).unwrap_err().kind(),
            ErrorKind::IsADirectory
        );
        let missing = dir.join("rldd-missing-file");
        assert_eq!(map_file(&missing).unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ignore_prefix() {
        let prefixes = ["/usr/lib".to_string(), "/System".to_string()];
        assert!(has_prefix("/usr/lib/libSystem.B.dylib", &prefixes));
        assert!(has_prefix("/System/Library", &prefixes));
        assert!(!has_prefix("/USR/lib/libz.dylib", &prefixes));
        assert!(!has_prefix("/usr/li", &prefixes));
    }

    #[cfg(windows)]
    #[test]
    fn ignore_prefix() {
        let prefixes = [r"C:\Windows".to_string()];
        assert!(has_prefix(r"C:\Windows\System32", &prefixes));
        assert!(has_prefix(r"c:\windows\system32", &prefixes));
        assert!(!has_prefix(r"C:\Win", &prefixes));
        assert!(!has_prefix(r"D:\Windows", &prefixes));
        // The prefix length falls inside the two byte 'é' of the path.
        assert!(!has_prefix("C:\\é", &[r"C:\x".to_string()]));
        // Either separator matches the other.
        assert!(has_prefix(
            r"C:\Windows\System32",
            &["C:/Windows".to_string()]
        ));
        assert!(has_prefix(
            "C:/Windows/System32",
            &[r"c:\windows\".to_string()]
        ));
        assert!(!has_prefix(r"C:\Windows", &["C:/Windows/".to_string()]));
        assert!(!has_prefix(r"C:\Windows", &[]));
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_prefix() {
        assert_eq!(strip_verbatim(r"\\?\C:\Windows"), r"C:\Windows");
        assert_eq!(strip_verbatim(r"\\?\UNC\host\share"), r"\\host\share");
        assert_eq!(strip_verbatim(r"C:\Windows"), r"C:\Windows");
    }
}
