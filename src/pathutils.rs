use std::path::Path;

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

// Strip the verbatim prefix added by fs::canonicalize (for instance,
// \\?\C:\Windows\System32 -> C:\Windows\System32).
#[cfg(windows)]
pub fn strip_verbatim(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
}
