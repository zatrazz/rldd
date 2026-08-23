use std::fmt;
use std::path::Path;

mod arenatree;
use crate::pathutils;

// A resolved dependency
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct DepNode {
    pub path: Option<String>,
    pub name: String,
    pub mode: DepMode,
    pub found: bool,
    // The recorded dependency name, when it differs from the resolved file
    // name (an API set on Windows).
    pub alias: Option<String>,
    // The dependency attributes from the load command (Mach-O only), such as
    // weak, re-export, upward, or delay-init.
    pub attrs: Vec<&'static str>,
    // The compatibility and current versions from the load command (Mach-O
    // only), printed in verbose mode.
    pub version: Option<String>,
    // The locations searched when the dependency is not found, printed in
    // verbose mode.
    pub searched: Vec<String>,
}

impl arenatree::EqualString for DepNode {
    #[cfg(unix)]
    fn eqstr(&self, other: &str) -> bool {
        // Dependencies resolved through a search path list are recorded with
        // the location they were found at, so they are matched by the leaf
        // name (the same leaf always resolves to the same object).
        if matches!(
            self.mode,
            DepMode::Preload
                | DepMode::LdLibraryPath
                | DepMode::LdFrameworkPath
                | DepMode::LdFallbackLibraryPath
                | DepMode::LdFallbackFrameworkPath
        ) {
            pathutils::get_name(&Path::new(other)) == self.name
        } else if self.path.is_none() || !Path::new(other).is_absolute() {
            *other == self.name
        } else {
            *other
                == format!(
                    "{}{}{}",
                    self.path.as_ref().unwrap(),
                    std::path::MAIN_SEPARATOR,
                    self.name
                )
        }
    }

    // A side-by-side module is matched by its full path, since the same name
    // may be loaded from more than one assembly.
    #[cfg(windows)]
    fn eqstr(&self, other: &str) -> bool {
        if other.contains(std::path::MAIN_SEPARATOR) || other.contains('/') {
            let Some(path) = &self.path else {
                return false;
            };
            let resolved = format!("{}{}{}", path, std::path::MAIN_SEPARATOR, self.name);
            return other.eq_ignore_ascii_case(&resolved);
        }
        pathutils::get_name(&Path::new(other)).eq_ignore_ascii_case(&self.name)
    }
}

// The resolved binary dependency tree.
pub type DepTree = arenatree::ArenaTree<DepNode>;

// The resolution mode for a dependency, used mostly for printing.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub enum DepMode {
    Preload,                 // Preload library.
    Direct,                  // DT_SONAME refers to an aboslute path.
    DtRpath,                 // DT_RPATH.
    LdLibraryPath,           // LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, or SetDllDirectory.
    LdFrameworkPath,         // DYLD_FRAMEWORK_PATH (Mach-O only).
    LdFallbackLibraryPath,   // DYLD_FALLBACK_LIBRARY_PATH (Mach-O only).
    LdFallbackFrameworkPath, // DYLD_FALLBACK_FRAMEWORK_PATH (Mach-O only).
    DtRunpath,               // DT_RUNPATH.
    LdCache,                 // Loader cache (ld.so.cache, KnownDLLs, etc.).
    SystemDirs,              // Default system directory (i.e '/lib64').
    #[cfg(windows)]
    ApiSet, // API set schema redirectio.
    #[cfg(windows)]
    SideBySide, // Side-by-side assembly.
    #[cfg(windows)]
    Application, // The application directory.
    #[cfg(windows)]
    WindowsDir, // The Windows directory.
    #[cfg(windows)]
    CurrentDir, // The current directory.
    #[cfg(windows)]
    EnvPath, // The PATH environment variable.
    Executable,              // The root executable/library.
    #[default]
    NotFound,
}

impl fmt::Display for DepMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DepMode::Preload => write!(f, "[preload]"),
            DepMode::Direct => write!(f, "[direct]"),
            DepMode::DtRpath => write!(f, "[rpath]"),
            #[cfg(target_os = "macos")]
            DepMode::LdLibraryPath => write!(f, "[DYLD_LIBRARY_PATH]"),
            #[cfg(windows)]
            DepMode::LdLibraryPath => write!(f, "[SetDllDirectory]"),
            #[cfg(all(unix, not(target_os = "macos")))]
            DepMode::LdLibraryPath => write!(f, "[LD_LIBRARY_PATH]"),
            DepMode::LdFrameworkPath => write!(f, "[DYLD_FRAMEWORK_PATH]"),
            DepMode::LdFallbackLibraryPath => write!(f, "[DYLD_FALLBACK_LIBRARY_PATH]"),
            DepMode::LdFallbackFrameworkPath => write!(f, "[DYLD_FALLBACK_FRAMEWORK_PATH]"),
            DepMode::DtRunpath => write!(f, "[runpath]"),
            #[cfg(target_os = "linux")]
            DepMode::LdCache => write!(f, "[ld.so.cache]"),
            #[cfg(target_os = "android")]
            DepMode::LdCache => write!(f, "[ld.config.txt]"),
            #[cfg(target_os = "freebsd")]
            DepMode::LdCache => write!(f, "[ld-elf.so.hints]"),
            #[cfg(target_os = "openbsd")]
            DepMode::LdCache => write!(f, "[ld-so.hints]"),
            #[cfg(target_os = "netbsd")]
            DepMode::LdCache => write!(f, "[ld.so.conf]"),
            #[cfg(any(target_os = "illumos", target_os = "solaris"))]
            DepMode::LdCache => write!(f, "[unknown]"),
            #[cfg(target_os = "macos")]
            DepMode::LdCache => write!(f, "[dyld cache]"),
            #[cfg(windows)]
            DepMode::LdCache => write!(f, "[KnownDLLs]"),
            #[cfg(windows)]
            DepMode::ApiSet => write!(f, "[api set]"),
            #[cfg(windows)]
            DepMode::SideBySide => write!(f, "[side-by-side]"),
            #[cfg(windows)]
            DepMode::Application => write!(f, "[application directory]"),
            #[cfg(windows)]
            DepMode::WindowsDir => write!(f, "[windows directory]"),
            #[cfg(windows)]
            DepMode::CurrentDir => write!(f, "[current directory]"),
            #[cfg(windows)]
            DepMode::EnvPath => write!(f, "[PATH]"),
            #[cfg(windows)]
            DepMode::SystemDirs => write!(f, "[system directory]"),
            #[cfg(not(windows))]
            DepMode::SystemDirs => write!(f, "[system default paths]"),
            DepMode::Executable => write!(f, ""),
            DepMode::NotFound => write!(f, "[not found]"),
        }
    }
}
