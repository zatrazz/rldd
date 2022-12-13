use std::fmt;
use std::path::Path;

mod arenatree;

// A resolved dependency
#[derive(PartialEq, Clone, Debug)]
pub struct DepNode {
    pub path: Option<String>,
    pub name: String,
    pub mode: DepMode,
    pub found: bool,
}

impl arenatree::EqualString for DepNode {
    fn eqstr(&self, other: &String) -> bool {
        if self.path.is_none() || !Path::new(other).is_absolute() {
            *other == self.name
        } else {
            *other
                == format!(
                    "{}{}{}",
                    &self.path.as_ref().unwrap(),
                    std::path::MAIN_SEPARATOR,
                    self.name
                )
        }
    }
}

// The resolved binary dependency tree.
pub type DepTree = arenatree::ArenaTree<DepNode>;

// The resolution mode for a dependency, used mostly for printing.
#[derive(PartialEq, Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum DepMode {
    Preload,       // Preload library.
    Direct,        // DT_SONAME refers to an aboslute path.
    DtRpath,       // DT_RPATH.
    LdLibraryPath, // LD_LIBRARY_PATH.
    DtRunpath,     // DT_RUNPATH.
    LdSoConf,      // ld.so.conf.
    SystemDirs,    // Default system directory (i.e '/lib64').
    Executable,    // The root executable/library.
    NotFound,
}

impl fmt::Display for DepMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DepMode::Preload => write!(f, "[preload]"),
            DepMode::Direct => write!(f, "[direct]"),
            DepMode::DtRpath => write!(f, "[rpath]"),
            DepMode::LdLibraryPath => write!(f, "[LD_LIBRARY_PATH]"),
            DepMode::DtRunpath => write!(f, "[runpath]"),
            #[cfg(target_os = "linux")]
            DepMode::LdSoConf => write!(f, "[ld.so.conf]"),
            #[cfg(target_os = "freebsd")]
            DepMode::LdSoConf => write!(f, "[ld-elf.so.hints]"),
            #[cfg(target_os = "openbsd")]
            DepMode::LdSoConf => write!(f, "[ld-so.hints]"),
            #[cfg(target_os = "macos")]
            DepMode::LdSoConf => write!(f, "[dyld cache]"),
            DepMode::SystemDirs => write!(f, "[system default paths]"),
            DepMode::Executable => write!(f, ""),
            DepMode::NotFound => write!(f, "[not found]"),
        }
    }
}
