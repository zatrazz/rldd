use std::fmt;

// The resolution mode for a dependency, used mostly for printing.
#[derive(PartialEq, Clone, Copy, Debug)]
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
            DepMode::SystemDirs => write!(f, "[system default paths]"),
            DepMode::Executable => write!(f, ""),
            DepMode::NotFound => write!(f, "[not found]"),
        }
    }
}
