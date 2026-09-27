#[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
use std::collections::HashMap;
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

impl DepNode {
    // An object located at the PATH directory with the NAME file name.
    pub fn new(path: Option<String>, name: String, mode: DepMode) -> Self {
        Self {
            path,
            name,
            mode,
            ..Default::default()
        }
    }

    // An object from its full path.  Only the ELF backend records the
    // dependencies from the path they were opened with.
    #[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
    pub fn from_path<P: AsRef<Path>>(path: &P, mode: DepMode) -> Self {
        Self::new(pathutils::get_path(path), pathutils::get_name(path), mode)
    }

    // A dependency that could not be resolved, along with the locations
    // searched for it.
    pub fn not_found(name: String, searched: Vec<String>) -> Self {
        Self {
            name,
            mode: DepMode::NotFound,
            searched,
            ..Default::default()
        }
    }

    // Mark a dependency already resolved elsewhere on the tree.
    pub fn already_found(mut self) -> Self {
        self.found = true;
        self
    }

    // A dependency that resolves to ENTRY, an object already on the tree,
    // recorded under the NAME it was requested with.
    pub fn repeat_of(entry: &DepNode, name: String) -> Self {
        Self::new(entry.path.clone(), name, entry.mode).already_found()
    }

    #[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
    pub fn with_alias(mut self, alias: Option<String>) -> Self {
        self.alias = alias;
        self
    }

    #[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
    pub fn with_attrs(mut self, attrs: Vec<&'static str>) -> Self {
        self.attrs = attrs;
        self
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn with_version(mut self, version: Option<String>) -> Self {
        self.version = version;
        self
    }
}

impl DepMode {
    // Dependencies resolved through a search path list are recorded with
    // the location they were found at, so they are matched by the leaf
    // name (the same leaf always resolves to the same object).  The Mach-O
    // backend matches the loaded images itself (by path, install name, and
    // file), so only the ELF modes are listed.
    #[cfg(unix)]
    fn matched_by_leaf(self) -> bool {
        matches!(self, DepMode::Preload | DepMode::LdLibraryPath)
    }
}

impl arenatree::EqualString for DepNode {
    #[cfg(unix)]
    fn eqstr(&self, other: &str) -> bool {
        if self.mode.matched_by_leaf() {
            pathutils::get_name(&Path::new(other)) == self.name
        } else if self.path.is_none() || !Path::new(other).is_absolute() {
            *other == self.name
        } else {
            *other == pathutils::join(self.path.as_ref().unwrap(), &self.name)
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
            return other.eq_ignore_ascii_case(&pathutils::join(path, &self.name));
        }
        pathutils::get_name(&Path::new(other)).eq_ignore_ascii_case(&self.name)
    }
}

// The resolved binary dependency tree.
pub type DepTree = arenatree::ArenaTree<DepNode>;

impl DepTree {
    // Add a dependency already resolved elsewhere on the tree, which is only
    // listed when ALL (the -a option) is set.
    pub fn add_repeated(&mut self, all: bool, node: DepNode, parent: usize) {
        if all {
            self.addnode(node, parent);
        }
    }
}

// An index of the tree nodes of the objects found (neither the not found
// entries nor the root), by the names DepNode::eqstr matches them with, so
// looking up a name does not scan the whole tree: the ones resolved through a
// search path list by their leaf name, and any other one by its name, or by
// its full path for an absolute name.  It is updated with the nodes added
// since the previous lookup, in tree order, so the first node matching a name
// is the one found.  The Android linker only looks up the objects of the
// namespaces instead.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
#[derive(Default)]
pub struct FoundIndex {
    // The number of tree nodes already indexed.
    indexed: usize,
    names: HashMap<String, usize>,
    // The names of the nodes without a path, also matched by an absolute
    // name.
    pathless: HashMap<String, usize>,
    paths: HashMap<String, usize>,
    leaves: HashMap<String, usize>,
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
impl FoundIndex {
    fn update(&mut self, deptree: &DepTree) {
        for (idx, node) in deptree.arena.iter().enumerate().skip(self.indexed) {
            let val = &node.val;
            if matches!(val.mode, DepMode::NotFound | DepMode::Executable) {
                continue;
            }
            if val.mode.matched_by_leaf() {
                self.leaves.entry(val.name.clone()).or_insert(idx);
                continue;
            }
            self.names.entry(val.name.clone()).or_insert(idx);
            match &val.path {
                Some(path) => {
                    self.paths
                        .entry(pathutils::join(path, &val.name))
                        .or_insert(idx);
                }
                None => {
                    self.pathless.entry(val.name.clone()).or_insert(idx);
                }
            }
        }
        self.indexed = deptree.arena.len();
    }

    // The first node of DEPTREE for an object found that matches NAME.
    pub fn find(&mut self, deptree: &DepTree, name: &str) -> Option<usize> {
        self.update(deptree);
        let direct = if Path::new(name).is_absolute() {
            [self.paths.get(name), self.pathless.get(name)]
        } else {
            [self.names.get(name), None]
        };
        let leaf = self.leaves.get(&pathutils::get_name(&Path::new(name)));
        direct.into_iter().chain([leaf]).flatten().min().copied()
    }
}

// The resolution mode for a dependency, used mostly for printing.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub enum DepMode {
    Preload,                 // Preload library.
    Direct,                  // DT_NEEDED refers to an absolute path.
    DtRpath,                 // DT_RPATH.
    LdLibraryPath,           // LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, or SetDllDirectory.
    LdFrameworkPath,         // DYLD_FRAMEWORK_PATH (Mach-O only).
    LdFallbackLibraryPath,   // DYLD_FALLBACK_LIBRARY_PATH (Mach-O only).
    LdFallbackFrameworkPath, // DYLD_FALLBACK_FRAMEWORK_PATH (Mach-O only).
    DtRunpath,               // DT_RUNPATH.
    LdCache,                 // Loader cache (ld.so.cache, KnownDLLs, etc.).
    SystemDirs,              // Default system directory (i.e '/lib64').
    #[cfg(windows)]
    ApiSet, // API set schema redirection.
    #[cfg(windows)]
    SideBySide, // Side-by-side assembly.
    #[cfg(windows)]
    DllRedirection, // '.local' DLL redirection.
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
            DepMode::DllRedirection => write!(f, "[.local]"),
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

// A symbol reference that no loaded object provides, reported by the
// relocation (ELF) or the import (PE) checks.
#[cfg(any(target_os = "linux", windows))]
pub struct UndefinedSymbol {
    pub name: String,
    // The object holding the reference: its full path on ELF, and the module
    // name on PE.
    pub object: String,
    // The required symbol version (ELF only).
    pub version: Option<String>,
    // The module the symbol is imported from (PE only).
    pub from: Option<String>,
}

#[cfg(any(target_os = "linux", windows))]
impl fmt::Display for UndefinedSymbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(version) = &self.version {
            write!(f, ", version {version}")?;
        }
        if let Some(from) = &self.from {
            write!(f, ", from {from}")?;
        }
        Ok(())
    }
}

#[cfg(all(test, any(target_os = "linux", windows)))]
mod tests {
    use super::*;

    fn undefined(version: Option<&str>, from: Option<&str>) -> String {
        UndefinedSymbol {
            name: "sym".to_string(),
            object: "obj".to_string(),
            version: version.map(str::to_string),
            from: from.map(str::to_string),
        }
        .to_string()
    }

    #[test]
    fn undefined_symbol_display() {
        assert_eq!(undefined(None, None), "sym");
        assert_eq!(
            undefined(Some("GLIBC_2.34"), None),
            "sym, version GLIBC_2.34"
        );
        assert_eq!(
            undefined(None, Some("kernel32.dll")),
            "sym, from kernel32.dll"
        );
    }
}

#[cfg(all(test, unix, not(any(target_os = "macos", target_os = "android"))))]
mod found_index_tests {
    use super::arenatree::EqualString;
    use super::*;

    // The index finds the same node as the first found one eqstr matches.
    #[test]
    fn found_index_matches_eqstr() {
        let mut deptree = DepTree::new();
        let root = deptree.addroot(DepNode::new(
            Some("/bin".to_string()),
            "main".to_string(),
            DepMode::Executable,
        ));
        let node = |path: &str, name: &str, mode| {
            DepNode::new(Some(path.to_string()), name.to_string(), mode)
        };
        let mut index = FoundIndex::default();
        deptree.addnode(DepNode::not_found("libx.so".to_string(), Vec::new()), root);
        assert_eq!(index.find(&deptree, "libx.so"), None);
        let x = deptree.addnode(node("/a", "libx.so", DepMode::DtRunpath), root);
        let p = deptree.addnode(node("/p", "libp.so", DepMode::Preload), root);
        let d = deptree.addnode(node("/d", "libd.so", DepMode::Direct), root);
        // The not found entry does not hide the one found later.
        assert_eq!(index.find(&deptree, "libx.so"), Some(x));
        assert_eq!(index.find(&deptree, "/a/libx.so"), Some(x));
        assert_eq!(index.find(&deptree, "/b/libx.so"), None);
        // A preload entry matches any path with its leaf name.
        assert_eq!(index.find(&deptree, "/q/libp.so"), Some(p));
        assert_eq!(index.find(&deptree, "libd.so"), Some(d));
        assert_eq!(index.find(&deptree, "main"), None);
        for name in [
            "libx.so",
            "/a/libx.so",
            "/b/libx.so",
            "/q/libp.so",
            "libd.so",
            "main",
        ] {
            let first = deptree.arena.iter().position(|n| {
                n.val.eqstr(name) && !matches!(n.val.mode, DepMode::NotFound | DepMode::Executable)
            });
            assert_eq!(index.find(&deptree, name), first, "{name}");
        }
    }
}
