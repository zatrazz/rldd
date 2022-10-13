use object::Architecture;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::{fmt, fs, env};

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

pub fn get_system_dirs(arch: object::Architecture) -> Option<SearchPathVec> {
    let mut r = SearchPathVec::new();

    let path = match arch {
        Architecture::X86_64
        | Architecture::Aarch64
        | Architecture::LoongArch64
        | Architecture::Mips64
        | Architecture::PowerPc64
        | Architecture::S390x
        | Architecture::Sparc64 => "/lib64",
        Architecture::Arm
        | Architecture::I386
        | Architecture::Mips
        | Architecture::PowerPc => "/lib",
        Architecture::Riscv64 => "/lib64/lp64d",
        Architecture::Riscv32 => "/lib32/ilp32d",
        Architecture::X86_64_X32 => "/libx32",
        _ => return None,
    };

    r.push(SearchPath {
        path: path.to_string(),
        dev: 0,
        ino: 0,
    });
    // The '/usr' part is configurable on glibc configure, however there is no
    // direct way to obtain it on runtime.
    // TODO: Add an option to override it.
    r.push(SearchPath {
        path: format!("/usr/{}", path.to_string()),
        dev: 0,
        ino: 0
    });

    Some(r)
}

pub fn get_ld_library_path() -> SearchPathVec {
    let mut r = SearchPathVec::new();

    let ld_library_path = match env::var("LD_LIBRARY_PATH") {
        Ok(path) => path,
        Err(_) => "".to_string(),
    };

    for path in ld_library_path.split(":") {
        add_searchpath(&mut r, path);
    }

    r
}
