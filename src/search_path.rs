use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::{fmt, fs};

use object::elf::*;

/* Not all machines are supported by object crate.  */
const EM_ARCV2: u16 = 195;

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

pub fn from_string(string: &str) -> SearchPathVec {
    let mut r = SearchPathVec::new();
    for path in string.split(":") {
        r.add_path(path);
    }
    r
}

pub fn get_slibdir(e_machine: u16, ei_class: u8) -> Option<&'static str> {
    match e_machine {
        EM_AARCH64 | EM_ALPHA | EM_PPC64 | EM_LOONGARCH => Some("/lib64"),
        EM_ARCV2 | EM_ARM | EM_CSKY | EM_PARISC | EM_386 | EM_68K | EM_MICROBLAZE
        | EM_ALTERA_NIOS2 | EM_OPENRISC | EM_PPC | EM_SH => Some("/lib"),
        EM_S390 | EM_SPARC | EM_MIPS | EM_MIPS_RS3_LE => match ei_class {
            ELFCLASS32 => Some("/lib"),
            ELFCLASS64 => Some("/lib64"),
            _ => return None,
        },
        EM_RISCV => match ei_class {
            ELFCLASS32 => Some("/lib32/ilp32d"),
            ELFCLASS64 => Some("/lib64/lp64d"),
            _ => return None,
        },
        EM_X86_64 => match ei_class {
            ELFCLASS32 => Some("/libx32"),
            ELFCLASS64 => Some("/lib64"),
            _ => return None,
        },
        _ => return None,
    }
}

pub fn get_system_dirs(e_machine: u16, ei_class: u8) -> Option<SearchPathVec> {
    let mut r = SearchPathVec::new();

    let path = get_slibdir(e_machine, ei_class)?;
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
        ino: 0,
    });

    Some(r)
}
