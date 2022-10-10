use glob::glob;
use object::Architecture;
use std::fs::File;
use std::io::{self, BufRead};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::{fmt, fs};

#[derive(Debug, PartialEq)]
pub struct SearchPath {
    path: String,
    dev: u64,
    ino: u64,
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

// List of unique existent search path in the filesystem.
type SearchPathVec = Vec<SearchPath>;

fn add_searchpath(v: &mut SearchPathVec, entry: &str) {
    match get_search_path(entry) {
        Some(searchpath) => {
            if !v.contains(&searchpath) {
                v.push(searchpath);
            }
        }
        None => {}
    }
}

fn merge_searchpaths(v: &mut SearchPathVec, n: &mut SearchPathVec) {
    n.retain(|i| !v.contains(i));
    v.append(n)
}

pub fn parse_ld_so_conf<P: AsRef<Path>>(
    arch: object::Architecture,
    filename: &P,
) -> Result<SearchPathVec, &'static str> {
    let r = parse_ld_so_conf_file(filename);
    match r {
        Ok(mut r) => {
            match get_slibdir(arch) {
                Some(p) => r.push(p),
                _ => {}
            }
            Ok(r)
        }
        Err(e) => return Err(e),
    }
}

fn parse_ld_so_conf_file<P: AsRef<Path>>(filename: &P) -> Result<SearchPathVec, &'static str> {
    let mut lines = match read_lines(filename) {
        Ok(lines) => lines,
        Err(_e) => return Err("Could not open the filename"),
    };

    let mut r = SearchPathVec::new();

    while let Some(Ok(entry)) = lines.next() {
        // Remove leading whitespace.
        let entry = entry.trim_start();
        // Remove trailing comments.
        let comment = match entry.find('#') {
            Some(comment) => comment,
            None => entry.len(),
        };
        let entry = &entry[0..comment];
        // Skip empty lines.
        if entry.is_empty() {
            continue;
        }

        if entry.starts_with("include") {
            let mut fields = entry.split_whitespace();
            match fields.nth(1) {
                Some(e) => match parse_ld_so_conf_glob(&filename.as_ref().parent(), e) {
                    Ok(mut v) => merge_searchpaths(&mut r, &mut v),
                    Err(e) => return Err(e),
                },
                None => return Err("Invalid ld.so.conf"),
            };
        // hwcap directives is ignored.
        } else if !entry.starts_with("hwcap") {
            add_searchpath(&mut r, entry);
        }
    }

    Ok(r)
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
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

fn parse_ld_so_conf_glob(
    root: &Option<&Path>,
    pattern: &str,
) -> Result<SearchPathVec, &'static str> {
    let mut r = SearchPathVec::new();

    let filename = if !Path::new(pattern).is_absolute() && root.is_some() {
        match Path::new(root.unwrap()).join(pattern).to_str() {
            Some(filename) => filename.to_string(),
            None => return Err("Invalid include entry"),
        }
    } else {
        pattern.to_string()
    };

    for entry in glob(filename.as_str()).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                match parse_ld_so_conf_file(&path) {
                    Ok(mut v) => merge_searchpaths(&mut r, &mut v),
                    Err(_e) => return Err("Invalid path in ld.so.conf include file"),
                };
            }
            Err(_e) => return Err("Invalid glob pattern"),
        }
    }

    Ok(r)
}

fn get_slibdir(arch: object::Architecture) -> Option<SearchPath> {
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
    Some(SearchPath {
        path: path.to_string(),
        dev: 0,
        ino: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::fs::File;
    use std::io::{Error, ErrorKind, Write};
    use tempfile::TempDir;

    fn handle_err(e: Result<SearchPathVec, &'static str>) -> Result<(), std::io::Error> {
        match e {
            Ok(_v) => Ok(()),
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    fn slibdir(arch: object::Architecture) -> Result<String, std::io::Error> {
        let v = match get_slibdir(arch) {
            Some(v) => v,
            None => return Err(Error::new(ErrorKind::Other, "")),
        };
        Ok(v.path)
    }

    #[test]
    fn parse_ld_conf_empty() -> Result<(), std::io::Error> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        File::create(&filepath)?;

        handle_err(parse_ld_so_conf(Architecture::X86_64, &filepath))
    }

    #[test]
    fn parse_ld_conf_single() -> Result<(), std::io::Error> {
        let arch = Architecture::X86_64;

        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;
        let libdir2 = tmpdir.path().join("lib2");
        fs::create_dir(&libdir2)?;

        write!(file, "{}\n", libdir1.display())?;
        write!(file, "{}\n", libdir2.display())?;

        match parse_ld_so_conf(Architecture::X86_64, &filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 3);
                assert_eq!(entries[0], libdir1.to_str().unwrap());
                assert_eq!(entries[1], libdir2.to_str().unwrap());
                assert_eq!(entries[2], slibdir(arch)?.as_str());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_invalid_include() -> Result<(), std::io::Error> {
        let arch = Architecture::X86_64;

        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;

        write!(file, "include invalid\n")?;
        write!(file, "hwcap ignored\n")?;

        // Invalid paths are ignored.
        match parse_ld_so_conf(arch, &filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], slibdir(arch)?.as_str());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_include() -> Result<(), std::io::Error> {
        let arch = Architecture::X86_64;

        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;

        let subdir1 = tmpdir.path().join("subdir1");
        fs::create_dir(&subdir1)?;
        let subfile1 = subdir1.join("include1");
        let mut file1 = File::create(&subfile1)?;

        let subdir2 = tmpdir.path().join("subdir2");
        fs::create_dir(&subdir2)?;
        let subfile2 = subdir2.join("include2");
        let mut file2 = File::create(&subfile2)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;
        let libdir2 = tmpdir.path().join("lib2");
        fs::create_dir(&libdir2)?;

        let libdir3 = tmpdir.path().join("lib3");
        fs::create_dir(&libdir3)?;
        let libdir4 = tmpdir.path().join("lib4");
        fs::create_dir(&libdir4)?;

        write!(file, "include {}/subdir*/*\n", tmpdir.path().display())?;
        write!(file, "{}\n", libdir1.display())?;
        write!(file, "{}\n", libdir2.display())?;
        write!(file1, "{}\n", libdir3.display())?;
        write!(file2, "{}\n", libdir4.display())?;

        match parse_ld_so_conf(Architecture::X86_64, &filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 5);
                assert_eq!(entries[0], libdir3.to_str().unwrap());
                assert_eq!(entries[1], libdir4.to_str().unwrap());
                assert_eq!(entries[2], libdir1.to_str().unwrap());
                assert_eq!(entries[3], libdir2.to_str().unwrap());
                assert_eq!(entries[4], slibdir(arch)?.as_str());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_include_relative() -> Result<(), std::io::Error> {
        let arch = Architecture::X86_64;

        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;

        let subdir = tmpdir.path().join("subdir");
        fs::create_dir(&subdir)?;
        let subfilepath = subdir.join("include");
        let mut subfile = File::create(&subfilepath)?;

        let subsubdir = tmpdir.path().join("subdir").join("subsubdir");
        fs::create_dir(&subsubdir)?;
        let subsubfilepath = subsubdir.join("include");
        let mut subsubfile = File::create(&subsubfilepath)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;
        let libdir2 = tmpdir.path().join("lib2");
        fs::create_dir(&libdir2)?;

        write!(file, "include subdir/*\n")?;
        write!(subfile, "include subsubdir/*\n")?;
        write!(subfile, "{}", libdir1.display())?;
        write!(subsubfile, "{}", libdir2.display())?;

        match parse_ld_so_conf(Architecture::X86_64, &filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 3);
                assert_eq!(entries[0], libdir2.to_str().unwrap());
                assert_eq!(entries[1], libdir1.to_str().unwrap());
                assert_eq!(entries[2], slibdir(arch)?.as_str());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_include_duplicated() -> Result<(), std::io::Error> {
        let arch = Architecture::X86_64;

        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;

        let subdir = tmpdir.path().join("subdir");
        fs::create_dir(&subdir)?;
        let subfilepath = subdir.join("include");
        let mut subfile = File::create(&subfilepath)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;

        write!(file, "include subdir/*\n")?;
        write!(file, "{}\n", libdir1.display())?;
        write!(file, "{}\n", libdir1.display())?;
        write!(subfile, "{}\n", libdir1.display())?;

        match parse_ld_so_conf(Architecture::X86_64, &filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0], libdir1.to_str().unwrap());
                assert_eq!(entries[1], slibdir(arch)?.as_str());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }
}
