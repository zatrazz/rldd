// Run-time link-editor configuration file parsing function.  The root files follow a simple
// format:
//
// - Each line issues a directive to a path (absolute or relative) or a include comment to include
//   another configuration file.
// - Each entry can have any leading or trailing whitespace.
// - Comments are started with '#' (as shell scritps).
// - Empty lines are ignored.
// - The 'include' command can reference a glob entry, which can include multiple file after
//   expansion.
// - Relative path are expanded based on the root of its parent.

use glob::glob;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use crate::search_path::*;

fn merge_searchpaths(v: &mut SearchPathVec, n: &mut SearchPathVec) {
    n.retain(|i| !v.contains(i));
    v.append(n)
}

// Returns a vector of all available paths (it must exist on the filesystem)
// parsed form the filename.
pub fn parse_ld_so_conf<P: AsRef<Path>>(filename: &P) -> Result<SearchPathVec, &'static str> {
    let mut lines = match read_lines(filename) {
        Ok(lines) => lines,
        Err(_e) => return Err("Could not open the filename"),
    };

    let mut r = SearchPathVec::new();

    while let Some(Ok(line)) = lines.next() {
        let line = match parse_line(&line) {
            Some(line) => line,
            None => continue,
        };

        if line.starts_with("include") {
            let mut fields = line.split_whitespace();
            match fields.nth(1) {
                Some(e) => match parse_ld_so_conf_glob(&filename.as_ref().parent(), e) {
                    Ok(mut v) => merge_searchpaths(&mut r, &mut v),
                    Err(e) => return Err(e),
                },
                None => return Err("Invalid ld.so.conf"),
            };
        // hwcap directives is ignored.
        } else if !line.starts_with("hwcap") {
            r.add_path(&line);
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

fn parse_line(line: &String) -> Option<String> {
    // Remove leading whitespace.
    let line = line.trim_start();
    // Remove trailing comments.
    let comment = match line.find('#') {
        Some(comment) => comment,
        None => line.len(),
    };
    let line = &line[0..comment];
    // Remove trailing whitespaces.
    let line = line.trim_end();
    // Skip empty lines.
    if line.is_empty() {
        return None;
    }
    Some(line.to_string())
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
                match parse_ld_so_conf(&path) {
                    Ok(mut v) => merge_searchpaths(&mut r, &mut v),
                    Err(_e) => return Err("Invalid path in ld.so.conf include file"),
                };
            }
            Err(_e) => return Err("Invalid glob pattern"),
        }
    }

    Ok(r)
}

// Returns a vector of libraries read from file FILENAME.  The file contains names of
// libraries to be loaded, separated by white spaces or `:'.
pub fn parse_ld_so_preload<P: AsRef<Path>>(filename: &P) -> SearchPathVec {
    let mut r = SearchPathVec::new();

    let mut lines = match read_lines(filename) {
        Ok(lines) => lines,
        // Ignore errors if file can not be read.
        Err(_) => return r,
    };

    while let Some(Ok(line)) = lines.next() {
        let line = match parse_line(&line) {
            Some(line) => line,
            None => continue,
        };

        for entry in line.split(&[':', ' ', '\t'][..]) {
            r.add_path(&entry);
        }
    }

    r
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

    #[test]
    fn parse_ld_conf_empty() -> Result<(), std::io::Error> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        File::create(&filepath)?;

        handle_err(parse_ld_so_conf(&filepath))
    }

    #[test]
    fn parse_ld_conf_single() -> Result<(), std::io::Error> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;
        let libdir2 = tmpdir.path().join("lib2");
        fs::create_dir(&libdir2)?;

        write!(file, "{}\n", libdir1.display())?;
        write!(file, "{}\n", libdir2.display())?;

        match parse_ld_so_conf(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0], libdir1.to_str().unwrap());
                assert_eq!(entries[1], libdir2.to_str().unwrap());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_invalid_include() -> Result<(), std::io::Error> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;

        write!(file, "include invalid\n")?;
        write!(file, "hwcap ignored\n")?;

        // Invalid paths are ignored.
        match parse_ld_so_conf(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 0);
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_include() -> Result<(), std::io::Error> {
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

        match parse_ld_so_conf(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 4);
                assert_eq!(entries[0], libdir3.to_str().unwrap());
                assert_eq!(entries[1], libdir4.to_str().unwrap());
                assert_eq!(entries[2], libdir1.to_str().unwrap());
                assert_eq!(entries[3], libdir2.to_str().unwrap());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_include_relative() -> Result<(), std::io::Error> {
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

        match parse_ld_so_conf(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0], libdir2.to_str().unwrap());
                assert_eq!(entries[1], libdir1.to_str().unwrap());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_include_duplicated() -> Result<(), std::io::Error> {
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

        match parse_ld_so_conf(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], libdir1.to_str().unwrap());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_comments() -> Result<(), std::io::Error> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;

        let subdir = tmpdir.path().join("subdir");
        fs::create_dir(&subdir)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;

        write!(file, "# comment number 1\n")?;
        write!(file, "   # comment number 2\n")?;
        write!(file, "include subdir/*  # comment number 3\n")?;
        write!(file, "{}  # comment number 4\n", libdir1.display())?;

        match parse_ld_so_conf(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], libdir1.to_str().unwrap());
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_so_preload_single() -> Result<(), std::io::Error> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.preload");
        let mut file = File::create(&filepath)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;
        let libdir2 = tmpdir.path().join("lib2");
        fs::create_dir(&libdir2)?;
        let libdir3 = tmpdir.path().join("lib3");
        fs::create_dir(&libdir3)?;
        let libdir4 = tmpdir.path().join("lib4");
        fs::create_dir(&libdir4)?;

        write!(file, "   # comment number 1\n")?;
        write!(
            file,
            " {}:{} # comment number 4\n",
            libdir1.display(),
            libdir2.display()
        )?;
        write!(
            file,
            " {} {} # comment number 4\n",
            libdir3.display(),
            libdir4.display()
        )?;

        let entries = parse_ld_so_preload(&filepath);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0], libdir1.to_str().unwrap());
        assert_eq!(entries[1], libdir2.to_str().unwrap());
        assert_eq!(entries[2], libdir3.to_str().unwrap());
        assert_eq!(entries[3], libdir4.to_str().unwrap());
        Ok(())
    }
}
