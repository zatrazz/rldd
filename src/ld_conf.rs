use glob::glob;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn parse_ld_so_conf(filename: &Path) -> Result<Vec<String>, &'static str> {
    let mut lines = match read_lines(filename) {
        Ok(lines) => lines,
        Err(_e) => return Err("Could not open the filename"),
    };

    let mut r = <Vec<String>>::new();

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
                Some(e) => match parse_ld_so_conf_glob(e) {
                    Ok(mut v) => r.append(&mut v),
                    Err(e) => return Err(e),
                },
                None => return Err("Invalid ld.so.conf"),
            };
        } else {
            r.push(entry.to_string());
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

fn parse_ld_so_conf_glob(filename: &str) -> Result<Vec<String>, &'static str> {
    let mut r = <Vec<String>>::new();

    for entry in glob(filename).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                match parse_ld_so_conf(&path) {
                    Ok(mut v) => r.append(&mut v),
                    Err(_e) => return Err("Invalid path in ld.so.conf include file"),
                };
            }
            Err(_e) => return Err("Invalid glob pattern"),
        }
    }

    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::fs::File;
    use std::io::{Error, ErrorKind, Write};
    use tempfile::TempDir;

    fn handle_err(e: Result<Vec<String>, &'static str>) -> Result<(), std::io::Error> {
        match e {
            Ok(v) => Ok(()),
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_conf_empty() -> Result<(), std::io::Error> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;

        handle_err(parse_ld_so_conf(&filepath))
    }

    #[test]
    fn parse_ld_conf_single() -> Result<(), std::io::Error> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld.so.conf");
        let mut file = File::create(&filepath)?;
        write!(file, "/usr/lib\n")?;
        write!(file, "/usr/lib64\n")?;

        match parse_ld_so_conf(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0], "/usr/lib");
                assert_eq!(entries[1], "/usr/lib64");
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

        write!(file, "include {}/subdir*/*\n", tmpdir.path().display())?;
        write!(file, "/usr/lib\n")?;
        write!(file, "/usr/lib64\n")?;
        write!(file1, "/usr/local/lib\n")?;
        write!(file2, "/usr/local/lib64\n")?;

        match parse_ld_so_conf(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 4);
                assert_eq!(entries[0], "/usr/local/lib");
                assert_eq!(entries[1], "/usr/local/lib64");
                assert_eq!(entries[2], "/usr/lib");
                assert_eq!(entries[3], "/usr/lib64");
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }
}
