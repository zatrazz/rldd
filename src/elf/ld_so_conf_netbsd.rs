// The NetBSD ld.so.conf format is quite simple:
// - Lines beginning with `#' are treated as comments and ignored.
// - Non-blank lines beginning with '/' is treated as directories to be scanned.
// - Lines that do not begin with a `/' are parsed as hardware dependent per library
//   directives (not supported, so they are skipped).

use std::path::Path;

use crate::search_path::*;

// Returns a vector of all available paths (it must exist on the filesystem)
// parsed form the filename.
pub fn parse_ld_so_conf<P: AsRef<Path>>(filename: &P) -> Result<SearchPathVec, &'static str> {
    let mut lines = match crate::pathutils::read_lines(filename) {
        Ok(lines) => lines,
        Err(_e) => return Err("Could not open the filename"),
    };

    let mut r = SearchPathVec::new();

    while let Some(Ok(line)) = lines.next() {
        let line = match parse_line(&line) {
            Some(line) => line,
            None => continue,
        };

        // NetBSD loader does string expansion for $ORIGIN, $OSNAME, $OSREL, and
        // $PLATFORM.  For now add these as TODOs.
        r.add_path(&line);
    }

    Ok(r)
}

// The directory of LINE, following _rtld_process_hints: only the spaces and
// tabs are blanks, and a line not starting with '/' is a directive and not a
// directory.
fn parse_line(line: &str) -> Option<String> {
    // Remove leading blanks.
    let line = line.trim_start_matches([' ', '\t']);
    // Remove trailing comments.
    let comment = match line.find('#') {
        Some(comment) => comment,
        None => line.len(),
    };
    let line = &line[0..comment];
    // Skip empty lines and the directives.
    if !line.starts_with('/') {
        return None;
    }
    // Remove trailing blanks.
    Some(line.trim_end_matches([' ', '\t']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;
    use std::fs;

    #[test]
    fn parse_directories() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let lib1 = tmpdir.path().join("lib1");
        fs::create_dir(&lib1)?;
        let lib2 = tmpdir.path().join("lib2");
        fs::create_dir(&lib2)?;
        let (lib1, lib2) = (lib1.to_str().unwrap(), lib2.to_str().unwrap());
        let missing = tmpdir.path().join("missing");

        // The missing directory and the repeated one are not added.
        let conf = tmpdir.path().join("ld.so.conf");
        fs::write(
            &conf,
            format!(
                "# comment\n\
                 \n\
                 \t {lib1}  # trailing comment\n\
                 {}\n\
                 {lib2}\n\
                 {lib1}\n",
                missing.display()
            ),
        )?;
        let dirs = parse_ld_so_conf(&conf).unwrap();
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0], lib1);
        assert_eq!(dirs[1], lib2);
        Ok(())
    }

    // A line not starting with '/' is a hardware dependent directive, which is
    // not a directory even when it names one relative to the current one
    // (cargo runs the tests from the package directory).
    #[test]
    fn skip_directives() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let lib1 = tmpdir.path().join("lib1");
        fs::create_dir(&lib1)?;
        let lib1 = lib1.to_str().unwrap();
        assert!(Path::new("src").is_dir());

        let conf = tmpdir.path().join("ld.so.conf");
        fs::write(
            &conf,
            format!(
                "libc.so machdep.cpu_brand Intel:{lib1}\n\
                 src\n\
                 ./src\n\
                 \r{lib1}\n"
            ),
        )?;
        assert!(parse_ld_so_conf(&conf).unwrap().is_empty());
        Ok(())
    }

    #[test]
    fn missing_file() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        assert!(parse_ld_so_conf(&tmpdir.path().join("ld.so.conf")).is_err());
        Ok(())
    }
}
