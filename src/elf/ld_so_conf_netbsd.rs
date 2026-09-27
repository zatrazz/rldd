// The NetBSD ld.so.conf format is quite simple:
// - Lines beginning with `#' are treated as comments and ignored.
// - Non-blank lines beginning with '/' is treated as directories to be scanned.
// - Lines that ddo not begin with a `/' are parsed as hardware dependent per library
//   directives (not supported).

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

fn parse_line(line: &str) -> Option<String> {
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

    #[test]
    fn missing_file() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        assert!(parse_ld_so_conf(&tmpdir.path().join("ld.so.conf")).is_err());
        Ok(())
    }
}
