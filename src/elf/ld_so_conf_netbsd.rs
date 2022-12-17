// The NetBSD ld.so.conf format is quite simple:
// - Lines beginning with `#' are treated as comments and ignored.
// - Non-blank lines beginning with '/' is treated as directories to be scanned.
// - Lines that ddo not begin with a `/' are parsed as hardware dependent per library
//   directives (not supported).

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use crate::search_path::*;

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

        // NetBSD loader does string expansion for $ORIGIN, $OSNAME, $OSREL, and
        // $PLATFORM.  For now add these as TODOs.
        r.add_path(&line);
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
