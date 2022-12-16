// Glibc ld.so.preload parsing function.  Each line issues a directive to an absolute path.

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use crate::search_path::*;

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
