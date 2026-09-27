// Glibc ld.so.preload parsing function.

use std::path::Path;

// The names of the libraries in CONTENTS, the ld.so.preload file.  The loader
// replaces each comment (from a '#' up to the end of the line) with spaces,
// and splits the rest on colons, spaces, tabs and newlines (dl_main), so any
// other character (a carriage return included) is part of a name.
fn parse_contents(contents: &str) -> Vec<String> {
    let mut r: Vec<String> = Vec::new();
    for line in contents.split('\n') {
        let line = match line.find('#') {
            Some(comment) => &line[..comment],
            None => line,
        };
        for entry in line.split([':', ' ', '\t']) {
            if !entry.is_empty() && !r.iter().any(|e| e == entry) {
                r.push(entry.to_string());
            }
        }
    }
    r
}

// Returns a vector of libraries read from file FILENAME.  The file contains names of
// libraries to be loaded, separated by white spaces or `:'.
pub fn parse_ld_so_preload<P: AsRef<Path>>(filename: &P) -> Vec<String> {
    match std::fs::read(filename) {
        Ok(contents) => parse_contents(&String::from_utf8_lossy(&contents)),
        // Ignore errors if file can not be read.
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preload_file() {
        assert_eq!(parse_contents(""), Vec::<String>::new());
        assert_eq!(
            parse_contents("/lib/liba.so libb.so:libc.so\n\t# comment libd.so\nlibe.so#x\n"),
            vec!["/lib/liba.so", "libb.so", "libc.so", "libe.so"]
        );
        // Duplicated entries are loaded once.
        assert_eq!(
            parse_contents("liba.so\nliba.so:libb.so"),
            vec!["liba.so", "libb.so"]
        );
        // The carriage return is not a separator.
        assert_eq!(parse_contents("liba.so\r\n"), vec!["liba.so\r"]);
    }
}
