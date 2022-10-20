use std::io::Write;
use std::path::{Path, PathBuf};

use colored::*;

pub struct Printer<'a> {
    w: &'a mut dyn Write,
    e: &'a mut dyn Write,
}

impl<'a> Printer<'a> {
    pub fn new(w: &'a mut dyn Write, e: &'a mut dyn Write) -> Self {
        Self { w, e }
    }

    pub fn print_executable(&mut self, path: &Path) {
        if let Some(parent) = path.parent() {
            let parent = parent.to_string_lossy().cyan();
            let delim = std::path::MAIN_SEPARATOR.to_string().cyan();
            write!(self.w, "{}{}", parent, delim).unwrap();
        }

        match path.file_name() {
            Some(filename) => {
                let filename = filename.to_string_lossy().bright_cyan();
                writeln!(self.w, "{}", filename).unwrap();
            }
            None => writeln!(self.e, "{}: invalid filename", "error".red()).unwrap(),
        }
    }

    pub fn print_dependency(
        &mut self,
        dtneeded: &String,
        _path: Option<PathBuf>,
        mode: &str,
        depth: usize,
    ) {
        let mode = format!("[{}]", mode).yellow();
        writeln!(
            self.w,
            "{:>width$}{} {}",
            "",
            dtneeded.bright_cyan(),
            mode,
            width = depth * 4
        )
        .unwrap();
    }

    pub fn print_not_found(&mut self, dtneeded: &String, depth: usize) {
        writeln!(
            self.w,
            "{:>width$}{}",
            "",
            format!("{} not found", dtneeded).red(),
            width = depth * 4
        )
        .unwrap();
    }
}

pub fn create<'a>(w: &'a mut dyn Write, e: &'a mut dyn Write) -> Printer<'a> {
    Printer::new(w, e)
}
