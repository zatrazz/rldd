use std::io::Write;
use std::path::Path;

use colored::*;

pub struct Printer<'a> {
    w: &'a mut dyn Write,
    e: &'a mut dyn Write,
    pp: bool,
}

impl<'a> Printer<'a> {
    pub fn new(w: &'a mut dyn Write, e: &'a mut dyn Write, pp: bool) -> Self {
        Self { w, e, pp }
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

    fn print_entry(
        &mut self,
        dtneeded: &String,
        path: &String,
        mode: &str,
        depth: usize,
        found: bool,
    ) {
        write!(self.w, "{:>width$}", "", width = depth * 4).unwrap();

        let delim = std::path::MAIN_SEPARATOR.to_string();
        if self.pp {
            write!(
                self.w,
                "{}{}",
                if !found { path.cyan() } else { path.magenta() },
                if !found {
                    delim.cyan()
                } else {
                    delim.magenta()
                }
            )
            .unwrap();
        };

        writeln!(
            self.w,
            "{} {}",
            if !found {
                dtneeded.bright_cyan().bold()
            } else {
                dtneeded.magenta()
            },
            if !found {
                mode.yellow()
            } else {
                mode.magenta()
            }
        )
        .unwrap()
    }

    pub fn print_dependency(&mut self, dtneeded: &String, path: &String, mode: &str, depth: usize) {
        self.print_entry(dtneeded, path, mode, depth, false)
    }

    pub fn print_already_found(
        &mut self,
        dtneeded: &String,
        path: &String,
        mode: &str,
        depth: usize,
    ) {
        self.print_entry(dtneeded, path, mode, depth, true)
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

pub fn create<'a>(w: &'a mut dyn Write, e: &'a mut dyn Write, pp: bool) -> Printer<'a> {
    Printer::new(w, e, pp)
}
