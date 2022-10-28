// Configurable printer module.

use std::io::Write;
use std::path::Path;
use termcolor::{BufferWriter, ColorChoice, WriteColor};

// Ignore output error for now.
macro_rules! ok {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(_) => {}
        }
    };
}

pub struct Printer {
    pp: bool,
}

impl Printer {
    pub fn new(pp: bool) -> Self {
        Self { pp: pp }
    }

    fn write_colorized<S: Into<String>>(
        &self,
        buffer: &mut termcolor::Buffer,
        color: &termcolor::ColorSpec,
        content: S,
    ) {
        ok!(buffer.set_color(color));
        ok!(buffer.write_all(content.into().as_bytes()));
        ok!(buffer.reset());
    }

    fn writeln_colorized<S: Into<String>>(
        &self,
        buffer: &mut termcolor::Buffer,
        color: &termcolor::ColorSpec,
        content: S,
    ) {
        self.write_colorized(buffer, color, format!("{}\n", content.into()));
    }

    pub fn print_executable(&self, path: &Path) {
        let writer = BufferWriter::stdout(ColorChoice::Always);
        let mut buffer = writer.buffer();

        if let Some(parent) = path.parent() {
            let parent = parent.to_string_lossy();
            let delim = std::path::MAIN_SEPARATOR.to_string();
            self.write_colorized(
                &mut buffer,
                termcolor::ColorSpec::new().set_fg(Some(termcolor::Color::Cyan)),
                &format!("{}{}", parent, delim),
            );
        }

        match path.file_name() {
            Some(filename) => {
                let filename = filename.to_string_lossy();
                self.writeln_colorized(
                    &mut buffer,
                    termcolor::ColorSpec::new()
                        .set_fg(Some(termcolor::Color::Cyan))
                        .set_intense(true),
                    filename.as_ref(),
                );
            }
            None => {
                self.writeln_colorized(
                    &mut buffer,
                    termcolor::ColorSpec::new().set_fg(Some(termcolor::Color::Red)),
                    "error invalid filename",
                );
            }
        }
        ok!(writer.print(&buffer));
    }

    fn print_entry(&self, dtneeded: &String, path: &String, mode: &str, found: bool) {
        let writer = BufferWriter::stdout(ColorChoice::Always);
        let mut buffer = writer.buffer();

        //write!(buffer, "{:>width$}", "", width = depth * 4).unwrap();

        let mut color = termcolor::ColorSpec::new();
        if !found {
            color.set_fg(Some(termcolor::Color::Cyan));
        } else {
            color.set_fg(Some(termcolor::Color::Magenta));
        }

        if self.pp {
            let delim = std::path::MAIN_SEPARATOR.to_string();
            self.write_colorized(&mut buffer, &color, format!("{}{}", path, delim));
        }

        if !found {
            color.set_bold(true);
        }
        self.write_colorized(&mut buffer, &color, dtneeded);

        color.set_bold(false);
        if !found {
            color.set_fg(Some(termcolor::Color::Yellow));
        }
        self.writeln_colorized(&mut buffer, &color, format!(" {}", mode));

        ok!(writer.print(&buffer));
    }

    fn print_preamble(&self, deptrace: &Vec<bool>) {
        for v in &deptrace[0..deptrace.len() - 1] {
            print!("{}", if *v { "|  " } else { "   " });
        }
        print!("\\_ ");
    }

    pub fn print_dependency(
        &self,
        dtneeded: &String,
        path: &String,
        mode: &str,
        deptrace: &Vec<bool>,
    ) {
        self.print_preamble(deptrace);
        self.print_entry(dtneeded, path, mode, false)
    }

    pub fn print_already_found(
        &self,
        dtneeded: &String,
        path: &String,
        mode: &str,
        deptrace: &Vec<bool>,
    ) {
        self.print_preamble(deptrace);
        self.print_entry(dtneeded, path, mode, true)
    }

    pub fn print_not_found(&self, dtneeded: &String, deptrace: &Vec<bool>) {
        self.print_preamble(deptrace);
        let writer = BufferWriter::stdout(ColorChoice::Always);
        let mut buffer = writer.buffer();
        self.writeln_colorized(
            &mut buffer,
            termcolor::ColorSpec::new()
                .set_fg(Some(termcolor::Color::Red))
                .set_bold(true),
            format!("{} not found", dtneeded),
        );
        ok!(writer.print(&buffer));
    }
}

pub fn create(pp: bool) -> Printer {
    Printer::new(pp)
}
