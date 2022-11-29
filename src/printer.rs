// Configurable printer module.

use std::io::Write;
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
    ldd: bool,
    one: bool,
}

impl Printer {
    pub fn new(pp: bool, ldd: bool, one: bool) -> Self {
        Self {
            pp: pp,
            ldd: ldd,
            one: one,
        }
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

    pub fn print_executable(&self, path: &Option<String>, name: &String) {
        let writer = BufferWriter::stdout(ColorChoice::Always);
        let mut buffer = writer.buffer();

        let mut color_path = termcolor::ColorSpec::new();
        let mut color_name = termcolor::ColorSpec::new();
        if self.ldd {
            if self.one {
                return;
            }
        } else {
            color_path.set_fg(Some(termcolor::Color::Cyan));
            color_name.set_fg(Some(termcolor::Color::Cyan));
        }

        if let Some(path) = path {
            let delim = std::path::MAIN_SEPARATOR.to_string();
            self.write_colorized(&mut buffer, &color_path, &format!("{}{}", path, delim));
        }

        if self.ldd {
            self.writeln_colorized(&mut buffer, &color_name, format!("{}:", name));
        } else {
            self.writeln_colorized(&mut buffer, &color_name, name);
        }

        ok!(writer.print(&buffer));
    }

    fn print_entry(&self, dtneeded: &String, path: &String, mode: &str, found: bool) {
        let writer = BufferWriter::stdout(ColorChoice::Always);
        let mut buffer = writer.buffer();

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

    fn print_ldd(&self, dtneeded: &String, path: &String) {
        let writer = BufferWriter::stdout(ColorChoice::Always);
        let mut buffer = writer.buffer();

        ok!(buffer.write_all(
            format!(
                "        {} => {}{}{}\n",
                dtneeded,
                path,
                std::path::MAIN_SEPARATOR,
                dtneeded
            )
            .as_bytes()
        ));

        ok!(writer.print(&buffer));
    }

    pub fn print_dependency(
        &self,
        dtneeded: &String,
        path: &String,
        mode: &str,
        deptrace: &Vec<bool>,
    ) {
        if self.ldd {
            self.print_ldd(dtneeded, path);
            return;
        }
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

pub fn create(pp: bool, ldd: bool, one: bool) -> Printer {
    Printer::new(pp, ldd, one)
}
