// Configurable printer module.

use std::io::{IsTerminal, Write};

// The SGR sequences for the normal (not intense) foreground colors, matching
// what a terminal renders for the 30-37 range.
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

#[derive(Clone, Copy)]
enum Color {
    Cyan,
    Magenta,
    Yellow,
    Red,
}

impl Color {
    fn sgr(self) -> &'static str {
        match self {
            Color::Cyan => "\x1b[36m",
            Color::Magenta => "\x1b[35m",
            Color::Yellow => "\x1b[33m",
            Color::Red => "\x1b[31m",
        }
    }
}

// A foreground color along with the bold attribute, the only styling used.
#[derive(Clone, Copy, Default)]
struct Style {
    color: Option<Color>,
    bold: bool,
}

impl Style {
    fn new() -> Self {
        Self::default()
    }

    fn fg(mut self, color: Color) -> Self {
        self.color = Some(color);
        self
    }

    fn bold(mut self, bold: bool) -> Self {
        self.bold = bold;
        self
    }
}

// Whether the terminal on stdout renders the SGR sequences.  On Windows this
// also switches the console to the virtual terminal mode, which is not the
// default for a console attached process.
fn color_supported() -> bool {
    if !std::io::stdout().is_terminal() {
        return false;
    }
    match std::env::var_os("TERM") {
        Some(term) if term == "dumb" => return false,
        // Unlike on Windows, an unset TERM on unix means a terminal that most
        // likely does not handle the escape sequences.
        None if !cfg!(windows) => return false,
        _ => {}
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    enable_virtual_terminal()
}

#[cfg(windows)]
fn enable_virtual_terminal() -> bool {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        STD_OUTPUT_HANDLE,
    };

    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() {
            return false;
        }
        let mut mode = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true;
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_virtual_terminal() -> bool {
    true
}

pub struct Printer {
    pp: bool,
    ldd: bool,
    one: bool,
    verbose: bool,
    color: bool,
}

impl Printer {
    pub fn new(pp: bool, ldd: bool, one: bool, verbose: bool) -> Self {
        let color = !ldd && color_supported();
        Self {
            pp,
            ldd,
            one,
            verbose,
            color,
        }
    }

    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    // Write the assembled line out, ignoring the output error the way the
    // tree listing has no way to report it.
    fn flush(&self, out: &str) {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(out.as_bytes());
    }

    fn write_colorized(&self, out: &mut String, style: &Style, content: &str) {
        if self.color {
            out.push_str(RESET);
            if style.bold {
                out.push_str(BOLD);
            }
            if let Some(color) = style.color {
                out.push_str(color.sgr());
            }
        }
        out.push_str(content);
        if self.color {
            out.push_str(RESET);
        }
    }

    fn writeln_colorized(&self, out: &mut String, style: &Style, content: &str) {
        self.write_colorized(out, style, content);
        out.push('\n');
    }

    pub fn print_executable(&self, path: &Option<String>, name: &String) {
        let mut out = String::new();

        let mut style_path = Style::new();
        let mut style_name = Style::new();
        if self.ldd {
            if self.one {
                return;
            }
        } else {
            style_path = style_path.fg(Color::Cyan);
            style_name = style_name.fg(Color::Cyan).bold(true);
        }

        if self.pp {
            if let Some(path) = path {
                let delim = std::path::MAIN_SEPARATOR;
                self.write_colorized(&mut out, &style_path, &format!("{path}{delim}"));
            }
        }

        if self.ldd {
            self.writeln_colorized(&mut out, &style_name, &format!("{name}:"));
        } else {
            self.writeln_colorized(&mut out, &style_name, name);
        }

        self.flush(&out);
    }

    fn print_entry(
        &self,
        dtneeded: &String,
        alias: Option<&str>,
        path: &String,
        mode: &str,
        found: bool,
    ) {
        let mut out = String::new();

        let style = if !found {
            Style::new().fg(Color::Cyan)
        } else {
            Style::new().fg(Color::Magenta)
        };

        // The recorded name, when the resolved file differs from it.
        if let Some(alias) = alias.filter(|alias| *alias != dtneeded) {
            self.write_colorized(&mut out, &style, &format!("{alias} -> "));
        }

        if self.pp {
            let delim = std::path::MAIN_SEPARATOR;
            self.write_colorized(&mut out, &style, &format!("{path}{delim}"));
        }

        self.write_colorized(&mut out, &style.bold(!found), dtneeded);

        let style = if !found {
            style.fg(Color::Yellow)
        } else {
            style
        };
        self.writeln_colorized(&mut out, &style, &format!(" {mode}"));

        self.flush(&out);
    }

    fn print_preamble(&self, deptrace: &[bool]) {
        for v in &deptrace[0..deptrace.len() - 1] {
            print!("{}", if *v { "|  " } else { "   " });
        }
        print!("\\_ ");
    }

    fn print_ldd(&self, dtneeded: &String, alias: Option<&str>, path: &String) {
        self.flush(&format!(
            "        {} => {}{}{}\n",
            alias.unwrap_or(dtneeded),
            path,
            std::path::MAIN_SEPARATOR,
            dtneeded
        ));
    }

    pub fn print_dependency(
        &self,
        dtneeded: &String,
        alias: Option<&str>,
        path: &String,
        mode: &str,
        deptrace: &[bool],
    ) {
        if self.ldd {
            self.print_ldd(dtneeded, alias, path);
            return;
        }
        self.print_preamble(deptrace);
        self.print_entry(dtneeded, alias, path, mode, false)
    }

    pub fn print_already_found(
        &self,
        dtneeded: &String,
        alias: Option<&str>,
        path: &String,
        mode: &str,
        deptrace: &[bool],
    ) {
        // The ldd mode only prints unique dependencies.
        if self.ldd {
            return;
        }
        self.print_preamble(deptrace);
        self.print_entry(dtneeded, alias, path, mode, true)
    }

    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    pub fn print_statically_linked(&self) {
        if self.ldd {
            println!("        statically linked");
        }
    }

    pub fn print_not_found(
        &self,
        dtneeded: &String,
        alias: Option<&str>,
        attrs: &[&'static str],
        searched: &[String],
        deptrace: &[bool],
    ) {
        let attrs = if attrs.is_empty() {
            String::new()
        } else {
            format!(" [{}]", attrs.join(" "))
        };
        if self.ldd {
            println!("        {} => not found{attrs}", alias.unwrap_or(dtneeded));
            return;
        }
        // The recorded name, when the resolved module differs from it.
        let dtneeded = match alias {
            Some(alias) if alias != dtneeded => format!("{alias} -> {dtneeded}"),
            _ => dtneeded.clone(),
        };
        self.print_preamble(deptrace);
        let mut out = String::new();
        self.writeln_colorized(
            &mut out,
            &Style::new().fg(Color::Red).bold(true),
            &format!("{dtneeded} not found{attrs}"),
        );
        self.flush(&out);

        if self.verbose {
            for location in searched {
                for v in deptrace {
                    print!("{}", if *v { "|  " } else { "   " });
                }
                println!("   searched {location}");
            }
        }
    }
}

pub fn create(pp: bool, ldd: bool, one: bool, verbose: bool) -> Printer {
    Printer::new(pp, ldd, one, verbose)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn printer(color: bool) -> Printer {
        Printer {
            pp: false,
            ldd: false,
            one: false,
            verbose: false,
            color,
        }
    }

    fn styled(style: &Style, content: &str) -> String {
        let mut out = String::new();
        printer(true).write_colorized(&mut out, style, content);
        out
    }

    // The sequences a terminal expects, which are the ones the previous
    // termcolor based printer emitted: a reset, then the attributes, then the
    // content, then a final reset.
    #[test]
    fn escape_sequences() {
        assert_eq!(styled(&Style::new(), "x"), "\x1b[0mx\x1b[0m");
        assert_eq!(
            styled(&Style::new().fg(Color::Cyan), "x"),
            "\x1b[0m\x1b[36mx\x1b[0m"
        );
        assert_eq!(
            styled(&Style::new().fg(Color::Cyan).bold(true), "x"),
            "\x1b[0m\x1b[1m\x1b[36mx\x1b[0m"
        );
        assert_eq!(
            styled(&Style::new().fg(Color::Magenta), "x"),
            "\x1b[0m\x1b[35mx\x1b[0m"
        );
        assert_eq!(
            styled(&Style::new().fg(Color::Yellow), "x"),
            "\x1b[0m\x1b[33mx\x1b[0m"
        );
        assert_eq!(
            styled(&Style::new().fg(Color::Red).bold(true), "x"),
            "\x1b[0m\x1b[1m\x1b[31mx\x1b[0m"
        );
        // Clearing the attribute drops it again.
        assert_eq!(
            styled(&Style::new().fg(Color::Magenta).bold(true).bold(false), "x"),
            "\x1b[0m\x1b[35mx\x1b[0m"
        );
    }

    // Nothing is emitted when the output is not a terminal, which is what the
    // ldd mode and a redirected stdout rely on.
    #[test]
    fn plain_output_has_no_escapes() {
        let mut out = String::new();
        printer(false).write_colorized(&mut out, &Style::new().fg(Color::Red).bold(true), "x");
        assert_eq!(out, "x");
    }

    #[test]
    fn writeln_appends_the_newline_after_the_reset() {
        let mut out = String::new();
        printer(true).writeln_colorized(&mut out, &Style::new().fg(Color::Cyan), "x");
        assert_eq!(out, "\x1b[0m\x1b[36mx\x1b[0m\n");
    }
}
