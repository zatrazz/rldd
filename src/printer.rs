// Configurable printer module.

use std::io::IsTerminal;

use crate::deptree::{DepMode, DepTree};
use crate::pathutils;

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

// The DIR directory ending with a separator, for the file name printed after
// it.
fn dir_prefix(dir: &str) -> String {
    pathutils::join(dir, "")
}

// The tree guide columns, one for each DEPTRACE level, continued when the
// level has further siblings.
fn indent(deptrace: &[bool]) -> String {
    deptrace
        .iter()
        .map(|v| if *v { "|  " } else { "   " })
        .collect()
}

// The tree guide of an entry at the last DEPTRACE level.
fn preamble(deptrace: &[bool]) -> String {
    indent(&deptrace[0..deptrace.len() - 1]) + "\\_ "
}

pub struct Printer {
    pp: bool,
    ldd: bool,
    one: bool,
    verbose: bool,
    color: bool,
    // The output, kept instead of written when set (for the tests).
    #[cfg(test)]
    captured: Option<std::cell::RefCell<String>>,
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
            #[cfg(test)]
            captured: None,
        }
    }

    // Write the assembled line out.
    fn flush(&self, line: &str) {
        #[cfg(test)]
        if let Some(captured) = &self.captured {
            captured.borrow_mut().push_str(line);
            return;
        }
        out!("{line}");
    }

    // Print the DEPS dependency tree, starting with the root object.
    pub fn print_deps(&self, deps: &DepTree) {
        let bin = deps.arena.first().unwrap();
        self.print_executable(&bin.val.path, &bin.val.name);

        #[cfg(all(target_family = "unix", not(target_os = "macos")))]
        if bin.children.is_empty() {
            self.print_statically_linked();
            return;
        }

        let mut deptrace = Vec::<bool>::new();
        self.print_deps_children(deps, &bin.children, &mut deptrace);
    }

    fn print_deps_children(&self, deps: &DepTree, children: &[usize], deptrace: &mut Vec<bool>) {
        let mut iter = children.iter().peekable();
        while let Some(c) = iter.next() {
            let dep = &deps.arena[*c];
            deptrace.push(children.len() > 1);
            let mut mode = if dep.val.attrs.is_empty() {
                dep.val.mode.to_string()
            } else {
                format!("[{}] {}", dep.val.attrs.join(" "), dep.val.mode)
            };
            // The load command versions (Mach-O only), shown in verbose mode
            // the way otool -L reports them.
            if self.verbose {
                if let Some(version) = &dep.val.version {
                    mode = format!("{mode} ({version})");
                }
            }
            if dep.val.mode == DepMode::NotFound {
                self.print_not_found(
                    &dep.val.name,
                    dep.val.alias.as_deref(),
                    &dep.val.attrs,
                    &dep.val.searched,
                    deptrace,
                );
            } else if dep.val.found {
                self.print_already_found(
                    &dep.val.name,
                    dep.val.alias.as_deref(),
                    dep.val.path.as_ref().unwrap(),
                    &mode,
                    deptrace,
                );
            } else {
                self.print_dependency(
                    &dep.val.name,
                    dep.val.alias.as_deref(),
                    dep.val.path.as_ref().unwrap(),
                    &mode,
                    deptrace,
                );
            }
            deptrace.pop();

            deptrace.push(children.len() > 1 && iter.peek().is_some());
            self.print_deps_children(deps, &dep.children, deptrace);
            deptrace.pop();
        }
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

    fn print_executable(&self, path: &Option<String>, name: &str) {
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
                self.write_colorized(&mut out, &style_path, &dir_prefix(path));
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
        dtneeded: &str,
        alias: Option<&str>,
        path: &str,
        mode: &str,
        found: bool,
        deptrace: &[bool],
    ) {
        let mut out = preamble(deptrace);

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
            self.write_colorized(&mut out, &style, &dir_prefix(path));
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

    fn print_ldd(&self, dtneeded: &str, alias: Option<&str>, path: &str) {
        self.flush(&format!(
            "        {} => {}\n",
            alias.unwrap_or(dtneeded),
            pathutils::join(path, dtneeded)
        ));
    }

    fn print_dependency(
        &self,
        dtneeded: &str,
        alias: Option<&str>,
        path: &str,
        mode: &str,
        deptrace: &[bool],
    ) {
        if self.ldd {
            self.print_ldd(dtneeded, alias, path);
            return;
        }
        self.print_entry(dtneeded, alias, path, mode, false, deptrace)
    }

    fn print_already_found(
        &self,
        dtneeded: &str,
        alias: Option<&str>,
        path: &str,
        mode: &str,
        deptrace: &[bool],
    ) {
        // The ldd mode only prints unique dependencies.
        if self.ldd {
            return;
        }
        self.print_entry(dtneeded, alias, path, mode, true, deptrace)
    }

    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    fn print_statically_linked(&self) {
        if self.ldd {
            self.flush("        statically linked\n");
        }
    }

    fn print_not_found(
        &self,
        dtneeded: &str,
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
            self.flush(&format!(
                "        {} => not found{attrs}\n",
                alias.unwrap_or(dtneeded)
            ));
            return;
        }
        // The recorded name, when the resolved module differs from it.
        let dtneeded = match alias {
            Some(alias) if alias != dtneeded => format!("{alias} -> {dtneeded}"),
            _ => dtneeded.to_string(),
        };
        let mut out = preamble(deptrace);
        self.writeln_colorized(
            &mut out,
            &Style::new().fg(Color::Red).bold(true),
            &format!("{dtneeded} not found{attrs}"),
        );
        self.flush(&out);

        if self.verbose {
            for location in searched {
                self.flush(&format!("{}   searched {location}\n", indent(deptrace)));
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
    use crate::deptree::DepNode;

    fn printer(color: bool) -> Printer {
        Printer {
            pp: false,
            ldd: false,
            one: false,
            verbose: false,
            color,
            captured: Some(Default::default()),
        }
    }

    // A tree with nested, not found, already found, aliased, and attributed
    // dependencies:
    //
    //   /bin/prog
    //     liba.so (/lib)
    //       libc.so (/lib)
    //       libd.so (not found)
    //     libb.so (/usr/lib, the alias.so name, weak)
    //       liba.so (already found)
    fn tree() -> DepTree {
        let dir = |dir: &str| Some(dir.to_string());
        let mut deps = DepTree::new();
        let root = deps.addroot(DepNode::new(
            dir("/bin"),
            "prog".into(),
            DepMode::Executable,
        ));
        let a = deps.addnode(
            DepNode::new(dir("/lib"), "liba.so".into(), DepMode::DtRpath),
            root,
        );
        deps.addnode(
            DepNode::new(dir("/lib"), "libc.so".into(), DepMode::DtRunpath),
            a,
        );
        deps.addnode(
            DepNode::not_found("libd.so".into(), vec!["/lib/libd.so".into()]),
            a,
        );
        let mut b = DepNode::new(dir("/usr/lib"), "libb.so".into(), DepMode::Direct);
        b.alias = Some("alias.so".into());
        b.attrs = vec!["weak"];
        let b = deps.addnode(b, root);
        let a = DepNode::new(dir("/lib"), "liba.so".into(), DepMode::DtRpath);
        deps.addnode(a.already_found(), b);
        deps
    }

    // The tree printed with the PP, LDD, ONE, and VERBOSE settings.
    fn print(pp: bool, ldd: bool, one: bool, verbose: bool, deps: &DepTree) -> String {
        let printer = Printer {
            pp,
            ldd,
            one,
            verbose,
            ..printer(false)
        };
        printer.print_deps(deps);
        printer.captured.unwrap().take()
    }

    // The path of the NAME file at DIR, as the platform separates them.
    fn path(dir: &str, name: &str) -> String {
        pathutils::join(dir, name)
    }

    #[test]
    fn tree_layout() {
        assert_eq!(
            print(false, false, false, false, &tree()),
            "prog\n\
             \\_ liba.so [rpath]\n\
             |  \\_ libc.so [runpath]\n\
             |  \\_ libd.so not found\n\
             \\_ alias.so -> libb.so [weak] [direct]\n   \
                \\_ liba.so [rpath]\n"
        );
        // The verbose mode lists the locations searched.
        assert_eq!(
            print(false, false, false, true, &tree()),
            "prog\n\
             \\_ liba.so [rpath]\n\
             |  \\_ libc.so [runpath]\n\
             |  \\_ libd.so not found\n\
             |  |     searched /lib/libd.so\n\
             \\_ alias.so -> libb.so [weak] [direct]\n   \
                \\_ liba.so [rpath]\n"
        );
    }

    #[test]
    fn path_layout() {
        assert_eq!(
            print(true, false, false, false, &tree()),
            format!(
                "{}\n\\_ {} [rpath]\n|  \\_ {} [runpath]\n|  \\_ libd.so not found\n\
                 \\_ alias.so -> {} [weak] [direct]\n   \\_ {} [rpath]\n",
                path("/bin", "prog"),
                path("/lib", "liba.so"),
                path("/lib", "libc.so"),
                path("/usr/lib", "libb.so"),
                path("/lib", "liba.so"),
            )
        );
        // A file at a root directory has a single separator.
        let mut deps = DepTree::new();
        let root = deps.addroot(DepNode::new(
            Some("/".into()),
            "prog".into(),
            DepMode::Executable,
        ));
        deps.addnode(
            DepNode::new(Some("/".into()), "liba.so".into(), DepMode::Direct),
            root,
        );
        assert_eq!(
            print(true, false, false, false, &deps),
            "/prog\n\\_ /liba.so [direct]\n"
        );
    }

    #[test]
    fn ldd_layout() {
        // Each dependency once, with the name it was requested with.
        let deps = format!(
            "        liba.so => {}\n        libc.so => {}\n        libd.so => not found\n        alias.so => {}\n",
            path("/lib", "liba.so"),
            path("/lib", "libc.so"),
            path("/usr/lib", "libb.so"),
        );
        assert_eq!(
            print(false, true, false, false, &tree()),
            format!("prog:\n{deps}")
        );
        assert_eq!(
            print(true, true, false, false, &tree()),
            format!("{}:\n{deps}", path("/bin", "prog"))
        );
        // A single file is not named.
        assert_eq!(print(false, true, true, false, &tree()), deps);
    }

    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    #[test]
    fn statically_linked() {
        let mut deps = DepTree::new();
        deps.addroot(DepNode::new(
            Some("/bin".into()),
            "prog".into(),
            DepMode::Executable,
        ));
        assert_eq!(print(false, false, false, false, &deps), "prog\n");
        assert_eq!(
            print(false, true, false, false, &deps),
            "prog:\n        statically linked\n"
        );
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
