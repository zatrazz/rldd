// FreeBSD libmap.conf(5) parsing, used to filter and remap shared object names.
// The semantics follow the rtld libmap.c implementation: mappings can be
// constrained to a program (exact path, directory prefix, or basename), only
// the matching section defined last is considered, and the unconstrained
// mappings are used as fallback.  For both, the mapping defined last wins.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Debug, PartialEq)]
enum ConstraintType {
    Exact,
    Directory,
    Basename,
}

#[derive(Debug)]
struct Constraint {
    ctype: ConstraintType,
    spec: String,
    // In definition order, while rtld inserts each one at the head of its
    // list (lm_add).
    mappings: Vec<(String, String)>,
}

impl Constraint {
    fn new(spec: &str) -> Self {
        let ctype = if spec.ends_with('/') {
            ConstraintType::Directory
        } else if spec.contains('/') {
            ConstraintType::Exact
        } else {
            ConstraintType::Basename
        };
        Self {
            ctype,
            spec: spec.to_string(),
            mappings: Vec::new(),
        }
    }

    // The lmp_find match of the program REFPATH.
    fn matches(&self, refpath: &str) -> bool {
        match self.ctype {
            ConstraintType::Exact => refpath == self.spec,
            ConstraintType::Directory => refpath.starts_with(&self.spec),
            ConstraintType::Basename => quickbasename(refpath) == self.spec,
        }
    }

    // The lml_find mapping of NAME, the one defined last.
    fn find(&self, name: &str) -> Option<&str> {
        self.mappings
            .iter()
            .rev()
            .find(|(from, _)| from == name)
            .map(|(_, to)| to.as_str())
    }
}

// The part of PATH after the last slash, which is empty for a directory.
fn quickbasename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// rtld keeps the unconstrained mappings on a basename section with this name.
const DEFAULT_SECTION: &str = "$DEFAULT$";

#[derive(Debug, Default)]
pub struct LibMap {
    // In definition order, while rtld inserts each one at the head of its list
    // (lmp_init), the unconstrained one included.
    sections: Vec<Constraint>,
    // The files (by path, and by device and inode) and the directories (by
    // path) already parsed.
    parsed: Vec<(String, Option<(u64, u64)>)>,
}

impl LibMap {
    // The lmp_find section of the program PATH: the one defined last whose
    // constraint matches.
    fn section(&self, path: &str) -> Option<&Constraint> {
        self.sections.iter().rev().find(|c| c.matches(path))
    }

    // The mapping of NAME for the object REFPATH, without the side effect of
    // find.
    #[cfg(test)]
    pub fn lookup<'a>(&'a self, refpath: &str, name: &str) -> Option<&'a str> {
        if let Some(target) = self.section(refpath).and_then(|c| c.find(name)) {
            return Some(target);
        }
        self.section(DEFAULT_SECTION).and_then(|c| c.find(name))
    }

    // The lm_find mapping of NAME, a library name or a search directory, for
    // the object REFPATH (None for no object, a preloaded one).  A mapping of
    // the object section also becomes an unconstrained one (lm_add(NULL,
    // ...)), which any object then gets for NAME.
    pub fn find(&mut self, refpath: Option<&str>, name: &str) -> Option<String> {
        if let Some(refpath) = refpath {
            if let Some(target) = self.section(refpath).and_then(|c| c.find(name)) {
                let target = target.to_string();
                self.add_mapping(&None, name, &target);
                return Some(target);
            }
        }
        self.section(DEFAULT_SECTION)
            .and_then(|c| c.find(name))
            .map(str::to_string)
    }

    // Like lm_add, the section is found with the lmp_find matching, so a
    // section adds to a matching one defined before it (for instance
    // [/usr/local/] to [/usr/]) instead of being created.
    fn add_mapping(&mut self, constraint: &Option<String>, from: &str, to: &str) {
        let spec = constraint.as_deref().unwrap_or(DEFAULT_SECTION);
        let section = match self.sections.iter().rposition(|c| c.matches(spec)) {
            Some(section) => section,
            None => {
                self.sections.push(Constraint::new(spec));
                self.sections.len() - 1
            }
        };
        let section = &mut self.sections[section];
        if section.find(from) != Some(to) {
            section.mappings.push((from.to_string(), to.to_string()));
        }
    }
}

// The lmc_parse line buffer size (MAXPATHLEN + 13), the rest of a longer line
// being skipped, and the section name one (MAXPATHLEN).
const LINE_SIZE: usize = 1024 + 13;
const SECTION_SIZE: usize = 1024;

// The only blanks lmc_parse takes.
fn is_blank(c: &u8) -> bool {
    *c == b' ' || *c == b'\t'
}

fn trim_blanks(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|c| !is_blank(c)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|c| !is_blank(c))
        .map_or(start, |end| end + 1);
    &s[start..end]
}

// The section name of a '[NAME]' selector line, given after the bracket,
// where only blanks might surround NAME.
fn parse_selector(selector: &[u8]) -> Option<String> {
    let selector = trim_blanks(selector);
    let end = selector
        .iter()
        .position(|c| is_blank(c) || *c == b']')
        .unwrap_or(selector.len());
    let (name, rest) = selector.split_at(end);
    if name.is_empty() || name.len() >= SECTION_SIZE || trim_blanks(rest) != b"]" {
        return None;
    }
    Some(String::from_utf8_lossy(name).into_owned())
}

// Parse the CONTENT lines the way lmc_parse does, on bytes: a mapping line has
// exactly two words, and an invalid or empty selector does not change the
// section.
fn parse_content(libmap: &mut LibMap, content: &[u8]) {
    // The constraint state is local to each parsed file.
    let mut constraint: Option<String> = None;

    for line in content.split(|c| *c == b'\n') {
        let line = &line[..line.len().min(LINE_SIZE - 1)];
        // A comment, a NUL, or a carriage return ends the line.
        let end = line
            .iter()
            .position(|c| matches!(c, b'#' | b'\0' | b'\r'))
            .unwrap_or(line.len());
        let line = trim_blanks(&line[..end]);
        if line.is_empty() {
            continue;
        }

        if let Some(selector) = line.strip_prefix(b"[") {
            if let Some(spec) = parse_selector(selector) {
                constraint = Some(spec);
            }
            continue;
        }

        let mut words = line.split(is_blank).filter(|word| !word.is_empty());
        let (Some(from), Some(to), None) = (words.next(), words.next(), words.next()) else {
            continue;
        };
        let (from, to) = (String::from_utf8_lossy(from), String::from_utf8_lossy(to));

        match from.as_ref() {
            "includedir" => parse_dir(libmap, &to),
            "include" => parse_file(libmap, &to),
            _ => libmap.add_mapping(&constraint, &from, &to),
        }
    }
}

// Like lmc_parse_file, a file already parsed (with the same path, or the same
// device and inode) is skipped, which also ends an include loop.  A file is
// recorded once read, so one that fails to open might be tried again.
fn parse_file(libmap: &mut LibMap, filename: &str) {
    if libmap.parsed.iter().any(|(path, _)| path == filename) {
        return;
    }
    let Ok(mut file) = fs::File::open(filename) else {
        return;
    };
    let Ok(metadata) = file.metadata() else {
        return;
    };
    let id = Some((metadata.dev(), metadata.ino()));
    if libmap.parsed.iter().any(|(_, parsed)| *parsed == id) {
        return;
    }
    let mut content = Vec::new();
    if file.read_to_end(&mut content).is_err() {
        return;
    }
    libmap.parsed.push((filename.to_string(), id));
    parse_content(libmap, &content);
}

// Like lmc_parse_dir, a directory already parsed (with the same path) is
// skipped, and only its regular files (not the symbolic links) named *.conf
// are parsed, the hidden ones included, in the directory order.
fn parse_dir(libmap: &mut LibMap, dirname: &str) {
    if libmap.parsed.iter().any(|(path, _)| path == dirname) {
        return;
    }
    let entries = match fs::read_dir(dirname) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    libmap.parsed.push((dirname.to_string(), None));
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|filetype| filetype.is_file()) {
            continue;
        }
        match entry.file_name().to_str() {
            Some(name) if name.ends_with(".conf") => {
                parse_file(libmap, &format!("{dirname}/{name}"));
            }
            _ => {}
        }
    }
}

pub fn parse_libmap<P: AsRef<Path>>(filename: &P) -> Option<LibMap> {
    if !filename.as_ref().exists() {
        return None;
    }
    let mut libmap = LibMap::default();
    parse_file(&mut libmap, &filename.as_ref().to_string_lossy());
    Some(libmap)
}

// The libmap.conf of the rtld loading an object of the EI_CLASS class, where
// the 32-bit compat rtld of a 64-bit system has its "32" COMPAT_libcompat
// suffix (_PATH_LIBMAP_CONF).
pub fn libmap_path(ei_class: object::elf::FileClass) -> &'static str {
    if cfg!(target_pointer_width = "64") && ei_class == object::elf::ELFCLASS32 {
        "/etc/libmap32.conf"
    } else {
        "/etc/libmap.conf"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;

    fn parse_str(content: &str) -> LibMap {
        let mut libmap = LibMap::default();
        parse_content(&mut libmap, content.as_bytes());
        libmap
    }

    #[test]
    fn parse_default_mapping() {
        let libmap = parse_str(
            "# comment\n\
             libfoo.so.1 libbar.so.1  # trailing comment\n\
             libbaz.so.1\tlibqux.so.1\n",
        );
        assert_eq!(
            libmap.lookup("/bin/prog", "libfoo.so.1"),
            Some("libbar.so.1")
        );
        assert_eq!(
            libmap.lookup("/bin/prog", "libbaz.so.1"),
            Some("libqux.so.1")
        );
        assert_eq!(libmap.lookup("/bin/prog", "libother.so.1"), None);
    }

    #[test]
    fn parse_constrained_mapping() {
        let libmap = parse_str(
            "libfoo.so.1 libdefault.so.1\n\
             [/usr/bin/prog]\n\
             libfoo.so.1 libexact.so.1\n\
             [/usr/local/]\n\
             libfoo.so.1 libdir.so.1\n\
             [prog3]\n\
             libfoo.so.1 libbase.so.1\n",
        );
        assert_eq!(
            libmap.lookup("/usr/bin/prog", "libfoo.so.1"),
            Some("libexact.so.1")
        );
        assert_eq!(
            libmap.lookup("/usr/local/bin/other", "libfoo.so.1"),
            Some("libdir.so.1")
        );
        assert_eq!(
            libmap.lookup("/opt/bin/prog3", "libfoo.so.1"),
            Some("libbase.so.1")
        );
        assert_eq!(
            libmap.lookup("/bin/unrelated", "libfoo.so.1"),
            Some("libdefault.so.1")
        );
    }

    #[test]
    fn parse_constraint_fallback() {
        let libmap = parse_str(
            "libbar.so.1 libdefault.so.1\n\
             [/usr/bin/prog]\n\
             libfoo.so.1 libexact.so.1\n",
        );
        // A matching constraint without the mapping falls back to the default.
        assert_eq!(
            libmap.lookup("/usr/bin/prog", "libbar.so.1"),
            Some("libdefault.so.1")
        );
    }

    // An empty or invalid selector keeps the current section.
    #[test]
    fn parse_invalid_selector() {
        let libmap = parse_str(
            "[prog]\n\
             []\n\
             [ ]\n\
             [a b]\n\
             [other]x\n\
             [other\n\
             libfoo.so.1 libprog.so.1\n\
             [ prog2 ]  # comment\n\
             libbar.so.1 libprog2.so.1\n",
        );
        assert_eq!(
            libmap.lookup("/bin/prog", "libfoo.so.1"),
            Some("libprog.so.1")
        );
        assert_eq!(libmap.lookup("/bin/other", "libfoo.so.1"), None);
        assert_eq!(
            libmap.lookup("/bin/prog2", "libbar.so.1"),
            Some("libprog2.so.1")
        );
    }

    // A mapping line has exactly two words, separated by blanks only, and a
    // carriage return ends it like a comment.
    #[test]
    fn parse_mapping_words() {
        let libmap = parse_str(
            "libfoo.so.1 libbar.so.1 extra\n\
             libbaz.so.1\n\
             libqux.so.1\x0blibquux.so.1\n\
             libcr.so.1 libcrlf.so.1\r\n\
             libhash.so.1\tlibhash2.so.1#comment\n",
        );
        for name in ["libfoo.so.1", "libbaz.so.1", "libqux.so.1"] {
            assert_eq!(libmap.lookup("/bin/x", name), None);
        }
        assert_eq!(libmap.lookup("/bin/x", "libcr.so.1"), Some("libcrlf.so.1"));
        assert_eq!(
            libmap.lookup("/bin/x", "libhash.so.1"),
            Some("libhash2.so.1")
        );
    }

    // The file is not required to be valid UTF-8.
    #[test]
    fn parse_invalid_utf8() {
        let mut libmap = LibMap::default();
        parse_content(&mut libmap, b"# caf\xe9\nlibfoo.so.1 libbar.so.1\n");
        assert_eq!(libmap.lookup("/bin/x", "libfoo.so.1"), Some("libbar.so.1"));
    }

    #[test]
    fn compat_libmap() {
        assert_eq!(libmap_path(object::elf::ELFCLASS64), "/etc/libmap.conf");
        if cfg!(target_pointer_width = "64") {
            assert_eq!(libmap_path(object::elf::ELFCLASS32), "/etc/libmap32.conf");
        }
    }

    // A mapping of the object section also becomes an unconstrained one,
    // while no object only gets the unconstrained ones.
    #[test]
    fn find_adds_the_constrained_mapping() {
        let mut libmap = parse_str("[prog]\nlibfoo.so.1 libbar.so.1\n");
        assert_eq!(libmap.find(Some("/bin/other"), "libfoo.so.1"), None);
        assert_eq!(libmap.find(None, "libfoo.so.1"), None);
        assert_eq!(
            libmap.find(Some("/bin/prog"), "libfoo.so.1").as_deref(),
            Some("libbar.so.1")
        );
        assert_eq!(
            libmap.find(Some("/bin/other"), "libfoo.so.1").as_deref(),
            Some("libbar.so.1")
        );
        assert_eq!(
            libmap.find(None, "libfoo.so.1").as_deref(),
            Some("libbar.so.1")
        );
    }

    #[test]
    fn mapping_defined_last_wins() {
        let libmap = parse_str(
            "libfoo.so.1 libfirst.so.1\n\
             libfoo.so.1 liblast.so.1\n\
             [prog]\n\
             libbar.so.1 libfirst.so.1\n\
             libbar.so.1 liblast.so.1\n",
        );
        assert_eq!(libmap.lookup("/bin/x", "libfoo.so.1"), Some("liblast.so.1"));
        assert_eq!(
            libmap.lookup("/bin/prog", "libbar.so.1"),
            Some("liblast.so.1")
        );
    }

    #[test]
    fn section_defined_last_wins() {
        let libmap = parse_str(
            "[/usr/local/]\n\
             libz.so.1 libdir.so.1\n\
             [prog]\n\
             libz.so.1 libbase.so.1\n",
        );
        assert_eq!(
            libmap.lookup("/usr/local/bin/prog", "libz.so.1"),
            Some("libbase.so.1")
        );
        assert_eq!(
            libmap.lookup("/usr/local/bin/other", "libz.so.1"),
            Some("libdir.so.1")
        );

        let libmap = parse_str(
            "[prog]\n\
             libz.so.1 libbase.so.1\n\
             [/usr/local/]\n\
             libz.so.1 libdir.so.1\n",
        );
        assert_eq!(
            libmap.lookup("/usr/local/bin/prog", "libz.so.1"),
            Some("libdir.so.1")
        );
        assert_eq!(
            libmap.lookup("/usr/bin/prog", "libz.so.1"),
            Some("libbase.so.1")
        );
    }

    // A section matching an earlier one, taken as a program path, adds its
    // mappings to it.
    #[test]
    fn section_adds_to_matching_section() {
        let libmap = parse_str(
            "[/usr/]\n\
             liba.so.1 libusr.so.1\n\
             [/usr/local/]\n\
             libb.so.1 liblocal.so.1\n\
             [prog]\n\
             libc.so.1 libbase.so.1\n\
             [/usr/bin/prog]\n\
             libd.so.1 libexact.so.1\n",
        );
        assert_eq!(
            libmap.lookup("/usr/bin/x", "libb.so.1"),
            Some("liblocal.so.1")
        );
        assert_eq!(
            libmap.lookup("/usr/local/bin/x", "liba.so.1"),
            Some("libusr.so.1")
        );
        assert_eq!(
            libmap.lookup("/opt/prog", "libd.so.1"),
            Some("libexact.so.1")
        );
    }

    #[test]
    fn parse_include() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let included = tmpdir.path().join("included.conf");
        fs::write(&included, "libbar.so.1 libincluded.so.1\n")?;
        let conf = tmpdir.path().join("libmap.conf");
        fs::write(
            &conf,
            format!("libfoo.so.1 libmain.so.1\ninclude {}\n", included.display()),
        )?;

        let libmap = parse_libmap(&conf).unwrap();
        assert_eq!(
            libmap.lookup("/bin/prog", "libfoo.so.1"),
            Some("libmain.so.1")
        );
        assert_eq!(
            libmap.lookup("/bin/prog", "libbar.so.1"),
            Some("libincluded.so.1")
        );
        assert!(parse_libmap(&tmpdir.path().join("missing.conf")).is_none());
        Ok(())
    }

    // Only the regular files named *.conf of an included directory are parsed,
    // the hidden ones included.
    #[test]
    fn parse_includedir() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let dir = tmpdir.path().join("libmap.d");
        fs::create_dir(&dir)?;
        fs::write(dir.join("a.conf"), "liba.so.1 libconf.so.1\n")?;
        fs::write(dir.join(".hidden.conf"), "libh.so.1 libhidden.so.1\n")?;
        fs::write(
            dir.join("0.conf.sample"),
            "liba.so.1 libsample.so.1\nlibs.so.1 libsample.so.1\n",
        )?;
        fs::write(dir.join("noext"), "libn.so.1 libnoext.so.1\n")?;
        let other = tmpdir.path().join("other");
        fs::write(&other, "libl.so.1 liblink.so.1\n")?;
        std::os::unix::fs::symlink(&other, dir.join("link.conf"))?;
        fs::create_dir(dir.join("sub.conf"))?;
        fs::write(dir.join("sub.conf/x.conf"), "libx.so.1 libsub.so.1\n")?;

        let conf = tmpdir.path().join("libmap.conf");
        fs::write(&conf, format!("includedir {}\n", dir.display()))?;
        let libmap = parse_libmap(&conf).unwrap();
        assert_eq!(libmap.lookup("/bin/x", "liba.so.1"), Some("libconf.so.1"));
        assert_eq!(libmap.lookup("/bin/x", "libh.so.1"), Some("libhidden.so.1"));
        for name in ["libs.so.1", "libn.so.1", "libl.so.1", "libx.so.1"] {
            assert_eq!(libmap.lookup("/bin/x", name), None);
        }
        Ok(())
    }

    // A file included again is not parsed again, so it does not override the
    // mappings defined after its first inclusion.
    #[test]
    fn parse_include_again() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let included = tmpdir.path().join("included.conf");
        fs::write(&included, "libfoo.so.1 libincluded.so.1\n")?;
        let conf = tmpdir.path().join("libmap.conf");
        let include = format!("include {}\n", included.display());
        fs::write(
            &conf,
            format!("{include}libfoo.so.1 libmain.so.1\n{include}"),
        )?;

        let libmap = parse_libmap(&conf).unwrap();
        assert_eq!(
            libmap.lookup("/bin/prog", "libfoo.so.1"),
            Some("libmain.so.1")
        );
        Ok(())
    }

    // Each file and directory is parsed once, however many times (and through
    // whatever loop) it is included.
    #[test]
    fn parse_include_loop() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let dir = tmpdir.path().display();
        let conf = tmpdir.path().join("libmap.conf");
        let included = tmpdir.path().join("included.conf");
        fs::write(
            &included,
            format!(
                "libbar.so.1 libincluded.so.1\n\
                 include {conf}\n\
                 include {included}\n\
                 includedir {dir}\n",
                conf = conf.display(),
                included = included.display(),
            ),
        )?;
        let include = format!("include {}\n", conf.display());
        fs::write(
            &conf,
            format!(
                "libfoo.so.1 libmain.so.1\n\
                 {include}{include}{include}{include}\
                 include {}\n\
                 includedir {dir}\n\
                 includedir {dir}\n\
                 include {dir}/./libmap.conf\n",
                included.display(),
            ),
        )?;

        let libmap = parse_libmap(&conf).unwrap();
        assert_eq!(
            libmap.lookup("/bin/prog", "libfoo.so.1"),
            Some("libmain.so.1")
        );
        assert_eq!(
            libmap.lookup("/bin/prog", "libbar.so.1"),
            Some("libincluded.so.1")
        );
        assert_eq!(libmap.parsed.len(), 3);
        Ok(())
    }
}
