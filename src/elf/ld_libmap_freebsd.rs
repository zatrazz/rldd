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

    // The lm_find mapping of NAME for the object REFPATH.  On a constrained
    // hit rtld also adds the result as an unconstrained mapping, which a
    // library name never uses again (the object is loaded under that name,
    // which rtld matches before mapping it), so it is left out.
    pub fn lookup<'a>(&'a self, refpath: &str, name: &str) -> Option<&'a str> {
        if let Some(target) = self.section(refpath).and_then(|c| c.find(name)) {
            return Some(target);
        }
        self.section(DEFAULT_SECTION).and_then(|c| c.find(name))
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

fn parse_content(libmap: &mut LibMap, content: &str) {
    // The constraint state is local to each parsed file.
    let mut constraint: Option<String> = None;

    for line in content.lines() {
        let line = match line.find('#') {
            Some(comment) => &line[..comment],
            None => line,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(spec) = line.strip_prefix('[') {
            if let Some(spec) = spec.strip_suffix(']') {
                let spec = spec.trim();
                constraint = if spec.is_empty() {
                    None
                } else {
                    Some(spec.to_string())
                };
            }
            continue;
        }

        let mut tokens = line.split_whitespace();
        let (from, to) = match (tokens.next(), tokens.next()) {
            (Some(from), Some(to)) => (from, to),
            _ => continue,
        };

        match from {
            "includedir" => parse_dir(libmap, to),
            "include" => parse_file(libmap, to),
            _ => libmap.add_mapping(&constraint, from, to),
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
    let mut content = String::new();
    if file.read_to_string(&mut content).is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;

    fn parse_str(content: &str) -> LibMap {
        let mut libmap = LibMap::default();
        parse_content(&mut libmap, content);
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
