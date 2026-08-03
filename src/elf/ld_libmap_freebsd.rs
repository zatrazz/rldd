// FreeBSD libmap.conf(5) parsing, used to filter and remap shared object names.
// The semantics follow the rtld lm.c implementation: mappings can be constrained
// to a program (exact path, directory prefix, or basename), only the first
// matching constrained list is considered, and the unconstrained mappings are
// used as fallback.

use std::fs;
use std::path::Path;

use crate::pathutils;

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

    fn matches(&self, refpath: &str) -> bool {
        match self.ctype {
            ConstraintType::Exact => refpath == self.spec,
            ConstraintType::Directory => refpath.starts_with(&self.spec),
            ConstraintType::Basename => pathutils::get_name(&Path::new(refpath)) == self.spec,
        }
    }
}

#[derive(Debug, Default)]
pub struct LibMap {
    default: Vec<(String, String)>,
    constraints: Vec<Constraint>,
}

fn find_mapping<'a>(mappings: &'a [(String, String)], name: &str) -> Option<&'a str> {
    mappings
        .iter()
        .find(|(from, _)| from == name)
        .map(|(_, to)| to.as_str())
}

impl LibMap {
    pub fn lookup<'a>(&'a self, refpath: &str, name: &str) -> Option<&'a str> {
        if let Some(constraint) = self.constraints.iter().find(|c| c.matches(refpath)) {
            if let Some(target) = find_mapping(&constraint.mappings, name) {
                return Some(target);
            }
        }
        find_mapping(&self.default, name)
    }

    fn add_mapping(&mut self, constraint: &Option<String>, from: &str, to: &str) {
        let mappings = match constraint {
            Some(spec) => {
                if !self.constraints.iter().any(|c| c.spec == *spec) {
                    self.constraints.push(Constraint::new(spec));
                }
                let constraint = self
                    .constraints
                    .iter_mut()
                    .find(|c| c.spec == *spec)
                    .unwrap();
                &mut constraint.mappings
            }
            None => &mut self.default,
        };
        // Only the first mapping for a name is used.
        if find_mapping(mappings, from).is_none() {
            mappings.push((from.to_string(), to.to_string()));
        }
    }
}

const MAX_INCLUDE_DEPTH: usize = 32;

fn parse_content(libmap: &mut LibMap, content: &str, depth: usize) {
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
            "includedir" => parse_dir(libmap, to, depth + 1),
            "include" => parse_file(libmap, &Path::new(to), depth + 1),
            _ => libmap.add_mapping(&constraint, from, to),
        }
    }
}

fn parse_file<P: AsRef<Path>>(libmap: &mut LibMap, filename: &P, depth: usize) {
    if depth > MAX_INCLUDE_DEPTH {
        return;
    }
    if let Ok(content) = fs::read_to_string(filename) {
        parse_content(libmap, &content, depth);
    }
}

fn parse_dir(libmap: &mut LibMap, dirname: &str, depth: usize) {
    if depth > MAX_INCLUDE_DEPTH {
        return;
    }
    let entries = match fs::read_dir(dirname) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    let mut paths: Vec<_> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            !pathutils::get_name(path).starts_with('.') && path.is_file()
        })
        .collect();
    paths.sort();
    for path in paths {
        parse_file(libmap, &path, depth);
    }
}

pub fn parse_libmap<P: AsRef<Path>>(filename: &P) -> Option<LibMap> {
    if !filename.as_ref().exists() {
        return None;
    }
    let mut libmap = LibMap::default();
    parse_file(&mut libmap, filename, 0);
    Some(libmap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(content: &str) -> LibMap {
        let mut libmap = LibMap::default();
        parse_content(&mut libmap, content, 0);
        libmap
    }

    #[test]
    fn parse_default_mapping() {
        let libmap = parse_str(
            "# comment\n\
             libfoo.so.1 libbar.so.1  # trailing comment\n\
             libbaz.so.1\tlibqux.so.1\n",
        );
        assert_eq!(libmap.lookup("/bin/prog", "libfoo.so.1"), Some("libbar.so.1"));
        assert_eq!(libmap.lookup("/bin/prog", "libbaz.so.1"), Some("libqux.so.1"));
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
}
