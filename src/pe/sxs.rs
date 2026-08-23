// Side-by-side assemblies: the dependent assemblies declared on the embedded
// RT_MANIFEST resource, resolved against the WinSxS store, which the loader
// searches before the standard order.

use std::cell::OnceCell;
use std::fs;
use std::path::MAIN_SEPARATOR;

// The identity of a dependent assembly, as recorded on the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assembly {
    pub name: String,
    version: String,
    arch: String,
    token: String,
    language: String,
}

// The assembly directories are named:
//
// '{arch}_{name}_{token}_{version}_{language}_{hash}'
//
// A neutral assembly language is recorded as 'none'.
pub struct WinSxs {
    root: String,
    dirs: OnceCell<Vec<String>>,
}

impl WinSxs {
    pub fn new(windows_dir: &str) -> WinSxs {
        WinSxs {
            root: format!("{windows_dir}{MAIN_SEPARATOR}WinSxS"),
            dirs: OnceCell::new(),
        }
    }

    // The store holds tens of thousands of directories, so it is only listed
    // when an object declares a dependent assembly.
    fn dirs(&self) -> &[String] {
        self.dirs.get_or_init(|| {
            let mut dirs = Vec::new();
            if let Ok(entries) = fs::read_dir(&self.root) {
                for entry in entries.flatten() {
                    if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                        dirs.push(entry.file_name().to_string_lossy().to_lowercase());
                    }
                }
            }
            dirs
        })
    }

    #[cfg(test)]
    fn with_dirs(root: &str, dirs: &[&str]) -> WinSxs {
        WinSxs {
            root: root.to_string(),
            dirs: OnceCell::from(dirs.iter().map(|dir| dir.to_string()).collect::<Vec<_>>()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.dirs().is_empty()
    }

    pub fn len(&self) -> usize {
        self.dirs().len()
    }

    // The directory of the highest version of ASSEMBLY.  The manifest records
    // the version the object was built against and the publisher policy
    // redirects it to the installed build. So only the major and the minor
    // are matched.
    pub fn resolve(&self, assembly: &Assembly, is_32bit: bool) -> Option<String> {
        let prefix = format!(
            "{}_{}_{}_",
            arch_name(&assembly.arch, is_32bit),
            assembly.name.to_lowercase(),
            assembly.token.to_lowercase()
        );
        let language = language_name(&assembly.language);
        let wanted = version(&assembly.version);

        let mut best: Option<(Vec<u32>, &String)> = None;
        for dir in self.dirs() {
            let Some(rest) = dir.strip_prefix(&prefix) else {
                continue;
            };
            let Some((found, rest)) = rest.split_once('_') else {
                continue;
            };
            if !rest.starts_with(&format!("{language}_")) {
                continue;
            }
            let found = version(found);
            if found.len() < 2 || wanted.len() < 2 || found[..2] != wanted[..2] {
                continue;
            }
            if best.as_ref().is_none_or(|(best, _)| found > *best) {
                best = Some((found, dir));
            }
        }

        best.map(|(_, dir)| format!("{}{MAIN_SEPARATOR}{dir}", self.root))
    }
}

// A manifest may record the architecture and the language as a wildcard,
// which the loader matches against the process ones.
fn arch_name(arch: &str, is_32bit: bool) -> String {
    match arch {
        "" | "*" => match is_32bit {
            true => "x86".to_string(),
            false => host_arch().to_string(),
        },
        arch => arch.to_lowercase(),
    }
}

fn host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

fn language_name(language: &str) -> String {
    match language {
        "" | "*" | "neutral" => "none".to_string(),
        language => language.to_lowercase(),
    }
}

fn version(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|field| field.parse().unwrap_or(0))
        .collect()
}

// Parse the dependent assembly identities out of a manifest.  No need for a
// a XML parser, the identities are self contained elements.
pub fn parse_manifest(manifest: &str) -> Vec<Assembly> {
    let mut assemblies = Vec::new();
    for chunk in manifest.split("<dependentAssembly").skip(1) {
        let Some(start) = chunk.find("<assemblyIdentity") else {
            continue;
        };
        let chunk = &chunk[start..];
        let identity = match chunk.find('>') {
            Some(end) => &chunk[..end],
            None => chunk,
        };
        let name = attribute(identity, "name");
        if name.is_empty() {
            continue;
        }
        let assembly = Assembly {
            name,
            version: attribute(identity, "version"),
            arch: attribute(identity, "processorArchitecture"),
            token: attribute(identity, "publicKeyToken"),
            language: attribute(identity, "language"),
        };
        if !assemblies.contains(&assembly) {
            assemblies.push(assembly);
        }
    }
    assemblies
}

fn attribute(element: &str, name: &str) -> String {
    let mut from = 0;
    while let Some(at) = element[from..].find(name) {
        let at = from + at;
        from = at + name.len();
        // The name must be a whole attribute, not the tail of another one.
        if at > 0 && !element.as_bytes()[at - 1].is_ascii_whitespace() {
            continue;
        }
        let value = element[from..].trim_start();
        let Some(value) = value.strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let quote = match value.chars().next() {
            Some(quote @ ('"' | '\'')) => quote,
            _ => continue,
        };
        let value = &value[1..];
        if let Some(end) = value.find(quote) {
            return value[..end].to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls"
        version="1.2.3.4" processorArchitecture="*" publicKeyToken="abcdefghijklmnopq"
        language="*" />
    </dependentAssembly>
  </dependency>
</assembly>"#;

    #[test]
    fn parse_dependent_assembly() {
        let assemblies = parse_manifest(MANIFEST);
        assert_eq!(assemblies.len(), 1);
        assert_eq!(assemblies[0].name, "Microsoft.Windows.Common-Controls");
        assert_eq!(assemblies[0].version, "1.2.3.4");
        assert_eq!(assemblies[0].token, "abcdefghijklmnopq");
        assert_eq!(arch_name(&assemblies[0].arch, false), "amd64");
        assert_eq!(language_name(&assemblies[0].language), "none");
    }

    #[test]
    fn no_dependency() {
        assert!(parse_manifest("<assembly></assembly>").is_empty());
    }

    #[test]
    fn attribute_prefix() {
        let identity = r#"<assemblyIdentity assemblyname="wrong" name="right""#;
        assert_eq!(attribute(identity, "name"), "right");
        assert_eq!(attribute(identity, "missing"), "");
    }

    // The store holds several builds of the same assembly, and the highest
    // one of the requested major and minor is used.
    #[test]
    fn resolve_highest_build() {
        let store = WinSxs::with_dirs(
            "W",
            &[
                "amd64_microsoft.windows.common-controls_6595b64144ccf1df_5.82.26100.8328_none_a",
                "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.26100.8875_none_b",
                "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.26100.8972_none_c",
                "x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.26100.9168_none_d",
            ],
        );
        let assembly = &parse_manifest(MANIFEST)[0];

        let resolved = store.resolve(assembly, false).unwrap();
        assert!(resolved.ends_with("6.0.26100.8972_none_c"), "{resolved}");

        // A 32 bit object resolves the x86 assembly instead.
        let resolved = store.resolve(assembly, true).unwrap();
        assert!(resolved.ends_with("6.0.26100.9168_none_d"), "{resolved}");
    }

    #[test]
    fn resolve_missing_assembly() {
        let store = WinSxs::with_dirs("W", &[]);
        assert!(store.resolve(&parse_manifest(MANIFEST)[0], false).is_none());
    }

    #[test]
    fn assembly_version() {
        assert_eq!(version("6.0.26100.8972"), vec![6, 0, 26100, 8972]);
        assert!(version("6.0.26100.8972") > version("6.0.26100.8875"));
    }
}
