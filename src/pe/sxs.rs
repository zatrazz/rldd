// Side-by-side assemblies: the dependent assemblies declared on the embedded
// RT_MANIFEST resource, resolved against the WinSxS store, which the loader
// searches before the standard order.

use std::cell::OnceCell;
use std::fs;
use std::path::MAIN_SEPARATOR;

use object::pe;

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

    // The directory of the highest version of ASSEMBLY for an object built
    // for MACHINE.  The manifest records the version the object was built
    // against and the publisher policy redirects it to the installed build.
    // So only the major and the minor are matched.
    pub fn resolve(&self, assembly: &Assembly, machine: pe::Machine) -> Option<String> {
        arch_names(&assembly.arch, machine)
            .iter()
            .find_map(|arch| self.best_build(assembly, arch))
            .map(|dir| format!("{}{MAIN_SEPARATOR}{dir}", self.root))
    }

    fn best_build(&self, assembly: &Assembly, arch: &str) -> Option<&String> {
        let prefix = format!(
            "{}_{}_{}_",
            arch,
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

        best.map(|(_, dir)| dir)
    }
}

// The names the assembly directories are prefixed with, in the order they are
// searched.  A manifest may record the architecture as a wildcard, which the
// loader matches against the one of the process.
fn arch_names(arch: &str, machine: pe::Machine) -> Vec<String> {
    let mut names = match arch {
        "" | "*" => vec![image_arch(machine).to_string()],
        arch => vec![arch.to_lowercase()],
    };
    // A Windows on ARM store holds no amd64 assembly, and the arm64 ones are
    // ARM64X images (the loader loads asemulated x86_64 object).
    if names[0] == "amd64" {
        names.push("arm64".to_string());
    }
    names
}

// The store architecture of an object, which is the one of the process the
// loader matches a wildcard against.
fn image_arch(machine: pe::Machine) -> &'static str {
    match machine {
        pe::IMAGE_FILE_MACHINE_I386 => "x86",
        pe::IMAGE_FILE_MACHINE_AMD64 => "amd64",
        pe::IMAGE_FILE_MACHINE_ARM64
        | pe::IMAGE_FILE_MACHINE_ARM64EC
        | pe::IMAGE_FILE_MACHINE_ARM64X => "arm64",
        pe::IMAGE_FILE_MACHINE_ARM
        | pe::IMAGE_FILE_MACHINE_ARMNT
        | pe::IMAGE_FILE_MACHINE_THUMB => "arm",
        pe::IMAGE_FILE_MACHINE_IA64 => "ia64",
        // No assembly is installed for the machines the store does not name.
        _ => "",
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
        assert_eq!(
            arch_names(&assemblies[0].arch, pe::IMAGE_FILE_MACHINE_AMD64),
            ["amd64", "arm64"]
        );
        assert_eq!(language_name(&assemblies[0].language), "none");
    }

    // The wildcard architecture follows the object, not the machine rldd
    // itself was built for.
    #[test]
    fn wildcard_architecture() {
        assert_eq!(
            arch_names("*", pe::IMAGE_FILE_MACHINE_ARM64),
            ["arm64".to_string()]
        );
        assert_eq!(
            arch_names("", pe::IMAGE_FILE_MACHINE_I386),
            ["x86".to_string()]
        );
        assert_eq!(
            arch_names("*", pe::IMAGE_FILE_MACHINE_ARM64X),
            ["arm64".to_string()]
        );
        // A recorded architecture is taken as it is.
        assert_eq!(
            arch_names("X86", pe::IMAGE_FILE_MACHINE_ARM64),
            ["x86".to_string()]
        );
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
                // Another major and minor, which the manifest does not ask for.
                "amd64_microsoft.windows.common-controls_abcdefghijklmnopq_1.1.5.0_none_a",
                // The build the object was linked against, and a later one.
                "amd64_microsoft.windows.common-controls_abcdefghijklmnopq_1.2.3.4_none_b",
                "amd64_microsoft.windows.common-controls_abcdefghijklmnopq_1.2.5.0_none_c",
                "x86_microsoft.windows.common-controls_abcdefghijklmnopq_1.2.6.0_none_d",
            ],
        );
        let assembly = &parse_manifest(MANIFEST)[0];

        let resolved = store
            .resolve(assembly, pe::IMAGE_FILE_MACHINE_AMD64)
            .unwrap();
        assert!(resolved.ends_with("1.2.5.0_none_c"), "{resolved}");

        // A 32 bit object resolves the x86 assembly instead.
        let resolved = store
            .resolve(assembly, pe::IMAGE_FILE_MACHINE_I386)
            .unwrap();
        assert!(resolved.ends_with("1.2.6.0_none_d"), "{resolved}");
    }

    // A Windows on ARM store holds the arm64 assemblies only, which an
    // emulated x86_64 object falls back to.
    #[test]
    fn resolve_on_windows_on_arm() {
        let store = WinSxs::with_dirs(
            "W",
            &["arm64_microsoft.windows.common-controls_abcdefghijklmnopq_1.2.5.0_none_e"],
        );
        let assembly = &parse_manifest(MANIFEST)[0];

        for machine in [
            pe::IMAGE_FILE_MACHINE_ARM64,
            pe::IMAGE_FILE_MACHINE_ARM64X,
            pe::IMAGE_FILE_MACHINE_AMD64,
        ] {
            let resolved = store.resolve(assembly, machine);
            assert!(
                resolved.is_some_and(|dir| dir.ends_with("_none_e")),
                "{machine:?}"
            );
        }
        assert!(store
            .resolve(assembly, pe::IMAGE_FILE_MACHINE_I386)
            .is_none());
    }

    #[test]
    fn resolve_missing_assembly() {
        let store = WinSxs::with_dirs("W", &[]);
        assert!(store
            .resolve(&parse_manifest(MANIFEST)[0], pe::IMAGE_FILE_MACHINE_AMD64)
            .is_none());
    }

    #[test]
    fn assembly_version() {
        assert_eq!(version("6.0.26100.8972"), vec![6, 0, 26100, 8972]);
        assert!(version("6.0.26100.8972") > version("6.0.26100.8875"));
    }
}
