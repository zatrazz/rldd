// Side-by-side assemblies: the dependent assemblies declared on the embedded
// RT_MANIFEST resource, resolved against the WinSxS store, which the loader
// searches before the standard order.

use std::cell::OnceCell;
use std::fs;

use object::pe;

use crate::pathutils;

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
            root: pathutils::join(windows_dir, "WinSxS"),
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
            .map(|dir| pathutils::join(&self.root, dir))
    }

    fn best_build(&self, assembly: &Assembly, arch: &str) -> Option<&String> {
        let prefix = format!(
            "{}_{}_{}_",
            arch,
            shorten(&assembly.name.to_lowercase(), NAME_LIMIT),
            assembly.token.to_lowercase()
        );
        let language = shorten(&language_name(&assembly.language), LANGUAGE_LIMIT);
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

// The store shortens the name and the language fields of the directory names
// longer than these, keeping as much of the head as of the tail around a '..':
// 'microsoft.windows.c..-controls.resources' and 'sr-..-rs' are the
// directory fields of Microsoft.Windows.Common-Controls.Resources and
// sr-Latn-RS.  Derived from a Windows 11 24H2 store, where the 12424
// shortened names are all 40 characters long and none of the others is
// longer, and the same holds for the languages and 8 characters.
const NAME_LIMIT: usize = 40;
const LANGUAGE_LIMIT: usize = 8;

fn shorten(field: &str, limit: usize) -> String {
    let chars: Vec<char> = field.chars().collect();
    if chars.len() <= limit {
        return field.to_string();
    }
    let keep = (limit - 2) / 2;
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{head}..{tail}")
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

// The manifest encoding, told by its byte order mark as an XML parser does:
// UTF-8 and UTF-16 in either order (the resource compiler keeps the file as
// it is, and an external manifest may be saved as UTF-16).  A UTF-16 one
// without a mark is told by the '<' that starts it, and anything else is
// taken as UTF-8.
fn decode(data: &[u8]) -> String {
    let utf16 = |data: &[u8], from: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| from(*c)).collect();
        String::from_utf16_lossy(&units)
    };
    match data {
        [0xef, 0xbb, 0xbf, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        [0xff, 0xfe, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xfe, 0xff, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [b'<', 0, ..] => utf16(data, u16::from_le_bytes),
        [0, b'<', ..] => utf16(data, u16::from_be_bytes),
        _ => String::from_utf8_lossy(data).into_owned(),
    }
}

// An element tag, with its name and the text holding its attributes.
struct Tag<'a> {
    name: &'a str,
    attrs: &'a str,
    closing: bool,
    empty: bool,
}

// The markup that holds no element, skipped whole: an element inside a
// comment or a CDATA section is text, not an element.
const SKIPPED: [(&str, &str); 4] = [
    ("<!--", "-->"),
    ("<![CDATA[", "]]>"),
    ("<?", "?>"),
    ("<!", ">"),
];

// The element tags of an XML document, in order.
fn tags(xml: &str) -> Vec<Tag<'_>> {
    let mut tags = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        rest = &rest[start..];
        if let Some((open, close)) = SKIPPED.iter().find(|(open, _)| rest.starts_with(open)) {
            match rest[open.len()..].find(close) {
                Some(end) => rest = &rest[open.len() + end + close.len()..],
                None => break,
            }
            continue;
        }

        // An attribute value may hold a '>', so the tag ends at the first one
        // outside the quotes.
        let mut quote = None;
        let Some(end) = rest.bytes().position(|byte| match quote {
            Some(open) if byte == open => {
                quote = None;
                false
            }
            Some(_) => false,
            None if byte == b'"' || byte == b'\'' => {
                quote = Some(byte);
                false
            }
            None => byte == b'>',
        }) else {
            break;
        };
        let body = &rest[1..end];
        rest = &rest[end + 1..];

        let (closing, body) = match body.strip_prefix('/') {
            Some(body) => (true, body),
            None => (false, body),
        };
        let (empty, body) = match body.strip_suffix('/') {
            Some(body) => (true, body),
            None => (false, body),
        };
        let split = body
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(body.len());
        tags.push(Tag {
            name: &body[..split],
            attrs: &body[split..],
            closing,
            empty,
        });
    }
    tags
}

// The element name without its namespace prefix: the manifests generated by
// the Visual Studio templates name the elements as '<asmv1:assembly>'.
fn local_name(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}

// The attributes of a tag, with the values unescaped.  The value may be quoted
// with either quote, and there may be whitespace around the '='.
fn attributes(mut text: &str) -> Vec<(&str, String)> {
    let mut attrs = Vec::new();
    loop {
        text = text.trim_start();
        let Some(eq) = text.find('=') else {
            break;
        };
        let name = text[..eq].trim_end();
        let value = text[eq + 1..].trim_start();
        let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            break;
        };
        let Some(end) = value[1..].find(quote) else {
            break;
        };
        attrs.push((name, unescape(&value[1..1 + end])));
        text = &value[1 + end + 1..];
    }
    attrs
}

// Expand the predefined entities and the character references.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';') else {
            break;
        };
        let expanded = match &rest[1..end] {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            reference => reference
                .strip_prefix("#x")
                .map(|hex| u32::from_str_radix(hex, 16))
                .or_else(|| reference.strip_prefix('#').map(str::parse))
                .and_then(Result::ok)
                .and_then(char::from_u32),
        };
        match expanded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

// Parse the dependent assembly identities out of a manifest.  No need for an
// XML parser: each identity is the assemblyIdentity element of a
// dependentAssembly one, so walking the element tags (with the comments and the
// CDATA sections skipped, and the namespace prefixes dropped) finds them.
pub fn parse_manifest(data: &[u8]) -> Vec<Assembly> {
    let manifest = decode(data);
    let mut assemblies = Vec::new();
    // Whether a dependentAssembly element is open and its identity still
    // pending.
    let mut dependent = false;
    for tag in tags(&manifest) {
        match (local_name(tag.name), tag.closing) {
            ("dependentAssembly", false) => dependent = !tag.empty,
            ("dependentAssembly", true) => dependent = false,
            ("assemblyIdentity", false) if dependent => {
                dependent = false;
                let attrs = attributes(tag.attrs);
                let attribute = |name: &str| {
                    attrs
                        .iter()
                        .find(|(attr, _)| *attr == name)
                        .map(|(_, value)| value.clone())
                        .unwrap_or_default()
                };
                let name = attribute("name");
                if name.is_empty() {
                    continue;
                }
                let assembly = Assembly {
                    name,
                    version: attribute("version"),
                    arch: attribute("processorArchitecture"),
                    token: attribute("publicKeyToken"),
                    language: attribute("language"),
                };
                if !assemblies.contains(&assembly) {
                    assemblies.push(assembly);
                }
            }
            _ => {}
        }
    }
    assemblies
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

    fn manifest() -> Vec<Assembly> {
        parse_manifest(MANIFEST.as_bytes())
    }

    #[test]
    fn parse_dependent_assembly() {
        let assemblies = manifest();
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
        assert!(parse_manifest(b"<assembly></assembly>").is_empty());
        assert!(parse_manifest(b"").is_empty());
        assert!(parse_manifest(b"<dependentAssembly><assemblyIdentity").is_empty());
    }

    // Only the identity of a dependent assembly counts, not the one of the
    // manifest itself nor any other element.
    #[test]
    fn own_identity() {
        let manifest = br#"<assembly><assemblyIdentity name="App" version="1.0.0.0"/>
            <file name="x.dll"/><dependency><dependentAssembly>
            <assemblyIdentity name="Dep" version="1.0.0.0"/>
            <assemblyIdentity name="Second" version="1.0.0.0"/>
            </dependentAssembly></dependency></assembly>"#;
        let names: Vec<_> = parse_manifest(manifest)
            .into_iter()
            .map(|a| a.name)
            .collect();
        assert_eq!(names, ["Dep"]);
    }

    // The template Visual Studio adds to a project holds the common controls
    // dependency inside a comment, which the loader ignores, and so does
    // anything inside a CDATA section.
    #[test]
    fn commented_dependency() {
        let commented = MANIFEST
            .replace("<dependency>", "<!-- <dependency>")
            .replace("</dependency>", "</dependency> -->");
        assert!(parse_manifest(commented.as_bytes()).is_empty());

        let cdata = MANIFEST
            .replace("<dependency>", "<![CDATA[ <dependency>")
            .replace("</dependency>", "</dependency> ]]>");
        assert!(parse_manifest(cdata.as_bytes()).is_empty());

        // A comment right before the element does not hide it.
        let before = MANIFEST.replace("<dependency>", "<!-- <dependency> --><dependency>");
        assert_eq!(parse_manifest(before.as_bytes()), manifest());
    }

    // The elements are matched without their namespace prefix.
    #[test]
    fn prefixed_elements() {
        let prefixed = MANIFEST
            .replace("<assembly xmlns=", "<asmv1:assembly xmlns:asmv1=")
            .replace("</assembly>", "</asmv1:assembly>")
            .replace("dependency>", "asmv1:dependency>")
            .replace("dependentAssembly>", "asmv1:dependentAssembly>")
            .replace("<assemblyIdentity", "<asmv1:assemblyIdentity");
        assert_eq!(parse_manifest(prefixed.as_bytes()), manifest());
    }

    fn utf16(text: &str, bom: bool, big_endian: bool) -> Vec<u8> {
        let mut data = Vec::new();
        let units = bom.then_some(0xfeff).into_iter().chain(text.encode_utf16());
        for unit in units {
            match big_endian {
                true => data.extend_from_slice(&unit.to_be_bytes()),
                false => data.extend_from_slice(&unit.to_le_bytes()),
            }
        }
        data
    }

    // The encoding is told by the byte order mark, or by the first character
    // of a UTF-16 manifest without one.
    #[test]
    fn manifest_encodings() {
        let mut utf8 = vec![0xef, 0xbb, 0xbf];
        utf8.extend_from_slice(MANIFEST.as_bytes());
        assert_eq!(parse_manifest(&utf8), manifest());
        for (bom, big_endian) in [(true, false), (true, true), (false, false), (false, true)] {
            let data = utf16(MANIFEST, bom, big_endian);
            assert_eq!(parse_manifest(&data), manifest(), "{bom} {big_endian}");
        }
    }

    // Both quotes, the whitespace around the '=', and the entities.
    #[test]
    fn attribute_syntax() {
        let manifest = br#"<dependentAssembly><assemblyIdentity
            name = 'A&amp;B&#x2E;C&#46;D' version	=	"1.0.0.0"
            publicKeyToken='x>y' language="&lt;&bogus;&gt;"/></dependentAssembly>"#;
        let assemblies = parse_manifest(manifest);
        assert_eq!(assemblies.len(), 1);
        assert_eq!(assemblies[0].name, "A&B.C.D");
        assert_eq!(assemblies[0].version, "1.0.0.0");
        assert_eq!(assemblies[0].token, "x>y");
        assert_eq!(assemblies[0].language, "<&bogus;>");
    }

    #[test]
    fn attribute_prefix() {
        let attrs = attributes(r#" assemblyname="wrong" name="right" "#);
        assert_eq!(
            attrs,
            [
                ("assemblyname", "wrong".to_string()),
                ("name", "right".to_string())
            ]
        );
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
        let assembly = &manifest()[0];

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
        let assembly = &manifest()[0];

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
    fn shortened_fields() {
        assert_eq!(
            shorten("microsoft.windows.common-controls.resources", NAME_LIMIT),
            "microsoft.windows.c..-controls.resources"
        );
        assert_eq!(
            shorten(
                "microsoft.windows.isolationautomation.proxystub",
                NAME_LIMIT
            ),
            "microsoft.windows.i..utomation.proxystub"
        );
        let exact = "a".repeat(NAME_LIMIT);
        assert_eq!(shorten(&exact, NAME_LIMIT), exact);
        assert_eq!(shorten("sr-latn-rs", LANGUAGE_LIMIT), "sr-..-rs");
        assert_eq!(shorten("ca-es-valencia", LANGUAGE_LIMIT), "ca-..cia");
        assert_eq!(shorten("qps-ploc", LANGUAGE_LIMIT), "qps-ploc");
        assert_eq!(shorten("en-us", LANGUAGE_LIMIT), "en-us");
    }

    // A long assembly name and a long language are matched against the
    // shortened directory fields.
    #[test]
    fn resolve_shortened_directory() {
        let store = WinSxs::with_dirs(
            "W",
            &[
                "amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.1.0_sr-..-rs_a",
                "amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.1.0_en-us_b",
            ],
        );
        let manifest = br#"<dependentAssembly><assemblyIdentity
            name="Microsoft.Windows.Common-Controls.Resources" version="6.0.0.0"
            processorArchitecture="amd64" publicKeyToken="6595b64144ccf1df"
            language="sr-Latn-RS"/></dependentAssembly>"#;
        let assembly = &parse_manifest(manifest)[0];
        let resolved = store.resolve(assembly, pe::IMAGE_FILE_MACHINE_AMD64);
        assert!(resolved.is_some_and(|dir| dir.ends_with("_sr-..-rs_a")));
    }

    #[test]
    fn resolve_missing_assembly() {
        let store = WinSxs::with_dirs("W", &[]);
        assert!(store
            .resolve(&manifest()[0], pe::IMAGE_FILE_MACHINE_AMD64)
            .is_none());
    }

    #[test]
    fn assembly_version() {
        assert_eq!(version("6.0.26100.8972"), vec![6, 0, 26100, 8972]);
        assert!(version("6.0.26100.8972") > version("6.0.26100.8875"));
    }
}
