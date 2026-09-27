use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::elf::android::*;
use crate::search_path;
use crate::search_path::SearchPathVecExt;

use object::elf::{FileClass, Machine};

// A link from one namespace to another, along the set of libraries the link
// makes accessible (the 'namespace.<ns>.link.<linked>.shared_libs' list, or
// every library when 'allow_all_shared_libs' is set).
#[derive(Debug)]
pub struct NamespaceLink {
    pub namespace: String,
    shared_libs: Vec<String>,
    allow_all_shared_libs: bool,
}

impl NamespaceLink {
    pub fn is_accessible<S: AsRef<str>>(&self, file: S) -> bool {
        self.allow_all_shared_libs || self.shared_libs.iter().any(|lib| lib == file.as_ref())
    }
}

pub type NamespaceLinkingConfigVec = Vec<NamespaceLink>;

#[derive(Debug)]
pub struct NamespaceConfig {
    name: String,
    isolated: bool,
    visible: bool,
    // The 'whitelisted' and 'allowed_libs' names, which the loader only sets
    // on the namespaces other than the default one (init_default_namespaces),
    // so they are left empty for that one.
    allowed_libs: Vec<String>,
    pub search_paths: search_path::SearchPathVec,
    // The 'permitted.paths' directories, only with the variables replaced:
    // unlike the search paths, the loader does not resolve them.
    permitted_paths: Vec<String>,
    pub namespaces: NamespaceLinkingConfigVec,
}

impl NamespaceConfig {
    // The name part of the bionic android_namespace_t::is_accessible: an
    // isolated namespace with an allowed_libs list only loads the names on
    // it.
    pub fn is_accessible<S: AsRef<str>>(&self, file: S) -> bool {
        if !self.isolated {
            return true;
        }

        if !self.allowed_libs.is_empty() && !self.allowed_libs.contains(&file.as_ref().to_string())
        {
            return false;
        }

        // The loader cache resolution will check the search_path and fail if it is not
        // found.
        true
    }

    // The bionic android_namespace_t::is_accessible, which the loader applies
    // to the real path of every file a namespace loads (a DT_RUNPATH hit, or
    // a DT_NEEDED with a slash, included).  An isolated namespace only loads
    // a file whose name is on its allowed_libs (if it has any), and that is
    // directly in one of the LD_LIBRARY_PATH directories (which only the
    // default namespace has) or of its search paths, or anywhere below one of
    // its permitted paths.
    #[allow(dead_code)] // Not applied by the resolution yet.
    pub fn is_accessible_path(
        &self,
        realpath: &str,
        ld_library_paths: &search_path::SearchPathVec,
    ) -> bool {
        if !self.isolated {
            return true;
        }

        if !self.allowed_libs.is_empty() {
            let name = realpath.rsplit('/').next().unwrap_or(realpath);
            if !self.allowed_libs.iter().any(|lib| lib == name) {
                return false;
            }
        }

        let file = realpath.as_bytes();
        ld_library_paths
            .iter()
            .chain(&self.search_paths)
            .any(|dir| file_is_in_dir(file, dir.path.as_bytes()))
            || self
                .permitted_paths
                .iter()
                .any(|dir| file_is_under_dir(file, dir.as_bytes()))
    }
}

// The bionic file_is_in_dir: FILE is directly in DIR, compared as strings.
fn file_is_in_dir(file: &[u8], dir: &[u8]) -> bool {
    file.strip_prefix(dir)
        .and_then(|rest| rest.strip_prefix(b"/"))
        .is_some_and(|name| !name.contains(&b'/'))
}

// The bionic file_is_under_dir: FILE is anywhere below DIR, compared as
// strings (so an empty DIR takes any absolute path, while '/' takes none).
fn file_is_under_dir(file: &[u8], dir: &[u8]) -> bool {
    file.strip_prefix(dir)
        .is_some_and(|rest| rest.starts_with(b"/"))
}

const DEFAULT_NAME_CONFIG: &str = "default";

// The ${SDK_VER} when no '.version' file sets the target SDK version.
const ANDROID_API_FUTURE: i64 = 10000;

pub type LdCacheNs = HashMap<String, NamespaceConfig>;

#[derive(Debug)]
pub struct LdCache {
    namespaces_config: LdCacheNs,
}

impl LdCache {
    fn new() -> LdCache {
        LdCache {
            namespaces_config: LdCacheNs::new(),
        }
    }

    pub fn get_default_namespace(&self) -> Option<&NamespaceConfig> {
        self.namespaces_config.get(DEFAULT_NAME_CONFIG)
    }

    pub fn get_namespace<S: AsRef<str>>(&self, name: S) -> Option<&NamespaceConfig> {
        self.namespaces_config.get(name.as_ref())
    }

    pub fn namespaces_count(&self) -> usize {
        self.namespaces_config.len()
    }

    fn config_set(&self) -> HashSet<String> {
        self.namespaces_config.keys().cloned().collect()
    }

    fn push_namespace(&mut self, name: &str) {
        self.namespaces_config.insert(
            name.to_string(),
            NamespaceConfig {
                name: name.to_string(),
                isolated: false,
                visible: false,
                search_paths: search_path::SearchPathVec::new(),
                allowed_libs: Vec::<String>::new(),
                permitted_paths: Vec::<String>::new(),
                namespaces: NamespaceLinkingConfigVec::new(),
            },
        );
    }
}

struct Properties {
    properties: HashMap<String, String>,
    target_sdk_version: String,
}

impl Properties {
    fn new() -> Properties {
        Properties {
            properties: HashMap::<String, String>::new(),
            target_sdk_version: "".to_string(),
        }
    }

    fn add<K: AsRef<str>, V: AsRef<str>>(&mut self, key: K, value: V) {
        self.properties
            .insert(key.as_ref().to_string(), value.as_ref().to_string());
    }

    fn append<K: AsRef<str>, V: AsRef<str>>(&mut self, key: K, value: V) {
        let key = key.as_ref().to_string();
        if let Some(v) = self.properties.get_mut(&key) {
            let sep = if key.ends_with(".links") || key.ends_with(".namespaces") {
                ','
            } else if key.ends_with(".paths")
                || key.ends_with(".shared_libs")
                || key.ends_with(".whitelisted")
                || key.ends_with(".allowed_libs")
            {
                ':'
            } else {
                return;
            };
            v.push_str(&format!("{sep}{}", value.as_ref()));
        } else {
            self.add(key, value);
        };
    }

    // A comma separated list, with each entry trimmed like the bionic
    // Properties::get_strings does.  A property that is set but empty is
    // one empty entry.
    fn get_strings<S: AsRef<str>>(&self, name: S) -> Vec<String> {
        match self.properties.get(name.as_ref()) {
            Some(value) => value
                .split(',')
                .map(|entry| entry.trim_matches(is_space).to_string())
                .collect(),
            None => Vec::new(),
        }
    }

    fn get_bool<S: AsRef<str>>(&self, name: S) -> bool {
        self.properties
            .get(name.as_ref())
            .map(|s| s == "true")
            .unwrap_or(false)
    }

    fn get_string<S: AsRef<str>>(&self, name: S) -> String {
        self.properties
            .get(name.as_ref())
            .unwrap_or(&"".to_string())
            .to_string()
    }

    // The bionic Properties::get_paths: the ':' separated list, with the
    // variables replaced on each entry.  An unset or empty property is an
    // empty list.
    fn get_paths<S: AsRef<str>>(
        &self,
        name: S,
        ei_class: FileClass,
        props: &SystemProperties,
    ) -> Vec<String> {
        let paths = self.get_string(name);
        if paths.is_empty() {
            return Vec::new();
        }

        // The VNDK APEX uses a different delimiter than the VNDK version
        // itself ('v30' against '-30').
        let vndk_ver = props.vndk_version_string('-');
        let vndk_apex_ver = props.vndk_version_string('v');
        let params = [
            ("LIB", libpath(ei_class)),
            ("SDK_VER", self.target_sdk_version.as_str()),
            ("VNDK_VER", vndk_ver.as_str()),
            ("VNDK_APEX_VER", vndk_apex_ver.as_str()),
        ];

        paths
            .split(':')
            .map(|path| format_string(path, &params))
            .collect()
    }
}

// The bionic resolve_path the search paths go through: the canonical path of
// an existing directory, so a library found through a symlinked directory is
// reported (and matched against the namespace directories) at its real
// location.  The loader falls back to the normalized path when it can not
// canonicalize an existing directory, and also accepts a directory inside a
// zip file, neither of which rldd can search.
fn resolve_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let resolved = std::fs::canonicalize(path).ok()?;
    resolved
        .is_dir()
        .then(|| resolved.to_string_lossy().into_owned())
}

// The bionic format_string: each '$NAME' or '${NAME}' of a variable in PARAMS
// is replaced, the variables tried in order with NAME matched as a prefix of
// what follows the '$' (so '$LIBFOO' is 'lib64FOO').  A replacement is not
// scanned again, and any other '$' is kept as is.
fn format_string(s: &str, params: &[(&str, &str)]) -> String {
    let mut r = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('$') {
        r.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let replaced = params.iter().find_map(|(name, replacement)| {
            after
                .strip_prefix(name)
                .or_else(|| {
                    after
                        .strip_prefix('{')
                        .and_then(|braced| braced.strip_prefix(name))
                        .and_then(|braced| braced.strip_prefix('}'))
                })
                .map(|tail| (replacement, tail))
        });
        match replaced {
            Some((replacement, tail)) => {
                r.push_str(replacement);
                rest = tail;
            }
            None => {
                r.push('$');
                rest = after;
            }
        }
    }
    r.push_str(rest);
    r
}

// A configuration line: a 'name = value' assignment, a 'name += value'
// append, a '[section]' header, or anything else, which the loader warns about
// and ignores.
#[derive(Debug, PartialEq)]
enum Token<'a> {
    PropertyAssign(&'a [u8], &'a [u8]),
    PropertyAppend(&'a [u8], &'a [u8]),
    Section(&'a [u8]),
    Error,
}

// The APEX whose configuration the bionic get_ld_config_file_apex_path
// selects for EXECUTABLE: an executable on the bin directory of an APEX
// (/apex/<name>/bin/<file>, and anywhere below that directory from Android 11
// on).  A shared library anywhere below /apex/<name> is taken as loaded by an
// executable on the bin directory of its APEX, like find_initial_section
// does.
fn apex_name(executable: &Path, library: bool, release: AndroidRelease) -> Option<String> {
    // The path split on '/' the way the loader does: "", "apex", the APEX
    // name, "bin", and the file.
    let parts: Vec<&[u8]> = executable
        .as_os_str()
        .as_bytes()
        .split(|&c| c == b'/')
        .collect();
    if parts.len() < 4 || !parts[0].is_empty() || parts[1] != b"apex" || parts[2].is_empty() {
        return None;
    }
    let in_bin = parts.len() >= 5
        && parts[3] == b"bin"
        && (parts.len() == 5 || release >= AndroidRelease::R30);
    (library || in_bin).then(|| String::from_utf8_lossy(parts[2]).into_owned())
}

// The configuration files the bionic get_ld_config_file_path tries for
// EXECUTABLE, in order: the first one that exists is read, and the last one
// is read regardless (a missing file meaning no configuration).
fn ld_config_candidates(
    executable: &Path,
    library: bool,
    e_machine: Machine,
    ei_class: FileClass,
    props: &SystemProperties,
) -> Vec<String> {
    let release = props.release;
    let default = "/system/etc/ld.config.txt".to_string();

    // Android 7.0/7.1 does not support ld.config.txt.
    if release < AndroidRelease::R26 {
        return Vec::new();
    }

    // Android 8.0/8.1 has the ld.config.txt hardcoded.
    if release < AndroidRelease::R28 {
        return vec![default];
    }

    let mut candidates = Vec::new();

    // Android 10 added the configuration the APEX ships, which Android 11
    // and 12 only read when linkerconfig did not generate one for it, and
    // Android 13 no longer reads.
    if release >= AndroidRelease::R29 {
        if let Some(apex) = apex_name(executable, library, release) {
            if release >= AndroidRelease::R30 {
                candidates.push(format!("/linkerconfig/{apex}/ld.config.txt"));
            }
            if release < AndroidRelease::R33 {
                candidates.push(format!("/apex/{apex}/etc/ld.config.txt"));
            }
        }
    }

    // Android 9 added the architecture specific configuration, used for the
    // native bridge objects.
    if let Some(abi) = abi_string(e_machine, ei_class) {
        candidates.push(format!("/system/etc/ld.config.{abi}.txt"));
    }

    // Android 11 added the generated configuration.
    if release >= AndroidRelease::R30 {
        candidates.push("/linkerconfig/ld.config.txt".to_string());
    }

    // Android 9 also added the VNDK ones.
    if props.vndk_lite {
        candidates.push("/system/etc/ld.config.vndk_lite.txt".to_string());
    } else {
        candidates.push(format!(
            "/system/etc/ld.config{}.txt",
            props.vndk_version_string('.')
        ));
    }

    candidates.push(default);
    candidates
}

// The configuration file for EXECUTABLE (a shared library when it has no
// INTERP), if the release has any.
pub fn get_ld_config_path<P: AsRef<Path>>(
    executable: &P,
    interp: Option<&str>,
    e_machine: Machine,
    ei_class: FileClass,
    props: &SystemProperties,
) -> Option<String> {
    let mut candidates = ld_config_candidates(
        executable.as_ref(),
        interp.is_none(),
        e_machine,
        ei_class,
        props,
    );
    let last = candidates.pop()?;
    Some(
        candidates
            .into_iter()
            .find(|path| Path::new(path).exists())
            .unwrap_or(last),
    )
}

// The target SDK version set by the '.version' file next to the binary, read
// the way the bionic Config::read_binary_config does: a missing file keeps
// the default version, while a file that can not be read or that does not
// hold a positive number (once trimmed) fails the whole configuration.
fn read_version_file<P: AsRef<Path>>(binary: &P) -> Result<Option<i64>, &'static str> {
    let Some(parent) = binary.as_ref().parent() else {
        return Ok(None);
    };
    let content = match std::fs::read(parent.join(".version")) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("error reading version file"),
    };
    match std::str::from_utf8(trim(&content))
        .ok()
        .and_then(|version| version.parse::<i64>().ok())
    {
        Some(version) if version > 0 => Ok(Some(version)),
        _ => Err("invalid version"),
    }
}

pub fn parse_ld_config_txt<P1: AsRef<Path>, P2: AsRef<Path>>(
    filename: &P2,
    binary: &P1,
    interp: Option<&str>,
    ei_class: FileClass,
    props: &SystemProperties,
) -> Result<LdCache, &'static str> {
    let is_asan = is_asan(interp);
    let is_hwasan = is_hwasan(interp);
    let release = props.release;

    if is_asan && release == AndroidRelease::R26 {
        return Err("asan not supported");
    }

    // The loader reads the file as bytes and only splits it on newlines, so
    // a byte that is not valid UTF-8 (on a comment, say) does not make the
    // whole file unreadable.
    let content = std::fs::read(filename).map_err(|_| "Could not open the filename")?;
    let lines: Vec<&[u8]> = content.split(|&c| c == b'\n').collect();

    let section = find_initial_section(binary, &lines, interp.is_none(), release)?;

    let start = find_section(&section, &lines)?;

    let mut properties = Properties::new();
    for line in &lines[start..] {
        match next_token(line) {
            Some(Token::PropertyAssign(name, value)) => {
                properties.add(lossy(name), lossy(value));
            }
            Some(Token::PropertyAppend(name, value)) => {
                properties.append(lossy(name), lossy(value));
            }
            Some(Token::Section(_)) => break,
            // The loader warns about an invalid line and ignores it, the
            // rest of the section still applies.
            Some(Token::Error) | None => continue,
        }
    }

    // The '.version' file is only read for the sections that opt in.  The
    // default is not the running release but the loader own __ANDROID_API__,
    // which the platform build defines as __ANDROID_API_FUTURE__.
    properties.target_sdk_version = ANDROID_API_FUTURE.to_string();
    if properties.get_bool("enable.target.sdk.version") {
        if let Some(version) = read_version_file(binary)? {
            properties.target_sdk_version = version.to_string();
        }
    }

    let mut ldcache = LdCache::new();

    ldcache.push_namespace(DEFAULT_NAME_CONFIG);

    for namespace in properties.get_strings("additional.namespaces") {
        ldcache.push_namespace(&namespace);
    }

    // The loop below borrow as immutable, so it can not check if the linked namespace
    // is within the ldcache.  To accomplish a different set with only ldcache
    // keys is used.
    let ns_configs_set = ldcache.config_set();

    for ns in ldcache.namespaces_config.values_mut() {
        let mut property_name_prefix = format!("namespace.{}", ns.name);
        for ns_linked in properties.get_strings(format!("{property_name_prefix}.links")) {
            if !ns_configs_set.contains(&ns_linked) {
                return Err("undefined namespace");
            }

            let allow_all = properties.get_bool(format!(
                "{property_name_prefix}.link.{ns_linked}.allow_all_shared_libs"
            ));

            let shared_libs = properties.get_string(format!(
                "{property_name_prefix}.link.{ns_linked}.shared_libs"
            ));

            if !allow_all && shared_libs.is_empty() {
                return Err("list of shared_libs is not specified or is empty.");
            }

            if allow_all && !shared_libs.is_empty() {
                return Err("both shared_libs and allow_all_shared_libs are set.");
            }

            ns.namespaces.push(NamespaceLink {
                namespace: ns_linked,
                shared_libs: shared_libs
                    .split(':')
                    .filter(|lib| !lib.is_empty())
                    .map(|lib| lib.to_string())
                    .collect(),
                allow_all_shared_libs: allow_all,
            });
        }

        ns.isolated = properties.get_bool(format!("{property_name_prefix}.isolated"));
        ns.visible = properties.get_bool(format!("{property_name_prefix}.visible"));

        // Android 12 added 'allowed_libs' as a synonym of 'whitelisted', and
        // the two lists are joined.  An empty entry is kept like the loader
        // does: it matches no name, but the list is still a restriction.
        if ns.name != DEFAULT_NAME_CONFIG {
            let mut allowed_libs =
                properties.get_string(format!("{property_name_prefix}.whitelisted"));
            let libs = properties.get_string(format!("{property_name_prefix}.allowed_libs"));
            if !allowed_libs.is_empty() && !libs.is_empty() {
                allowed_libs.push(':');
            }
            allowed_libs.push_str(&libs);
            if !allowed_libs.is_empty() {
                ns.allowed_libs = allowed_libs.split(':').map(|lib| lib.to_string()).collect();
            }
        }

        if is_asan {
            property_name_prefix.push_str(".asan");
        } else if is_hwasan {
            property_name_prefix.push_str(".hwasan");
        }

        ns.search_paths = search_path::SearchPathVec::new();
        for path in properties.get_paths(
            format!("{property_name_prefix}.search.paths"),
            ei_class,
            props,
        ) {
            if let Some(path) = resolve_path(&path) {
                ns.search_paths.add_path(&path);
            }
        }

        ns.permitted_paths = properties.get_paths(
            format!("{property_name_prefix}.permitted.paths"),
            ei_class,
            props,
        );
    }

    Ok(ldcache)
}

// The path prefix that identifies the partition a file belongs to. The first
// path component, along the APEX name for the /apex ones.
fn partition_prefix<P: AsRef<Path>>(path: &P) -> Option<std::path::PathBuf> {
    let mut parts = path.as_ref().iter();
    // Skip the root component.
    parts.next()?;
    let first = parts.next()?;
    let mut prefix = std::path::PathBuf::from(first);
    if first == "apex" {
        prefix.push(parts.next()?);
    }
    Some(prefix)
}

// Find the section that applies to the binary, from the 'dir.<section>' entries
// that precede the first one.  The 'fallback' flag enables the partition match
// described on find_section_fallback.
fn find_initial_section<P: AsRef<Path>>(
    binary: &P,
    lines: &[&[u8]],
    fallback: bool,
    release: AndroidRelease,
) -> Result<Vec<u8>, &'static str> {
    // The mappings, in file order, with the directory already resolved.
    let mut dirs: Vec<(Vec<u8>, std::path::PathBuf)> = Vec::new();

    for line in lines {
        match next_token(line) {
            Some(Token::PropertyAssign(name, value)) => {
                let Some(section) = name.strip_prefix(b"dir.") else {
                    continue;
                };

                // The bionic parse_config_file drops the trailing slashes and
                // ignores an empty directory.
                let mut value = value;
                while let Some(stripped) = value.strip_suffix(b"/") {
                    value = stripped;
                }
                if value.is_empty() {
                    continue;
                }

                // Android 10 resolves the directory, skipping one that does not
                // exist and taking it as written when it can not be resolved
                // otherwise.  The older releases always take it as written.
                let dir = std::path::PathBuf::from(OsStr::from_bytes(value));
                let resolved = if release >= AndroidRelease::R29 {
                    match std::fs::canonicalize(&dir) {
                        Ok(resolved) => resolved,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => dir,
                    }
                } else {
                    dir
                };

                if file_is_under_dir(
                    binary.as_ref().as_os_str().as_bytes(),
                    resolved.as_os_str().as_bytes(),
                ) {
                    return Ok(section.to_vec());
                }
                dirs.push((section.to_vec(), resolved));
            }
            Some(Token::Section(_)) => break,
            // Bionic loader ignore ill formatted lines.
            _ => continue,
        }
    }

    if fallback {
        if let Some(section) = find_section_fallback(binary, &dirs) {
            return Ok(section);
        }
    }

    Err("initial section for binary not found")
}

fn find_section_fallback<P: AsRef<Path>>(
    binary: &P,
    dirs: &[(Vec<u8>, std::path::PathBuf)],
) -> Option<Vec<u8>> {
    let partition = partition_prefix(binary)?;
    dirs.iter()
        .find(|(_, dir)| partition_prefix(dir).is_some_and(|prefix| prefix == partition))
        .map(|(section, _)| section.clone())
}

// Return the index of the line that follows the section header.
fn find_section(section: &[u8], lines: &[&[u8]]) -> Result<usize, &'static str> {
    for (index, line) in lines.iter().enumerate() {
        if matches!(next_token(line), Some(Token::Section(name)) if name == section) {
            return Ok(index + 1);
        }
    }
    Err("section for binary not found")
}

// The property names and values, which are only compared against ASCII names
// and used as paths or library names.
fn lossy(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

// The C locale isspace characters (the vertical tab included), which the
// android::base::Trim the loader uses strips.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&c| !is_space(c.into()))
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&c| !is_space(c.into()))
        .map_or(start, |end| end + 1);
    &s[start..end]
}

// Split a line the way the bionic ConfigParser::next_token does, returning
// None for an empty or a comment line.
fn next_token(line: &[u8]) -> Option<Token<'_>> {
    // A comment runs from the first '#' to the end of the line.
    let line = match line.iter().position(|&c| c == b'#') {
        Some(comment) => &line[..comment],
        None => line,
    };
    let line = trim(line);
    if line.is_empty() {
        return None;
    }

    if line[0] == b'[' && line[line.len() - 1] == b']' {
        return Some(Token::Section(&line[1..line.len() - 1]));
    }

    // A line with a '+=' is an append split at the first one, otherwise it
    // is an assignment split at the first '=', the value keeping any other
    // separator.
    if let Some(append) = line.windows(2).position(|w| w == b"+=") {
        return Some(Token::PropertyAppend(
            trim(&line[..append]),
            trim(&line[append + 2..]),
        ));
    }
    if let Some(assign) = line.iter().position(|&c| c == b'=') {
        return Some(Token::PropertyAssign(
            trim(&line[..assign]),
            trim(&line[assign + 1..]),
        ));
    }

    Some(Token::Error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;
    use object::elf::*;
    use std::fs;
    use std::fs::File;
    use std::io::{Error, Write};
    use std::iter::zip;

    // The properties of an Android 12 device without a VNDK.
    fn props() -> SystemProperties {
        SystemProperties {
            release: AndroidRelease(31),
            vndk_version: String::new(),
            vndk_lite: false,
        }
    }

    fn create_cfg(tmp_path: &str) -> String {
        format!(
            "# comment \n\
      dir.test = {base}\n\
      \n\
      [test]\n\
      \n\
      enable.target.sdk.version = true\n\
      additional.namespaces=system\n\
      additional.namespaces+=vndk\n\
      additional.namespaces+=vndk_in_system\n\
      namespace.default.isolated = true\n\
      namespace.default.search.paths = {base}/vendor/${{LIB}}\n\
      namespace.default.permitted.paths = {base}/vendor/${{LIB}}\n\
      namespace.default.asan.search.paths = {base}/data\n\
      namespace.default.asan.search.paths += {base}/vendor/${{LIB}}\n\
      namespace.default.asan.permitted.paths = {base}/data:{base}/vendor\n\
      namespace.default.hwasan.search.paths = {base}/vendor/${{LIB}}/hwasan\n\
      namespace.default.hwasan.search.paths += {base}/vendor/${{LIB}}\n\
      namespace.default.links = system\n\
      namespace.default.links += vndk\n\
      namespace.default.link.system.shared_libs=  libc.so\n\
      namespace.default.link.system.shared_libs +=   libm.so:libdl.so\n\
      namespace.default.link.system.shared_libs   +=libstdc++.so\n\
      namespace.default.link.vndk.shared_libs = libcutils.so:libbase.so\n\
      namespace.system.isolated = true\n\
      namespace.system.visible = true\n\
      namespace.system.search.paths = {base}/system/${{LIB}}\n\
      namespace.system.permitted.paths = {base}/system/${{LIB}}\n\
      namespace.system.asan.search.paths = {base}/data:{base}/system/${{LIB}}\n\
      namespace.system.asan.permitted.paths = {base}/data:{base}/system\n\
      namespace.system.hwasan.search.paths = {base}/system/${{LIB}}/hwasan\n\
      namespace.system.hwasan.search.paths += {base}/system/${{LIB}}\n\
      namespace.vndk.isolated = tr\n\
      namespace.vndk.isolated += ue\n\
      namespace.vndk.search.paths = {base}/system/${{LIB}}/vndk\n\
      namespace.vndk.asan.search.paths = {base}/data\n\
      namespace.vndk.asan.search.paths += {base}/system/${{LIB}}/vndk\n\
      namespace.vndk.links = default\n\
      namespace.vndk.link.default.allow_all_shared_libs = true\n\
      namespace.vndk.link.vndk_in_system.allow_all_shared_libs = true\n\
      namespace.vndk_in_system.isolated = true\n\
      namespace.vndk_in_system.visible = true\n\
      namespace.vndk_in_system.search.paths = {base}/system/${{LIB}}\n\
      namespace.vndk_in_system.permitted.paths = {base}/system/${{LIB}}\n\
      namespace.vndk_in_system.whitelisted = libz.so:libyuv.so:libtinyxml2.so\n\
      \n",
            base = tmp_path
        )
    }

    fn test_skeleton(interp: &str) -> Result<(), std::io::Error> {
        let is_asan = is_asan(Some(interp));
        let is_hwasan = is_hwasan(Some(interp));

        let tmpdir = TempDir::new()?;
        let cfgpath = tmpdir.path().join("ld.config.txt");

        let dirtest = tmpdir.path().join("tmp");
        fs::create_dir(&dirtest)?;

        let binpath = dirtest.join("binary");
        File::create(&binpath)?;

        let versiondir = dirtest.join(".version");
        let mut versionfile = File::create(&versiondir)?;
        write!(versionfile, "26")?;

        let vendor = dirtest.join("vendor");
        fs::create_dir(&vendor)?;

        let vendorlib = dirtest.join("vendor/lib");
        fs::create_dir(&vendorlib)?;

        let vendorlibhwasan = dirtest.join("vendor/lib/hwasan");
        fs::create_dir(&vendorlibhwasan)?;

        let data = dirtest.join("data");
        fs::create_dir(&data)?;

        let system = dirtest.join("system");
        fs::create_dir(&system)?;

        let systemlib = dirtest.join("system/lib");
        fs::create_dir(&systemlib)?;

        let systemlibhwasan = dirtest.join("system/lib/hwasan");
        fs::create_dir(&systemlibhwasan)?;

        let vndklib = dirtest.join("system/lib/vndk");
        fs::create_dir(&vndklib)?;

        let cfgcontent = create_cfg(&dirtest.to_string_lossy());

        let mut file = File::create(&cfgpath)?;
        file.write_all(cfgcontent.as_bytes())?;

        // Only the namespaces with a sanitizer specific property have one, the
        // others end up with an empty search path list.
        let expected_default_search_paths = if is_asan {
            vec![data.to_str().unwrap(), vendorlib.to_str().unwrap()]
        } else if is_hwasan {
            vec![
                vendorlibhwasan.to_str().unwrap(),
                vendorlib.to_str().unwrap(),
            ]
        } else {
            vec![vendorlib.to_str().unwrap()]
        };
        let expected_system_search_paths = if is_asan {
            vec![data.to_str().unwrap(), systemlib.to_str().unwrap()]
        } else if is_hwasan {
            vec![
                systemlibhwasan.to_str().unwrap(),
                systemlib.to_str().unwrap(),
            ]
        } else {
            vec![systemlib.to_str().unwrap()]
        };
        let expected_vndk_search_paths = if is_asan {
            vec![data.to_str().unwrap(), vndklib.to_str().unwrap()]
        } else if is_hwasan {
            vec![]
        } else {
            vec![vndklib.to_str().unwrap()]
        };
        let expected_vndk_in_system_search_paths = if is_asan || is_hwasan {
            vec![]
        } else {
            vec![systemlib.to_str().unwrap()]
        };

        match parse_ld_config_txt(&cfgpath, &binpath, Some(interp), ELFCLASS32, &props()) {
            Ok(ldcache) => {
                let default_ns = ldcache
                    .get_default_namespace()
                    .ok_or(Error::other("default namespace not found"))?;

                assert!(default_ns.isolated);
                assert!(!default_ns.visible);
                assert_eq!(
                    default_ns.search_paths.len(),
                    expected_default_search_paths.len()
                );
                for (d, e) in zip(&default_ns.search_paths, &expected_default_search_paths) {
                    assert_eq!(d, e);
                }

                assert_eq!(default_ns.namespaces.len(), 2);
                assert_eq!(default_ns.namespaces[0].namespace, "system");
                assert_eq!(default_ns.namespaces[1].namespace, "vndk");

                // A link only makes the libraries on its shared_libs list
                // accessible.
                for lib in ["libc.so", "libm.so", "libdl.so", "libstdc++.so"] {
                    assert!(default_ns.namespaces[0].is_accessible(lib));
                }
                assert!(!default_ns.namespaces[0].is_accessible("libcutils.so"));
                assert!(default_ns.namespaces[1].is_accessible("libcutils.so"));
                assert!(!default_ns.namespaces[1].is_accessible("libc.so"));

                assert_eq!(ldcache.namespaces_config.len(), 4);

                let system_ns = ldcache.namespaces_config.get("system").unwrap();
                assert_eq!(system_ns.name, "system");
                assert!(system_ns.isolated);
                assert!(system_ns.visible);
                assert_eq!(
                    system_ns.search_paths.len(),
                    expected_system_search_paths.len()
                );
                for (d, e) in zip(&system_ns.search_paths, &expected_system_search_paths) {
                    assert_eq!(d, e);
                }

                let vndk_ns = ldcache.namespaces_config.get("vndk").unwrap();
                assert_eq!(vndk_ns.name, "vndk");
                assert!(!vndk_ns.isolated);
                assert!(!vndk_ns.visible);
                assert_eq!(vndk_ns.search_paths.len(), expected_vndk_search_paths.len());
                for (d, e) in zip(&vndk_ns.search_paths, &expected_vndk_search_paths) {
                    assert_eq!(d, e);
                }
                assert_eq!(vndk_ns.namespaces.len(), 1);
                // The link allows every shared library.
                assert!(vndk_ns.namespaces[0].is_accessible("libanything.so"));

                let vndk_ns_system = ldcache.namespaces_config.get("vndk_in_system").unwrap();
                assert_eq!(vndk_ns_system.name, "vndk_in_system");
                assert!(vndk_ns_system.isolated);
                assert!(vndk_ns_system.visible);
                assert_eq!(
                    vndk_ns_system.search_paths.len(),
                    expected_vndk_in_system_search_paths.len()
                );
                for (d, e) in zip(
                    &vndk_ns_system.search_paths,
                    &expected_vndk_in_system_search_paths,
                ) {
                    assert_eq!(d, e);
                }
                assert_eq!(
                    vndk_ns_system.allowed_libs,
                    vec!["libz.so", "libyuv.so", "libtinyxml2.so"]
                );

                Ok(())
            }
            Err(e) => Err(Error::other(e)),
        }
    }

    #[test]
    fn smoke() -> Result<(), std::io::Error> {
        test_skeleton("linker")
    }

    #[test]
    fn smoke_asan() -> Result<(), std::io::Error> {
        test_skeleton("linker_asan")
    }

    #[test]
    fn smoke_hwasan() -> Result<(), std::io::Error> {
        test_skeleton("linker_hwasan64")
    }

    #[test]
    fn partition_prefixes() {
        let prefix = |path: &str| {
            partition_prefix(&Path::new(path)).map(|p| p.to_string_lossy().into_owned())
        };

        assert_eq!(prefix("/system/lib64/libfoo.so").as_deref(), Some("system"));
        assert_eq!(prefix("/system/bin/"), prefix("/system/lib64/libfoo.so"));
        assert_eq!(prefix("/vendor/bin"), prefix("/vendor/lib64/hw/libfoo.so"));
        assert_ne!(prefix("/odm/bin"), prefix("/vendor/lib64/libfoo.so"));

        // The APEX name is part of the prefix, so each one has its own.
        assert_eq!(
            prefix("/apex/com.android.art/lib64/libart.so").as_deref(),
            Some("apex/com.android.art")
        );
        assert_eq!(
            prefix("/apex/com.android.art/bin"),
            prefix("/apex/com.android.art/lib64/libart.so")
        );
        assert_ne!(
            prefix("/apex/com.android.i18n/bin"),
            prefix("/apex/com.android.art/lib64/libart.so")
        );

        assert_eq!(prefix("/"), None);
    }

    #[test]
    fn shared_library_section() -> Result<(), std::io::Error> {
        let tmpdir = TempDir::new()?;
        let cfgpath = tmpdir.path().join("ld.config.txt");

        let dirtest = tmpdir.path().join("tmp");
        fs::create_dir(&dirtest)?;
        fs::create_dir(dirtest.join("vendor"))?;
        let vendorlib = dirtest.join("vendor/lib");
        fs::create_dir(&vendorlib)?;

        let mut file = File::create(&cfgpath)?;
        file.write_all(create_cfg(&dirtest.to_string_lossy()).as_bytes())?;

        // Outside the mapped directory, but on the same partition.
        let libpath = tmpdir.path().join("libfoo.so");
        File::create(&libpath)?;

        assert!(
            parse_ld_config_txt(&cfgpath, &libpath, Some("linker"), ELFCLASS32, &props()).is_err()
        );

        let ldcache = parse_ld_config_txt(&cfgpath, &libpath, None, ELFCLASS32, &props())
            .map_err(Error::other)?;
        let default_ns = ldcache
            .get_default_namespace()
            .ok_or(Error::other("default namespace not found"))?;
        assert_eq!(default_ns.search_paths.len(), 1);
        assert_eq!(default_ns.search_paths[0], vendorlib.to_str().unwrap());

        Ok(())
    }

    // A temporary tree with the 'bin/binary' executable the configurations
    // are parsed for, along with the 'lib' and 'lib64' directories.  A
    // '{base}' on a configuration stands for the tree root.
    struct Fixture {
        _tmpdir: TempDir,
        base: String,
    }

    impl Fixture {
        fn new() -> Result<Fixture, Error> {
            let tmpdir = TempDir::new()?;
            // The binary is matched against the resolved 'dir.' directories.
            let base = fs::canonicalize(tmpdir.path())?
                .to_string_lossy()
                .into_owned();
            for dir in ["bin", "lib", "lib64"] {
                fs::create_dir(Path::new(&base).join(dir))?;
            }
            File::create(Path::new(&base).join("bin/binary"))?;
            Ok(Fixture {
                _tmpdir: tmpdir,
                base,
            })
        }

        fn path(&self, path: &str) -> String {
            format!("{}/{path}", self.base)
        }

        fn parse_with(
            &self,
            config: &[u8],
            interp: &str,
            props: &SystemProperties,
        ) -> Result<LdCache, &'static str> {
            let cfgpath = Path::new(&self.base).join("ld.config.txt");
            fs::write(&cfgpath, config).map_err(|_| "could not write the configuration")?;
            parse_ld_config_txt(
                &cfgpath,
                &self.path("bin/binary"),
                Some(interp),
                ELFCLASS64,
                props,
            )
        }

        fn parse_as(&self, config: &[u8], interp: &str) -> Result<LdCache, &'static str> {
            self.parse_with(config, interp, &props())
        }

        fn parse_bytes(&self, config: &[u8]) -> Result<LdCache, &'static str> {
            self.parse_as(config, "/system/bin/linker64")
        }

        fn parse(&self, config: &str) -> Result<LdCache, &'static str> {
            self.parse_bytes(config.replace("{base}", &self.base).as_bytes())
        }
    }

    fn search_paths(ldcache: &LdCache, namespace: &str) -> Vec<String> {
        ldcache
            .get_namespace(namespace)
            .map(|ns| ns.search_paths.iter().map(|p| p.path.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn tokens() {
        assert_eq!(next_token(b""), None);
        assert_eq!(next_token(b"  # name = [value]"), None);
        assert_eq!(
            next_token(b" [section] # comment"),
            Some(Token::Section(b"section"))
        );
        assert_eq!(
            next_token(b"[ section ]"),
            Some(Token::Section(b" section "))
        );
        assert_eq!(
            next_token(b"name = value # comment"),
            Some(Token::PropertyAssign(b"name", b"value"))
        );
        // The line is split at the first separator, the value keeping any
        // other.
        assert_eq!(
            next_token(b"name = a=b"),
            Some(Token::PropertyAssign(b"name", b"a=b"))
        );
        assert_eq!(
            next_token(b"name += a+=b=c"),
            Some(Token::PropertyAppend(b"name", b"a+=b=c"))
        );
        // A '+=' anywhere makes the line an append.
        assert_eq!(
            next_token(b"name = a += b"),
            Some(Token::PropertyAppend(b"name = a", b"b"))
        );
        // The C locale whitespace, the vertical tab and a CRLF ending
        // included.
        assert_eq!(
            next_token(b"\x0bname\t=\x0cvalue\r"),
            Some(Token::PropertyAssign(b"name", b"value"))
        );
        assert_eq!(next_token(b"not a property"), Some(Token::Error));
        assert_eq!(next_token(b"[section"), Some(Token::Error));
    }

    #[test]
    fn variables() {
        let params = [
            ("LIB", "lib64"),
            ("SDK_VER", "10000"),
            ("VNDK_VER", "-31"),
            ("VNDK_APEX_VER", "v31"),
        ];
        let format = |s| format_string(s, &params);

        assert_eq!(format("/system/${LIB}/x"), "/system/lib64/x");
        assert_eq!(format("/system/$LIB/x"), "/system/lib64/x");
        assert_eq!(
            format("/a${SDK_VER}/b$VNDK_VER/c${VNDK_APEX_VER}"),
            "/a10000/b-31/cv31"
        );
        // The name is a prefix match for the unbraced form only.
        assert_eq!(format("/$LIBFOO"), "/lib64FOO");
        assert_eq!(format("/${LIBFOO}"), "/${LIBFOO}");
        // Unknown variables, a lone '$', and an unterminated brace are kept.
        assert_eq!(format("$ORIGIN/${PLATFORM}"), "$ORIGIN/${PLATFORM}");
        assert_eq!(format("/a$/b$"), "/a$/b$");
        assert_eq!(format("/${LIB"), "/${LIB");
        assert_eq!(format("$$LIB"), "$lib64");
        // A replacement is not expanded again.
        assert_eq!(format_string("$A$B", &[("A", "$B"), ("B", "x")]), "$Bx");
    }

    #[test]
    fn unbraced_variables() -> Result<(), Error> {
        let fixture = Fixture::new()?;
        let ldcache = fixture
            .parse(
                "dir.test = {base}/bin\n\
                 [test]\n\
                 namespace.default.search.paths = {base}/$LIB\n",
            )
            .map_err(Error::other)?;
        assert_eq!(
            search_paths(&ldcache, "default"),
            vec![fixture.path("lib64")]
        );
        Ok(())
    }

    #[test]
    fn resolved_search_paths() -> Result<(), Error> {
        let fixture = Fixture::new()?;
        std::os::unix::fs::symlink(fixture.path("lib64"), fixture.path("link"))?;
        let ldcache = fixture
            .parse(
                "dir.test = {base}/bin\n\
                 [test]\n\
                 namespace.default.search.paths = {base}/link:{base}/bin/binary\n\
                 namespace.default.search.paths += {base}/missing::{base}/lib/../lib\n",
            )
            .map_err(Error::other)?;
        // The symlink and the '..' are resolved, while a file, a missing
        // directory and an empty entry are dropped.
        assert_eq!(
            search_paths(&ldcache, "default"),
            vec![fixture.path("lib64"), fixture.path("lib")]
        );
        Ok(())
    }

    #[test]
    fn namespace_accessibility() -> Result<(), Error> {
        let fixture = Fixture::new()?;
        std::os::unix::fs::symlink(fixture.path("lib64"), fixture.path("link"))?;
        let config = "dir.test = {base}/bin\n\
             [test]\n\
             additional.namespaces = other,open\n\
             namespace.default.isolated = true\n\
             namespace.default.search.paths = {base}/lib\n\
             namespace.default.permitted.paths = {base}/link/$LIB:{base}/missing\n\
             namespace.default.asan.permitted.paths = /data/asan{base}/${LIB}\n\
             namespace.default.allowed_libs = libfoo.so\n\
             namespace.other.isolated = true\n\
             namespace.other.search.paths = {base}/link\n\
             namespace.other.whitelisted = libfoo.so\n\
             namespace.other.allowed_libs = libbar.so\n\
             namespace.open.search.paths = {base}/lib\n"
            .replace("{base}", &fixture.base);
        let ldcache = fixture
            .parse_bytes(config.as_bytes())
            .map_err(Error::other)?;
        let no_paths = search_path::SearchPathVec::new();

        let default_ns = ldcache
            .get_default_namespace()
            .ok_or(Error::other("default namespace not found"))?;
        // The permitted paths are only substituted, not resolved.
        assert_eq!(
            default_ns.permitted_paths,
            vec![fixture.path("link/lib64"), fixture.path("missing")]
        );
        // The default namespace ignores its allowed_libs.
        assert!(default_ns.allowed_libs.is_empty());
        assert!(default_ns.is_accessible_path(&fixture.path("lib/libbaz.so"), &no_paths));
        // A file directly on a search path, or anywhere below a permitted path.
        assert!(!default_ns.is_accessible_path(&fixture.path("lib/sub/libbaz.so"), &no_paths));
        assert!(default_ns.is_accessible_path(&fixture.path("link/lib64/sub/libbaz.so"), &no_paths));
        assert!(!default_ns.is_accessible_path(&fixture.path("lib64/libbaz.so"), &no_paths));
        assert!(!default_ns.is_accessible_path(&fixture.path("libx/libbaz.so"), &no_paths));
        // Or directly on a LD_LIBRARY_PATH directory.
        let ld_library_paths = search_path::from_string(fixture.path("lib64"), &[':']);
        assert!(default_ns.is_accessible_path(&fixture.path("lib64/libbaz.so"), &ld_library_paths));

        // Both lists apply, against the resolved search path.
        let other_ns = ldcache
            .get_namespace("other")
            .ok_or(Error::other("other namespace not found"))?;
        assert_eq!(other_ns.allowed_libs, vec!["libfoo.so", "libbar.so"]);
        assert!(other_ns.is_accessible_path(&fixture.path("lib64/libfoo.so"), &no_paths));
        assert!(other_ns.is_accessible_path(&fixture.path("lib64/libbar.so"), &no_paths));
        assert!(!other_ns.is_accessible_path(&fixture.path("lib64/libbaz.so"), &no_paths));
        assert!(!other_ns.is_accessible_path(&fixture.path("link/libfoo.so"), &no_paths));

        // A namespace that is not isolated loads anything.
        let open_ns = ldcache
            .get_namespace("open")
            .ok_or(Error::other("open namespace not found"))?;
        assert!(open_ns.is_accessible_path("/anywhere/libbaz.so", &no_paths));

        // The sanitizer variants.
        let ldcache = fixture
            .parse_as(config.as_bytes(), "/system/bin/linker_asan64")
            .map_err(Error::other)?;
        let default_ns = ldcache
            .get_default_namespace()
            .ok_or(Error::other("default namespace not found"))?;
        assert_eq!(
            default_ns.permitted_paths,
            vec![format!("/data/asan{}/lib64", fixture.base)]
        );
        Ok(())
    }

    #[test]
    fn config_candidates() {
        let candidates = |path: &str, library: bool, release: u32| {
            let props = SystemProperties {
                release: AndroidRelease(release),
                ..props()
            };
            ld_config_candidates(Path::new(path), library, EM_X86_64, ELFCLASS64, &props)
        };
        let arch = "/system/etc/ld.config.x86_64.txt";
        let generated = "/linkerconfig/ld.config.txt";
        let default = "/system/etc/ld.config.txt";

        assert!(candidates("/system/bin/ls", false, 25).is_empty());
        assert_eq!(candidates("/system/bin/ls", false, 27), vec![default]);
        assert_eq!(
            candidates("/system/bin/ls", false, 28),
            vec![arch, default, default]
        );
        assert_eq!(
            candidates("/system/bin/ls", false, 30),
            vec![arch, generated, default, default]
        );

        // Android 10 only reads the configuration an APEX ships, for an
        // executable directly on its bin directory, the runtime APEX
        // included.
        let runtime = "/apex/com.android.runtime/etc/ld.config.txt";
        assert_eq!(
            candidates("/apex/com.android.runtime/bin/linker64", false, 29),
            vec![runtime, arch, default, default]
        );
        assert_eq!(
            candidates("/apex/com.android.runtime/bin/sub/tool", false, 29),
            vec![arch, default, default]
        );
        // Android 11 and 12 read the generated one first, anywhere below
        // the bin directory.
        let art = [
            "/linkerconfig/com.android.art/ld.config.txt",
            "/apex/com.android.art/etc/ld.config.txt",
        ];
        for release in [30, 32] {
            assert_eq!(
                candidates("/apex/com.android.art/bin/sub/dalvikvm64", false, release),
                vec![art[0], art[1], arch, generated, default, default]
            );
        }
        // Android 13 only reads the generated one.
        assert_eq!(
            candidates("/apex/com.android.art/bin/dalvikvm64", false, 33),
            vec![art[0], arch, generated, default, default]
        );
        // An executable elsewhere on the APEX gets the system configuration,
        // while a shared library gets the one of its APEX.
        assert_eq!(
            candidates("/apex/com.android.art/lib64/tool", false, 33),
            vec![arch, generated, default, default]
        );
        assert_eq!(
            candidates("/apex/com.android.art/lib64/libart.so", true, 33),
            vec![art[0], arch, generated, default, default]
        );
        assert_eq!(
            candidates("/apex/com.android.art/lib64/libart.so", true, 29),
            vec![art[1], arch, default, default]
        );

        // The VNDK ones.
        let vndk = |vndk_version: &str, vndk_lite: bool| {
            let props = SystemProperties {
                vndk_version: vndk_version.to_string(),
                vndk_lite,
                ..props()
            };
            ld_config_candidates(
                Path::new("/system/bin/ls"),
                false,
                EM_386,
                ELFCLASS32,
                &props,
            )
        };
        assert_eq!(
            vndk("31", false),
            vec![
                "/system/etc/ld.config.x86.txt",
                generated,
                "/system/etc/ld.config.31.txt",
                default
            ]
        );
        assert_eq!(vndk("current", false)[2], default);
        assert_eq!(vndk("31", true)[2], "/system/etc/ld.config.vndk_lite.txt");
    }

    #[test]
    fn section_directories() -> Result<(), Error> {
        let fixture = Fixture::new()?;
        std::os::unix::fs::symlink(fixture.path("bin"), fixture.path("link"))?;
        let section = |config: &str, release: u32| {
            let props = SystemProperties {
                release: AndroidRelease(release),
                ..props()
            };
            let config = format!(
                "{config}\n\
                 [first]\n\
                 namespace.default.search.paths = {{base}}/lib\n\
                 [second]\n\
                 namespace.default.search.paths = {{base}}/lib64\n"
            )
            .replace("{base}", &fixture.base);
            fixture
                .parse_with(config.as_bytes(), "/system/bin/linker64", &props)
                .map(|ldcache| search_paths(&ldcache, "default"))
        };
        let first = Ok(vec![fixture.path("lib")]);
        let second = Ok(vec![fixture.path("lib64")]);

        // The trailing slashes are dropped, and an empty directory ignored.
        assert_eq!(
            section("dir.first = /\ndir.second = {base}/bin//", 31),
            second
        );
        // Only a whole directory matches.
        assert_eq!(
            section("dir.first = {base}/bi\ndir.second = {base}", 31),
            second
        );
        // Android 10 resolves the directory, the older releases do not.
        assert_eq!(
            section("dir.first = {base}/link\ndir.second = {base}", 31),
            first
        );
        assert_eq!(
            section("dir.first = {base}/link\ndir.second = {base}", 28),
            second
        );
        assert!(section("dir.first = {base}/missing", 31).is_err());
        Ok(())
    }

    #[test]
    fn value_with_separator() -> Result<(), Error> {
        let fixture = Fixture::new()?;
        let ldcache = fixture
            .parse(
                "dir.test = {base}/bin\n\
                 [test]\n\
                 namespace.default.search.paths = {base}/lib\n\
                 namespace.default.unknown = a=b\n",
            )
            .map_err(Error::other)?;
        assert_eq!(search_paths(&ldcache, "default"), vec![fixture.path("lib")]);
        Ok(())
    }

    #[test]
    fn invalid_line() -> Result<(), Error> {
        let fixture = Fixture::new()?;
        let ldcache = fixture
            .parse(
                "dir.test = {base}/bin\n\
                 [test]\n\
                 additional.namespaces = other\n\
                 this line is not a property\n\
                 namespace.default.search.paths = {base}/lib\n\
                 namespace.other.search.paths = {base}/lib64\n\
                 [next]\n\
                 namespace.default.search.paths = {base}/lib64\n",
            )
            .map_err(Error::other)?;
        assert_eq!(search_paths(&ldcache, "default"), vec![fixture.path("lib")]);
        assert_eq!(search_paths(&ldcache, "other"), vec![fixture.path("lib64")]);
        Ok(())
    }

    #[test]
    fn namespace_lists() -> Result<(), Error> {
        let fixture = Fixture::new()?;
        let ldcache = fixture
            .parse(
                "dir.test = {base}/bin\n\
                 [test]\n\
                 additional.namespaces = first ,\tsecond\n\
                 namespace.default.links = first , second\n\
                 namespace.default.link.first.shared_libs = libfoo.so\n\
                 namespace.default.link.second.allow_all_shared_libs = true\n\
                 namespace.second.search.paths = {base}/lib\n",
            )
            .map_err(Error::other)?;
        let default_ns = ldcache
            .get_default_namespace()
            .ok_or(Error::other("default namespace not found"))?;
        let links: Vec<&str> = default_ns
            .namespaces
            .iter()
            .map(|link| link.namespace.as_str())
            .collect();
        assert_eq!(links, vec!["first", "second"]);
        assert_eq!(search_paths(&ldcache, "second"), vec![fixture.path("lib")]);

        // An empty entry names no namespace, which fails the configuration.
        assert!(fixture
            .parse(
                "dir.test = {base}/bin\n\
                 [test]\n\
                 namespace.default.links =\n"
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn version_file() -> Result<(), Error> {
        let fixture = Fixture::new()?;
        for dir in ["sdk26", "sdk31", "sdk10000"] {
            fs::create_dir(fixture.path(dir))?;
        }
        let config = "dir.test = {base}/bin\n\
                      [test]\n\
                      enable.target.sdk.version = true\n\
                      namespace.default.search.paths = {base}/sdk${SDK_VER}\n";
        let version = fixture.path("bin/.version");

        // Without the file, the loader own API level applies rather than the
        // device release (31), and so it does without the versioning.
        let ldcache = fixture.parse(config).map_err(Error::other)?;
        assert_eq!(
            search_paths(&ldcache, "default"),
            vec![fixture.path("sdk10000")]
        );
        fs::write(&version, "26\n")?;
        let ldcache = fixture
            .parse(&config.replace("enable.target.sdk.version = true", ""))
            .map_err(Error::other)?;
        assert_eq!(
            search_paths(&ldcache, "default"),
            vec![fixture.path("sdk10000")]
        );

        // The content is trimmed.
        fs::write(&version, "26\n")?;
        let ldcache = fixture.parse(config).map_err(Error::other)?;
        assert_eq!(
            search_paths(&ldcache, "default"),
            vec![fixture.path("sdk26")]
        );

        // Anything but a positive number fails the configuration.
        for invalid in ["", "abc", "0", "-26", "26 27"] {
            fs::write(&version, invalid)?;
            assert!(fixture.parse(config).is_err(), "{invalid:?}");
        }
        Ok(())
    }

    #[test]
    fn non_utf8_bytes() -> Result<(), Error> {
        let fixture = Fixture::new()?;
        let base = fixture.base.as_bytes();
        let config = [
            b"# caf\xe9\r\ndir.test = ".as_ref(),
            base,
            b"/bin # \xff\xfe\r\n[test]\r\nnamespace.default.search.paths = ",
            base,
            b"/lib\r\n",
        ]
        .concat();
        let ldcache = fixture.parse_bytes(&config).map_err(Error::other)?;
        assert_eq!(search_paths(&ldcache, "default"), vec![fixture.path("lib")]);
        Ok(())
    }
}
