use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use crate::elf::android::*;
use crate::search_path;

pub type NamespaceLinkingConfigVec = Vec<String>;

#[derive(Debug)]
pub struct NamespaceConfig {
    name: String,
    isolated: bool,
    visible: bool,
    allowed_libs: Vec<String>,
    pub search_paths: search_path::SearchPathVec,
    pub namespaces: NamespaceLinkingConfigVec,
}

impl NamespaceConfig {
    pub fn is_accessible<S: AsRef<str>>(&self, file: S) -> bool {
        if !self.isolated {
            return true;
        }

        if !self.allowed_libs.is_empty() && !self.allowed_libs.contains(&file.as_ref().to_string())
        {
            return false;
        }

        // The resolve_dependency_ld_cache will check the search_path and fail if it is not
        // found.
        true
    }
}

const DEFAULT_NAME_CONFIG: &str = "default";

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

    fn get<S: AsRef<str>>(&self, name: S) -> Option<&String> {
        self.properties.get(name.as_ref())
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

    fn get_paths<S: AsRef<str>>(
        &self,
        name: S,
        e_machine: u16,
        ei_class: u8,
    ) -> search_path::SearchPathVec {
        let mut path = self.get_string(name);

        let lib = libpath(e_machine, ei_class).unwrap();

        path = path.replace("${SDK_VER}", self.target_sdk_version.as_str());

        let vndk_version_str = get_vndk_version_str('-');

        path = path.replace("${VNDK_VER}", vndk_version_str.as_str());
        path = path.replace("${VNDK_APEX_VER}", vndk_version_str.as_str());

        path = path.replace("${LIB}", lib);

        search_path::from_string(path, &[':'])
    }
}

#[derive(Debug)]
enum Token {
    PropertyAssign,
    PropertyAppend,
    Section,
    Error,
}

fn get_vndk_version_str(delimiter: char) -> String {
    let vndk_str = get_vndk_version_string("");
    if vndk_str.is_empty() || vndk_str == "default" {
        return "".to_string();
    }
    format!("{delimiter}{vndk_str}")
}

pub fn get_ld_config_path<P: AsRef<Path>>(
    executable: &P,
    e_machine: u16,
    ei_class: u8,
) -> Option<String> {
    fn get_ld_config_vndk_path() -> String {
        if get_property_bool("ro.vndk.lite", false).unwrap() {
            return "/system/etc/ld.config.vndk_lite.txt".to_string();
        }

        format!("/system/etc/ld.config{}.txt", get_vndk_version_str('.'))
    }

    fn get_default_ld_config_path() -> Option<String> {
        Some("/system/etc/ld.config.txt".to_string())
    }

    fn get_vndk_ld_config_path(e_machine: u16, ei_class: u8, linkerconfig: bool) -> Option<String> {
        if let Some(abi) = abi_string(e_machine, ei_class) {
            let ld_config_arch = format!("/system/etc/ld.config.{abi}.txt");
            if Path::new(&ld_config_arch).exists() {
                return Some(ld_config_arch);
            }
        }

        if linkerconfig {
            let linkerconfig_path = "/linkerconfig/ld.config.txt".to_string();
            if Path::new(&linkerconfig_path).exists() {
                return Some(linkerconfig_path);
            }
        }

        let vndk_config = get_ld_config_vndk_path();
        if Path::new(&vndk_config).exists() {
            return Some(vndk_config);
        }

        get_default_ld_config_path()
    }

    fn get_apex_ld_config_path<P: AsRef<Path>>(
        executable: &P,
        linkerconfig: bool,
    ) -> Option<String> {
        let parts: Vec<&OsStr> = executable.as_ref().iter().collect();
        if parts.len() == 5 && parts[1] == "apex" && parts[3] == "bin" {
            let name = parts[2].to_string_lossy();
            if linkerconfig {
                let linkerconfig_path = format!("/linkerconfig/{name}/ld.config.txt)");
                if Path::new(&linkerconfig_path).exists() {
                    return Some(linkerconfig_path);
                }
            }
            let apex_config = format!("/apex/{name}/etc/ld.config.txt");
            if Path::new(&apex_config).exists() {
                return Some(apex_config);
            }
        }
        None
    }

    if let Ok(release) = get_release() {
        return match release {
            // Android 7.0/7.1 does not support ld.config.txt.
            AndroidRelease::AndroidR24 | AndroidRelease::AndroidR25 => None,

            // Android 8.0/8.1 has the ld.config.txt hardcoded.
            AndroidRelease::AndroidR26 | AndroidRelease::AndroidR27 => get_default_ld_config_path(),

            // Android 9 added support for abi and vndk specific path.
            AndroidRelease::AndroidR28 => get_vndk_ld_config_path(e_machine, ei_class, false),

            // Android 10 added support per binary ld.config.txt.
            AndroidRelease::AndroidR29 => {
                if let Some(cfg) = get_apex_ld_config_path(executable, false) {
                    return Some(cfg);
                }
                get_vndk_ld_config_path(e_machine, ei_class, false)
            }

            // Android 11 added the /linkerconfig folder support.
            AndroidRelease::AndroidR30
            | AndroidRelease::AndroidR31
            | AndroidRelease::AndroidR32
            | AndroidRelease::AndroidR33
            | AndroidRelease::AndroidR34 => {
                if let Some(cfg) = get_apex_ld_config_path(executable, true) {
                    return Some(cfg);
                }
                get_vndk_ld_config_path(e_machine, ei_class, true)
            }
        };
    }
    None
}

pub fn read_version_file<P: AsRef<Path>>(binary: &P) -> Result<i64, &'static str> {
    if let Some(parent) = binary.as_ref().parent() {
        if let Ok(version_str) = std::fs::read_to_string(parent.join(".version")) {
            if let Ok(value) = version_str.parse::<i64>() {
                return Ok(value);
            }
        }
    }
    Err("error reading version file")
}

pub fn parse_ld_config_txt<P1: AsRef<Path>, P2: AsRef<Path>, S: AsRef<str>>(
    filename: &P2,
    binary: &P1,
    interp: S,
    e_machine: u16,
    ei_class: u8,
) -> Result<LdCache, &'static str> {
    let is_asan = is_asan(interp);
    let release = get_release().map_err(|_| "invalid android release")?;

    if is_asan && matches!(release, AndroidRelease::AndroidR26) {
        return Err("asan not supported");
    }

    let mut lines = match read_lines(filename) {
        Ok(lines) => lines,
        Err(_e) => return Err("Could not open the filename"),
    };

    let section = find_initial_section(binary, &mut lines)?;

    find_section(&section, &mut lines)?;

    let mut properties = Properties::new();
    while let Some(Ok(line)) = lines.next() {
        let (token, line) = match next_token(&line) {
            Some(fields) => fields,
            None => continue,
        };
        match token {
            Token::PropertyAssign => {
                let (name, value) = parse_assignment(&line)?;
                properties.add(name, value);
            }
            Token::PropertyAppend => {
                let (name, value) = parse_append(&line)?;
                properties.append(name, value);
            }
            Token::Section | Token::Error => break,
        }
    }

    let target_sdk_version = if properties.get_bool("enable.target.sdk.version") {
        read_version_file(binary)?.to_string()
    } else {
        release.to_string()
    };
    properties.target_sdk_version = target_sdk_version;

    let mut ldcache = LdCache::new();

    ldcache.push_namespace(DEFAULT_NAME_CONFIG);

    if let Some(additional_namespaces) = properties.get("additional.namespaces") {
        for namespace in additional_namespaces.split(',') {
            ldcache.push_namespace(namespace);
        }
    }

    // The loop below borrow as immutable, so it can not check if the linked namespace
    // is within the ldcache.  To accomplish a different set with only ldcache
    // keys is used.
    let ns_configs_set = ldcache.config_set();

    for (_, ns) in ldcache.namespaces_config.iter_mut() {
        let mut property_name_prefix = format!("namespace.{}", ns.name);
        if let Some(linked_namespaces) = properties.get(&format!("{property_name_prefix}.links")) {
            for ns_linked in linked_namespaces.split(',') {
                if !ns_configs_set.contains(ns_linked) {
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

                ns.namespaces.push(ns_linked.to_string());
            }
        }

        ns.isolated = properties.get_bool(format!("{property_name_prefix}.isolated"));
        ns.visible = properties.get_bool(format!("{property_name_prefix}.visible"));

        // Android r31 added 'allowed_libs' as synonym for 'whitelisted'.
        let mut allowed_libs: Vec<String> = properties
            .get_string(format!("{property_name_prefix}.whitelisted"))
            .split(':')
            .map(|s| s.to_string())
            .filter(|x| !x.is_empty())
            .collect();
        allowed_libs.append(
            &mut properties
                .get_string(format!("{property_name_prefix}.allowed_libs"))
                .split(':')
                .map(|s| s.to_string())
                .filter(|x| !x.is_empty())
                .collect(),
        );
        ns.allowed_libs = allowed_libs;

        if is_asan {
            property_name_prefix.push_str(".asan");
        }

        ns.search_paths = properties.get_paths(
            format!("{property_name_prefix}.search.paths"),
            e_machine,
            ei_class,
        );

        // Skip the permitted.paths, since it is not required for program loading.
    }

    Ok(ldcache)
}

fn find_initial_section<P: AsRef<Path>>(
    binary: &P,
    lines: &mut io::Lines<io::BufReader<File>>,
) -> Result<String, &'static str> {
    while let Some(Ok(line)) = lines.next() {
        let (token, line) = match next_token(&line) {
            Some(fields) => fields,
            None => continue,
        };
        // Bionic loader ignore ill formatted lines.
        match token {
            Token::PropertyAssign => {
                let (name, value) = parse_assignment(&line)?;
                if !name.starts_with("dir.") {
                    continue;
                }

                if let Ok(resolved) = std::fs::canonicalize(value) {
                    if binary.as_ref().starts_with(resolved) {
                        return Ok(name[4..].to_string());
                    }
                }
            }
            Token::Section => break,
            Token::PropertyAppend | Token::Error => continue,
        }
    }
    Err("initial section for binary not found")
}

fn find_section(
    section: &String,
    lines: &mut io::Lines<io::BufReader<File>>,
) -> Result<(), &'static str> {
    while let Some(Ok(line)) = lines.next() {
        let (token, line) = match next_token(&line) {
            Some(line) => line,
            None => continue,
        };
        match token {
            Token::PropertyAssign | Token::PropertyAppend => continue,
            Token::Section => {
                if section == &line {
                    return Ok(());
                }
            }
            _ => break,
        }
    }
    Err("section for binary not found")
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn next_token(line: &str) -> Option<(Token, String)> {
    // Remove leading whitespace.
    let line = line.trim_start();
    // Remove trailing comments.
    let comment = match line.find('#') {
        Some(comment) => comment,
        None => line.len(),
    };
    let line = &line[0..comment];
    // Remove trailing whitespaces.
    let line = line.trim_end();
    // Skip empty lines.
    if line.is_empty() {
        return None;
    }

    if line.starts_with('[') && line.ends_with(']') {
        return Some((Token::Section, line[1..line.len() - 1].to_string()));
    } else if line.contains("+=") {
        return Some((Token::PropertyAppend, line.to_string()));
    } else if line.contains('=') {
        return Some((Token::PropertyAssign, line.to_string()));
    }

    Some((Token::Error, line.to_string()))
}

fn parse_assignment(line: &str) -> Result<(&str, &str), &'static str> {
    let vec: Vec<&str> = line.split('=').collect();
    if vec.len() != 2 {
        return Err("invalid assigment line");
    }
    Ok((vec[0].trim(), vec[1].trim()))
}

fn parse_append(line: &str) -> Result<(&str, &str), &'static str> {
    let vec: Vec<&str> = line.split("+=").collect();
    if vec.len() != 2 {
        return Err("invalid append line");
    }
    Ok((vec[0].trim(), vec[1].trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::elf::*;
    use std::fs;
    use std::fs::File;
    use std::io::{Error, ErrorKind, Write};
    use std::iter::zip;
    use tempfile::TempDir;

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

    fn test_skeleton(is_asan: bool) -> Result<(), std::io::Error> {
        let interp = match &is_asan {
            true => "linker_asan",
            false => "linker",
        };

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

        let data = dirtest.join("data");
        fs::create_dir(&data)?;

        let system = dirtest.join("system");
        fs::create_dir(&system)?;

        let systemlib = dirtest.join("system/lib");
        fs::create_dir(&systemlib)?;

        let vndklib = dirtest.join("system/lib/vndk");
        fs::create_dir(&vndklib)?;

        let cfgcontent = create_cfg(&dirtest.to_string_lossy());

        let mut file = File::create(&cfgpath)?;
        file.write_all(cfgcontent.as_bytes())?;

        let expected_default_search_paths = match &is_asan {
            true => vec![data.to_str().unwrap(), vendorlib.to_str().unwrap()],
            false => vec![vendorlib.to_str().unwrap()],
        };
        let expected_system_search_paths = match &is_asan {
            true => vec![data.to_str().unwrap(), systemlib.to_str().unwrap()],
            false => vec![systemlib.to_str().unwrap()],
        };
        let expected_vndk_search_paths = match &is_asan {
            true => vec![data.to_str().unwrap(), vndklib.to_str().unwrap()],
            false => vec![vndklib.to_str().unwrap()],
        };
        let expected_vndk_in_system_search_paths = match &is_asan {
            true => vec![],
            false => vec![systemlib.to_str().unwrap()],
        };

        match parse_ld_config_txt(&cfgpath, &binpath, interp, EM_386, ELFCLASS32) {
            Ok(ldcache) => {
                let default_ns = ldcache
                    .get_default_namespace()
                    .ok_or(Error::new(ErrorKind::Other, "default namespace not found"))?;

                assert_eq!(default_ns.isolated, true);
                assert_eq!(default_ns.visible, false);
                assert_eq!(
                    default_ns.search_paths.len(),
                    expected_default_search_paths.len()
                );
                for (d, e) in zip(&default_ns.search_paths, &expected_default_search_paths) {
                    assert_eq!(d, e);
                }

                assert_eq!(default_ns.namespaces.len(), 2);
                assert_eq!(default_ns.namespaces[0], "system");
                assert_eq!(default_ns.namespaces[1], "vndk");

                assert_eq!(ldcache.namespaces_config.len(), 4);

                let system_ns = ldcache.namespaces_config.get("system").unwrap();
                assert_eq!(system_ns.name, "system");
                assert_eq!(system_ns.isolated, true);
                assert_eq!(system_ns.visible, true);
                assert_eq!(
                    system_ns.search_paths.len(),
                    expected_system_search_paths.len()
                );
                for (d, e) in zip(&system_ns.search_paths, &expected_system_search_paths) {
                    assert_eq!(d, e);
                }

                let vndk_ns = ldcache.namespaces_config.get("vndk").unwrap();
                assert_eq!(vndk_ns.name, "vndk");
                assert_eq!(vndk_ns.isolated, false);
                assert_eq!(vndk_ns.visible, false);
                assert_eq!(vndk_ns.search_paths.len(), expected_vndk_search_paths.len());
                for (d, e) in zip(&vndk_ns.search_paths, &expected_vndk_search_paths) {
                    assert_eq!(d, e);
                }
                assert_eq!(vndk_ns.namespaces.len(), 1);

                let vndk_ns_system = ldcache.namespaces_config.get("vndk_in_system").unwrap();
                assert_eq!(vndk_ns_system.name, "vndk_in_system");
                assert_eq!(vndk_ns_system.isolated, true);
                assert_eq!(vndk_ns_system.visible, true);
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
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn smoke() -> Result<(), std::io::Error> {
        test_skeleton(false)
    }

    #[test]
    fn smoke_asan() -> Result<(), std::io::Error> {
        test_skeleton(true)
    }
}
