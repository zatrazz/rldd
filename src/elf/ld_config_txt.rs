use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use crate::elf::android::*;
use crate::pathutils;
use crate::search_path;

#[derive(Debug)]
pub struct NamespaceLinkingConfig {
    name: String,
    shared_libs: String,
    allow_all: bool,
}
pub type NamespaceLinkingConfigVec = Vec<NamespaceLinkingConfig>;

#[derive(Debug)]
pub struct NamespaceConfig {
    name: String,
    isolated: bool,
    visible: bool,
    search_paths: search_path::SearchPathVec,
    permitted: search_path::SearchPathVec,
    allowed_libs: Vec<String>,
    namespaces: NamespaceLinkingConfigVec,
}

pub trait NamespaceConfigTrait {
    fn push_namespace(&mut self, name: &str) -> &Self;
}

const DEFAULT_NAME_CONFIG: &str = "default";

pub trait LdCacheTraits {
    fn get_default_namespace(&self) -> Option<&NamespaceConfig>;
}

pub type LdCache = HashMap<String, NamespaceConfig>;

impl LdCacheTraits for LdCache {
    fn get_default_namespace(&self) -> Option<&NamespaceConfig> {
        self.get(DEFAULT_NAME_CONFIG)
    }
}

impl NamespaceConfigTrait for LdCache {
    fn push_namespace(&mut self, name: &str) -> &Self {
        self.insert(
            name.to_string(),
            NamespaceConfig {
                name: name.to_string(),
                isolated: false,
                visible: false,
                search_paths: search_path::SearchPathVec::new(),
                permitted: search_path::SearchPathVec::new(),
                allowed_libs: Vec::<String>::new(),
                namespaces: NamespaceLinkingConfigVec::new(),
            },
        );
        self
    }
}

pub trait Properties {
    fn get_bool<S: AsRef<str>>(&self, name: S) -> bool;
    fn get_string<S: AsRef<str>>(&self, name: S) -> String;
    fn get_paths<S: AsRef<str>>(
        &self,
        name: S,
        e_machine: u16,
        ei_class: u8,
    ) -> search_path::SearchPathVec;
}

impl Properties for HashMap<String, String> {
    fn get_bool<S: AsRef<str>>(&self, name: S) -> bool {
        self.get(name.as_ref())
            .and_then(|s| Some(s == "true"))
            .unwrap_or(false)
    }

    fn get_string<S: AsRef<str>>(&self, name: S) -> String {
        self.get(name.as_ref())
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

        // TODO Add SDK_VER support
        // TODO Add VNDK_VER support
        // TODO Add VNDK_APEX_VER support (the expansion depends on release version)

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

pub fn get_ld_config_path<P: AsRef<Path>>(
    executable: &P,
    e_machine: u16,
    ei_class: u8,
) -> Option<String> {
    fn get_ld_config_vndk_path() -> String {
        if get_property_bool("ro.vndk.lite", false).unwrap() {
            return "/system/etc/ld.config.vndk_lite.txt".to_string();
        }

        format!("/system/etc/ld.config.{}.txt", get_vndk_version_string(""))
    }

    fn get_default_ld_config_path() -> Option<String> {
        Some("/system/etc/ld.config.txt".to_string())
    }

    fn get_vndk_ld_config_path(e_machine: u16, ei_class: u8, linkerconfig: bool) -> Option<String> {
        if let Some(abi) = abi_string(e_machine, ei_class) {
            let ld_config_arch = format!("/system/etc/ld.config.{}.txt", abi);
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
                let linkerconfig_path = format!("/linkerconfig/{}/ld.config.txt)", name);
                if Path::new(&linkerconfig_path).exists() {
                    return Some(linkerconfig_path);
                }
            }
            let apex_config = format!("/apex/{}/etc/ld.config.txt", name);
            if Path::new(&apex_config).exists() {
                return Some(apex_config);
            }
        }
        None
    }

    if let Ok(release) = get_release() {
        return match release {
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

pub fn parse_ld_config_txt<P1: AsRef<Path>, P2: AsRef<Path>, S: AsRef<str>>(
    filename: &P2,
    binary: &P1,
    interp: S,
    e_machine: u16,
    ei_class: u8,
) -> Result<LdCache, &'static str> {
    let mut lines = match read_lines(filename) {
        Ok(lines) => lines,
        Err(_e) => return Err("Could not open the filename"),
    };

    let section = find_initial_section(binary, &mut lines)?;

    find_section(&section, &mut lines)?;

    let mut properties = HashMap::<String, String>::new();
    while let Some(Ok(line)) = lines.next() {
        let (token, line) = match next_token(&line) {
            Some(fields) => fields,
            None => continue,
        };
        match token {
            Token::PropertyAssign => {
                let (name, value) = parse_assignment(&line)?;
                properties.insert(name.to_string(), value.to_string());
            }
            Token::PropertyAppend => {
                let (name, value) = parse_append(&line)?;
                if let Some(vec) = properties.get_mut(name) {
                    let sep = if name.ends_with(".links") || name.ends_with(".namespaces") {
                        ','
                    } else if name.ends_with(".paths")
                        || name.ends_with(".shared_libs")
                        || name.ends_with(".whitelisted")
                        || name.ends_with(".allowed_libs")
                    {
                        ':'
                    } else {
                        continue;
                    };
                    vec.push_str(&format!("{}{}", sep, value).to_string());
                } else {
                    properties.insert(name.to_string(), value.to_string());
                }
            }
            Token::Section | Token::Error => break,
        }
    }

    let mut ns_configs = LdCache::new();

    ns_configs.push_namespace(DEFAULT_NAME_CONFIG);

    if let Some(additional_namespaces) = properties.get("additional.namespaces") {
        for namespace in additional_namespaces.split(',') {
            ns_configs.push_namespace(namespace);
        }
    }

    // TODO: handle sdk version
    if properties.get_bool("enable.target.sdk.version") {}

    // The loop below borrow as immutable, so it can not check if the linked namespace
    // is within the ns_configs.  To accomplish a different set with only ns_config
    // keys is used.
    let ns_configs_set: HashSet<String> = ns_configs.keys().cloned().collect();

    let is_asan = is_asan(interp);

    for (_, ns) in ns_configs.iter_mut() {
        let mut property_name_prefix = format!("namespace.{}", ns.name);
        if let Some(linked_namespaces) = properties.get(&format!("{}.links", property_name_prefix))
        {
            for ns_linked in linked_namespaces.split(',') {
                if !ns_configs_set.contains(ns_linked) {
                    return Err("undefined namespace");
                }

                let allow_all = properties.get_bool(format!(
                    "{}.link.{}.allow_all_shared_libs",
                    property_name_prefix, ns_linked
                ));

                let shared_libs = properties.get_string(format!(
                    "{}.link.{}.shared_libs",
                    property_name_prefix, ns_linked
                ));

                if !allow_all && shared_libs.is_empty() {
                    return Err("list of shared_libs is not specified or is empty.");
                }

                if allow_all && !shared_libs.is_empty() {
                    return Err("both shared_libs and allow_all_shared_libs are set.");
                }

                ns.namespaces.push(NamespaceLinkingConfig {
                    name: ns_linked.to_string(),
                    shared_libs: shared_libs,
                    allow_all: allow_all,
                });
            }
        }

        ns.isolated = properties.get_bool(format!("{}.isolated", property_name_prefix));
        ns.visible = properties.get_bool(format!("{}.visible", property_name_prefix));

        // Android r31 added 'allowed_libs' as synonym for 'whitelisted'.
        let mut allowed_libs: Vec<String> = properties
            .get_string(format!("{}.whitelisted", property_name_prefix))
            .split(':')
            .map(|s| s.to_string())
            .filter(|x| !x.is_empty())
            .collect();
        allowed_libs.append(
            &mut properties
                .get_string(format!("{}.allowed_libs", property_name_prefix))
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
            format!("{}.search.paths", property_name_prefix),
            e_machine,
            ei_class,
        );

        ns.permitted = properties.get_paths(
            format!("{}.permitted.paths", property_name_prefix),
            e_machine,
            ei_class,
        );
    }

    Ok(ns_configs)
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
                    if pathutils::file_is_under_dir(binary, &resolved) {
                        //  Skip the "dir."
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

fn next_token(line: &String) -> Option<(Token, String)> {
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
    } else if line.contains("=") {
        return Some((Token::PropertyAssign, line.to_string()));
    }

    Some((Token::Error, line.to_string()))
}

fn parse_assignment(line: &String) -> Result<(&str, &str), &'static str> {
    let vec: Vec<&str> = line.split("=").collect();
    if vec.len() != 2 {
        return Err("invalid assigment line");
    }
    Ok((vec[0].trim(), vec[1].trim()))
}

fn parse_append(line: &String) -> Result<(&str, &str), &'static str> {
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
        let expected_default_permitted_paths = match &is_asan {
            true => vec![data.to_str().unwrap(), vendor.to_str().unwrap()],
            false => vec![vendorlib.to_str().unwrap()],
        };
        let expected_system_search_paths = match &is_asan {
            true => vec![data.to_str().unwrap(), systemlib.to_str().unwrap()],
            false => vec![systemlib.to_str().unwrap()],
        };
        let expected_system_permitted_paths = match &is_asan {
            true => vec![data.to_str().unwrap(), system.to_str().unwrap()],
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
        let expected_vndk_in_system_permitted_paths = match &is_asan {
            true => vec![],
            false => vec![system.to_str().unwrap()],
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
                assert_eq!(
                    default_ns.permitted.len(),
                    expected_default_permitted_paths.len()
                );
                for (d, e) in zip(&default_ns.permitted, &expected_default_permitted_paths) {
                    assert_eq!(d, e);
                }

                assert_eq!(default_ns.namespaces.len(), 2);
                assert_eq!(default_ns.namespaces[0].name, "system");
                assert_eq!(
                    default_ns.namespaces[0].shared_libs,
                    "libc.so:libm.so:libdl.so:libstdc++.so"
                );
                assert_eq!(default_ns.namespaces[0].allow_all, false);
                assert_eq!(default_ns.namespaces[1].name, "vndk");
                assert_eq!(
                    default_ns.namespaces[1].shared_libs,
                    "libcutils.so:libbase.so"
                );
                assert_eq!(default_ns.namespaces[1].allow_all, false);

                assert_eq!(ldcache.len(), 4);

                let system_ns = ldcache.get("system").unwrap();
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
                assert_eq!(
                    system_ns.permitted.len(),
                    expected_system_permitted_paths.len()
                );
                for (d, e) in zip(&system_ns.permitted, &expected_system_permitted_paths) {
                    assert_eq!(d, e);
                }

                let vndk_ns = ldcache.get("vndk").unwrap();
                assert_eq!(vndk_ns.name, "vndk");
                assert_eq!(vndk_ns.isolated, false);
                assert_eq!(vndk_ns.visible, false);
                assert_eq!(vndk_ns.search_paths.len(), expected_vndk_search_paths.len());
                for (d, e) in zip(&vndk_ns.search_paths, &expected_vndk_search_paths) {
                    assert_eq!(d, e);
                }
                assert_eq!(vndk_ns.permitted.len(), 0);
                assert_eq!(vndk_ns.namespaces.len(), 1);
                assert_eq!(vndk_ns.namespaces[0].name, "default");
                assert_eq!(vndk_ns.namespaces[0].allow_all, true);

                let vndk_ns_system = ldcache.get("vndk_in_system").unwrap();
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
                    vndk_ns_system.permitted.len(),
                    expected_vndk_in_system_permitted_paths.len()
                );
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
