use object::elf::*;
#[cfg(target_os = "android")]
use std::ffi::CString;
use std::fmt;
#[cfg(target_os = "android")]
use std::io::Error;

use crate::elf::ld_config_txt::{LdCache, NamespaceLink};
use crate::pathutils;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AndroidRelease(pub u32);

impl AndroidRelease {
    // Android 7.0, which added DT_RUNPATH.
    pub const R24: AndroidRelease = AndroidRelease(24);
    // Android 8.0, which added the ld.config.txt file on a hardcoded path.
    pub const R26: AndroidRelease = AndroidRelease(26);
    // Android 9, which added the abi and vndk specific configuration paths
    // along with the /odm partition.
    pub const R28: AndroidRelease = AndroidRelease(28);
    // Android 10, which added the per APEX configuration, and $LIB on
    // DT_RUNPATH.
    pub const R29: AndroidRelease = AndroidRelease(29);
    // Android 11, which added the generated /linkerconfig files.
    pub const R30: AndroidRelease = AndroidRelease(30);
    // Android 13, which dropped the configuration shipped on the APEX.
    pub const R33: AndroidRelease = AndroidRelease(33);
}

impl fmt::Display for AndroidRelease {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.0)
    }
}

// The system properties the loader configuration depends on.  They are read
// from the device, except on the host tests that set them directly.
#[derive(Clone, Debug)]
pub struct SystemProperties {
    // ro.build.version.sdk
    pub release: AndroidRelease,
    // ro.vndk.version, empty when unset.
    pub vndk_version: String,
    // ro.vndk.lite
    pub vndk_lite: bool,
}

impl SystemProperties {
    #[cfg(target_os = "android")]
    pub fn get() -> Result<SystemProperties, std::io::Error> {
        Ok(SystemProperties {
            release: get_release()?,
            vndk_version: get_property("ro.vndk.version", "").unwrap_or_default(),
            vndk_lite: get_property_bool("ro.vndk.lite", false).unwrap_or(false),
        })
    }

    // The properties of the device, read once.
    #[cfg(target_os = "android")]
    pub fn current() -> Option<&'static SystemProperties> {
        static PROPS: std::sync::OnceLock<Option<SystemProperties>> = std::sync::OnceLock::new();
        PROPS.get_or_init(|| SystemProperties::get().ok()).as_ref()
    }

    // The bionic Config::get_vndk_version_string: the VNDK version preceded
    // by DELIMITER, or nothing when it is unset or 'current'.
    pub fn vndk_version_string(&self, delimiter: char) -> String {
        if self.vndk_version.is_empty() || self.vndk_version == "current" {
            return String::new();
        }
        format!("{delimiter}{}", self.vndk_version)
    }
}

#[cfg(target_os = "android")]
const PROP_VALUE_MAX: usize = 92;

#[cfg(target_os = "android")]
pub fn get_property<S1: AsRef<str>, S2: AsRef<str>>(
    property: S1,
    default: S2,
) -> Result<String, std::io::Error> {
    let name = CString::new(property.as_ref())?;

    let mut val: Vec<libc::c_uchar> = vec![0; PROP_VALUE_MAX];
    let ret = unsafe {
        libc::__system_property_get(name.as_ptr(), val.as_mut_ptr() as *mut libc::c_char)
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // The returned value is the length of the property value, zero meaning an
    // unset or empty property.
    match ret as usize {
        0 => Ok(default.as_ref().to_string()),
        l => std::str::from_utf8(&val[..l.min(PROP_VALUE_MAX)])
            .map_err(|_e| Error::other("Invalid UTF8 sequence"))
            .map(|s| s.trim_matches(char::from(0)).to_string()),
    }
}

#[cfg(target_os = "android")]
pub fn get_release_str() -> Result<String, std::io::Error> {
    get_property("ro.build.version.sdk", "")
}

#[cfg(target_os = "android")]
pub fn get_release() -> Result<AndroidRelease, std::io::Error> {
    get_release_str()?
        .trim()
        .parse::<u32>()
        .map(AndroidRelease)
        .map_err(|_| Error::other("Could not read the Android release"))
}

#[cfg(target_os = "android")]
pub fn get_property_bool<S: AsRef<str>>(
    property: S,
    default: bool,
) -> Result<bool, std::io::Error> {
    match get_property(property, "")?.as_str() {
        "1" | "y" | "yes" | "on" | "true" => Ok(true),
        "0" | "n" | "no" | "off" | "false" => Ok(false),
        _ => Ok(default),
    }
}

// The sanitizer in use is derived from the loader name, the way bionic builds
// a separate linker for each one.  A shared library has no PT_INTERP segment.
fn interp_name(interp: Option<&str>) -> String {
    match interp {
        Some(interp) => pathutils::get_name(&std::path::Path::new(interp)),
        None => String::new(),
    }
}

pub fn is_asan(interp: Option<&str>) -> bool {
    matches!(
        interp_name(interp).as_str(),
        "linker_asan" | "linker_asan64"
    )
}

pub fn is_hwasan(interp: Option<&str>) -> bool {
    matches!(
        interp_name(interp).as_str(),
        "linker_hwasan" | "linker_hwasan64"
    )
}

// The ${LIB} substitution and the system directories suffix, which the bionic
// loader hardwires as 'lib64' for the LP64 ABIs and 'lib' for the ILP32 ones.
pub fn libpath(ei_class: FileClass) -> &'static str {
    match ei_class {
        ELFCLASS64 => "lib64",
        _ => "lib",
    }
}

// The bionic ABI_STRING, used on the architecture specific configuration file
// name.
pub fn abi_string(e_machine: Machine, ei_class: FileClass) -> Option<&'static str> {
    match e_machine {
        EM_AARCH64 => Some("arm64"),
        EM_ARM => Some("arm"),
        EM_X86_64 => Some("x86_64"),
        EM_386 => Some("x86"),
        EM_RISCV => match ei_class {
            ELFCLASS64 => Some("riscv64"),
            _ => None,
        },
        _ => None,
    }
}

// The LD_PRELOAD entries, which the linker splits on spaces and colons
// (parse_LD_PRELOAD).
pub fn preload_list(list: &str) -> Vec<String> {
    list.split([' ', ':'])
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

// The LD_LIBRARY_PATH directories, which the linker resolves to their real
// path without expanding any token, dropping the ones that are not a
// directory (parse_LD_LIBRARY_PATH).
pub fn library_path_list(list: &str) -> Vec<String> {
    list.split(':')
        .filter_map(crate::elf::ld_config_txt::resolve_path)
        .collect()
}

// The DT_RUNPATH directories of an object whose real path is in the ORIGIN
// directory (None when it is not valid UTF-8), for an object of the EI_CLASS
// class on the RELEASE (None for the latest one).  The linker expands $ORIGIN
// and, from Android 10, $LIB (the library directory of its ABI) on each
// entry, and resolves it to its real path, dropping the ones that are not a
// directory (soinfo::set_dt_runpath).  It has no DT_RUNPATH before Android 7.
// An entry is kept as an error when $ORIGIN has no value.
pub fn runpath_list(
    list: &str,
    origin: Option<&str>,
    ei_class: FileClass,
    release: Option<AndroidRelease>,
) -> Vec<Result<String, String>> {
    use crate::elf::ld_config_txt::{format_string, resolve_path};

    if release.is_some_and(|release| release < AndroidRelease::R24) {
        return Vec::new();
    }
    let mut params = vec![("ORIGIN", origin.unwrap_or_default())];
    if release.is_none_or(|release| release >= AndroidRelease::R29) {
        params.push(("LIB", libpath(ei_class)));
    }
    list.split(':')
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| {
            if origin.is_none() && entry.contains("ORIGIN") {
                return Some(Err(entry.to_string()));
            }
            resolve_path(&format_string(entry, &params)).map(Ok)
        })
        .collect()
}

// The bionic fix_dt_needed: a 32-bit linker takes the file name of a
// DT_NEEDED entry NAME with a path when the TARGET_SDK_VERSION of the binary
// is below 23 (a workaround for old applications, b/21364029).  For an
// executable, only a '.version' file its configuration section opts in sets
// it that low; without a configuration it is the linker own API level.
pub fn fix_dt_needed(
    name: &str,
    ei_class: FileClass,
    target_sdk_version: Option<i64>,
) -> std::borrow::Cow<'_, str> {
    if ei_class == ELFCLASS32
        && target_sdk_version.is_some_and(|version| version < 23)
        && name.contains('/')
    {
        return pathutils::get_name(&std::path::Path::new(name)).into();
    }
    name.into()
}

// The namespace an ld.config.txt link names, None for the default one (the
// key the objects are recorded with).
pub fn namespace_key(name: &str) -> Option<String> {
    (name != "default").then(|| name.to_string())
}

// An object loaded on a linker namespace.
struct NamespaceObject {
    // The namespace it was loaded on, None for the default one.
    namespace: Option<String>,
    // Whether it is on every namespace: the linker adds the executable, the
    // LD_PRELOAD objects and the DF_1_GLOBAL ones to all the namespaces of
    // the configuration (find_libraries).
    global: bool,
    // The DT_SONAME the dependency names are matched against: an object
    // without one is only matched by its file.
    soname: Option<String>,
    file_id: Option<(u64, u64)>,
    // The dependency tree node.
    node: usize,
}

// The objects the linker namespaces loaded, looked up the way the linker
// looks up the soinfo list of each namespace.
#[derive(Default)]
pub struct LoadedObjects {
    objects: Vec<NamespaceObject>,
}

impl LoadedObjects {
    pub fn record(
        &mut self,
        namespace: &Option<String>,
        global: bool,
        soname: Option<&str>,
        file_id: Option<(u64, u64)>,
        node: usize,
    ) {
        self.objects.push(NamespaceObject {
            namespace: namespace.clone(),
            global,
            soname: soname.map(str::to_string),
            file_id,
            node,
        });
    }

    fn on<'a>(
        &'a self,
        namespace: &'a Option<String>,
    ) -> impl Iterator<Item = &'a NamespaceObject> {
        self.objects
            .iter()
            .filter(move |object| object.global || object.namespace == *namespace)
    }

    // The bionic find_loaded_library_by_soname: the node of the object NAME
    // matches on NAMESPACE of the CACHE configuration, or with SEARCH_LINKED
    // on the namespaces it links to whose link shares NAME.  A name with a
    // slash is not matched.
    pub fn find_by_soname(
        &self,
        cache: Option<&LdCache>,
        namespace: &Option<String>,
        name: &str,
        search_linked: bool,
    ) -> Option<usize> {
        if name.contains('/') {
            return None;
        }
        let find = |namespace: &Option<String>| {
            self.on(namespace)
                .find(|object| object.soname.as_deref() == Some(name))
                .map(|object| object.node)
        };
        find(namespace).or_else(|| {
            if !search_linked {
                return None;
            }
            links(cache, namespace)
                .iter()
                .filter(|link| link.is_accessible(name))
                .find_map(|link| find(&namespace_key(&link.namespace)))
        })
    }

    // The bionic find_loaded_library_by_inode: the node of the object loaded
    // from FILE_ID on NAMESPACE, or with SEARCH_LINKED on the namespaces it
    // links to whose link shares the object soname.
    pub fn find_by_file(
        &self,
        cache: Option<&LdCache>,
        namespace: &Option<String>,
        file_id: (u64, u64),
        search_linked: bool,
    ) -> Option<usize> {
        let find = |namespace: &Option<String>| {
            self.on(namespace)
                .find(|object| object.file_id == Some(file_id))
                .map(|object| (object.node, object.soname.clone()))
        };
        if let Some((node, _)) = find(namespace) {
            return Some(node);
        }
        if !search_linked {
            return None;
        }
        links(cache, namespace).iter().find_map(|link| {
            find(&namespace_key(&link.namespace))
                .filter(|(_, soname)| link.is_accessible(soname.as_deref().unwrap_or_default()))
                .map(|(node, _)| node)
        })
    }
}

// The links of NAMESPACE on the CACHE configuration.
fn links<'a>(cache: Option<&'a LdCache>, namespace: &Option<String>) -> &'a [NamespaceLink] {
    let config = cache.and_then(|cache| match namespace {
        Some(name) => cache.get_namespace(name),
        None => cache.get_default_namespace(),
    });
    config.map_or(&[], |config| &config.namespaces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;
    use std::fs;

    #[test]
    fn namespace_lookups() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let base = fs::canonicalize(tmpdir.path())?;
        fs::create_dir(base.join("bin"))?;
        fs::write(base.join("bin/binary"), [])?;
        let config = base.join("ld.config.txt");
        fs::write(
            &config,
            format!(
                "dir.test = {}/bin\n\
                 [test]\n\
                 additional.namespaces = art,other\n\
                 namespace.default.links = art,other\n\
                 namespace.default.link.art.shared_libs = libart.so\n\
                 namespace.default.link.other.allow_all_shared_libs = true\n\
                 namespace.art.links = default\n\
                 namespace.art.link.default.shared_libs = libc.so\n",
                base.display()
            ),
        )?;
        let props = SystemProperties {
            release: AndroidRelease(31),
            vndk_version: String::new(),
            vndk_lite: false,
        };
        let cache = crate::elf::ld_config_txt::parse_ld_config_txt(
            &config,
            &base.join("bin/binary"),
            Some("/system/bin/linker64"),
            ELFCLASS64,
            &props,
        )
        .map_err(std::io::Error::other)?;
        let cache = Some(&cache);

        let default = None;
        let art = namespace_key("art");
        let other = namespace_key("other");
        assert_eq!(namespace_key("default"), None);

        let mut loaded = LoadedObjects::default();
        loaded.record(&default, true, None, Some((1, 1)), 0);
        loaded.record(&default, false, Some("libc.so"), Some((1, 2)), 1);
        loaded.record(&art, false, Some("libart.so"), Some((1, 3)), 2);
        loaded.record(&art, false, Some("libx.so"), Some((1, 4)), 3);
        loaded.record(&other, false, Some("libdup.so"), Some((1, 5)), 4);
        // A preloaded object is on every namespace.
        loaded.record(&default, true, Some("libp.so"), Some((1, 6)), 5);
        loaded.record(&art, false, None, Some((1, 7)), 6);

        let soname = |namespace: &Option<String>, name, linked| {
            loaded.find_by_soname(cache, namespace, name, linked)
        };
        // The namespace own objects, then the ones the links share.
        assert_eq!(soname(&default, "libc.so", true), Some(1));
        assert_eq!(soname(&default, "libart.so", true), Some(2));
        assert_eq!(soname(&default, "libart.so", false), None);
        assert_eq!(soname(&default, "libx.so", true), None);
        assert_eq!(soname(&default, "libdup.so", true), Some(4));
        assert_eq!(soname(&default, "libp.so", false), Some(5));
        assert_eq!(soname(&art, "libc.so", true), Some(1));
        assert_eq!(soname(&art, "libdup.so", true), None);
        assert_eq!(soname(&art, "libp.so", false), Some(5));
        // A name with a slash is not matched.
        assert_eq!(soname(&default, "/lib/libc.so", true), None);

        let file = |namespace: &Option<String>, id, linked| {
            loaded.find_by_file(cache, namespace, id, linked)
        };
        assert_eq!(file(&default, (1, 1), false), Some(0));
        assert_eq!(file(&default, (1, 3), true), Some(2));
        assert_eq!(file(&default, (1, 3), false), None);
        // Through a link, the object soname must be shared.
        assert_eq!(file(&default, (1, 4), true), None);
        assert_eq!(file(&default, (1, 7), true), None);
        assert_eq!(file(&art, (1, 2), true), Some(1));
        assert_eq!(file(&art, (1, 7), false), Some(6));
        Ok(())
    }

    #[test]
    fn dt_needed_paths() {
        let fix = |name, ei_class, version| fix_dt_needed(name, ei_class, version).into_owned();
        // Only a 32-bit binary targeting an API level below 23.
        assert_eq!(fix("/a/b/libfoo.so", ELFCLASS32, Some(22)), "libfoo.so");
        assert_eq!(fix("b/libfoo.so", ELFCLASS32, Some(22)), "libfoo.so");
        assert_eq!(
            fix("/a/b/libfoo.so", ELFCLASS32, Some(23)),
            "/a/b/libfoo.so"
        );
        assert_eq!(
            fix("/a/b/libfoo.so", ELFCLASS64, Some(22)),
            "/a/b/libfoo.so"
        );
        assert_eq!(fix("/a/b/libfoo.so", ELFCLASS32, None), "/a/b/libfoo.so");
        assert_eq!(fix("libfoo.so", ELFCLASS32, Some(22)), "libfoo.so");
    }

    #[test]
    fn preload_entries() {
        assert_eq!(
            preload_list(" liba.so:libb.so\tlibc.so::"),
            vec!["liba.so", "libb.so\tlibc.so"]
        );
        assert!(preload_list("").is_empty());
    }

    #[test]
    fn runpath_entries() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let base = fs::canonicalize(tmpdir.path())?;
        for dir in ["o", "o/lib64", "o/lib"] {
            fs::create_dir(base.join(dir))?;
        }
        std::os::unix::fs::symlink(base.join("o/lib64"), base.join("link"))?;
        let base = base.to_str().unwrap();
        let origin = format!("{base}/o");
        let runpath = |list: &str, origin: Option<&str>, release| {
            runpath_list(list, origin, ELFCLASS64, release)
        };

        // $ORIGIN and $LIB, braced or not, with each entry resolved and the
        // ones that are not a directory dropped.  $PLATFORM is not a token.
        let list = format!("$ORIGIN/$LIB:${{ORIGIN}}/../link::{base}/missing:/${{PLATFORM}}");
        let lib64 = format!("{base}/o/lib64");
        assert_eq!(
            runpath(&list, Some(&origin), None),
            vec![Ok(lib64.clone()), Ok(lib64.clone())]
        );
        assert_eq!(
            runpath_list("$ORIGIN/${LIB}", Some(&origin), ELFCLASS32, None),
            vec![Ok(format!("{base}/o/lib"))]
        );
        // Android 9 has no $LIB, and Android 6 no DT_RUNPATH at all.
        assert_eq!(
            runpath(&list, Some(&origin), Some(AndroidRelease(28))),
            vec![Ok(lib64.clone())]
        );
        assert!(runpath(&list, Some(&origin), Some(AndroidRelease(23))).is_empty());
        // An $ORIGIN that is not valid UTF-8.
        assert_eq!(
            runpath(&format!("$ORIGIN/lib:{base}/o"), None, None),
            vec![Err("$ORIGIN/lib".to_string()), Ok(origin.clone())]
        );

        // Nothing is expanded on LD_LIBRARY_PATH, only resolved.
        assert_eq!(
            library_path_list(&format!("$ORIGIN:{base}/link::{base}/o")),
            vec![lib64, origin]
        );
        Ok(())
    }
}
