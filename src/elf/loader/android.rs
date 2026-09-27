// The bionic linker.

use super::*;
use crate::elf::android::{self as bionic, AndroidRelease};

pub(in crate::elf) struct Android;

// The release of the device, None when it can not be read (the rules of the
// latest release apply then).
fn release() -> Option<AndroidRelease> {
    bionic::SystemProperties::current().map(|props| props.release)
}

impl Loader for Android {
    type Cache = ld_config_txt::LdCache;

    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        binary: &P,
        elc: &ElfInfo,
    ) {
        let Some(props) = bionic::SystemProperties::current() else {
            return;
        };
        if let Some(ld_config_path) = ld_config_txt::get_ld_config_path(
            binary,
            elc.interp.as_deref(),
            elc.e_machine,
            elc.ei_class,
            props,
        ) {
            // On Android 10 and forward each executable might have a associated ld.config.txt
            // file in different paths, so we need to reload for each argument.
            // A shared library has no PT_INTERP segment, so no sanitizer applies.
            *ld_cache = ld_config_txt::parse_ld_config_txt(
                &Path::new(&ld_config_path),
                binary,
                elc.interp.as_deref(),
                elc.ei_class,
                props,
            )
            .ok();
        }
    }

    // android loader only uses the default system search patch if the ld.so.config file can not
    // be loader or if an error was found parsing it (for instance if the executable does not
    // has an entry associated in the section).
    fn load_system_dirs(ld_cache: &Option<Self::Cache>) -> bool {
        ld_cache.is_none()
    }

    fn preload_list(list: &str, _elc: &ElfInfo) -> Vec<String> {
        bionic::preload_list(list)
    }

    // The DT_RUNPATH entries with $ORIGIN and $LIB expanded, and the
    // LD_LIBRARY_PATH ones without any token, both resolved to their real
    // path the way the linker keeps them.
    fn search_list(
        list: &str,
        site: TokenSite,
        elc: &ElfInfo,
        _platform: Option<&String>,
    ) -> Vec<Result<String, String>> {
        match site {
            TokenSite::SearchPath => {
                bionic::runpath_list(list, elc.origin.as_deref(), elc.ei_class, release())
            }
            _ => bionic::library_path_list(list)
                .into_iter()
                .map(Ok)
                .collect(),
        }
    }

    // No token is expanded on DT_NEEDED nor on LD_PRELOAD.
    fn expand_tokens(
        input: &str,
        _site: TokenSite,
        _elc: &ElfInfo,
        _platform: Option<&String>,
    ) -> Option<String> {
        Some(input.to_string())
    }

    // $ORIGIN is the directory of the object real path (the soinfo realpath
    // the linker gets from the file descriptor).
    fn origin_directory<P: AsRef<Path>>(filename: &P, _melc: Option<&ElfInfo>) -> Option<String> {
        canonical_origin_directory(filename)
    }

    // The bionic loader does not implement DT_RPATH at all: it warns about the
    // unused dynamic entry and only searches DT_RUNPATH.
    fn rpath_search(_elc: &ElfInfo) -> bool {
        false
    }

    // The linker ignores DF_1_NODEFLIB (it is not among the DT_FLAGS_1 flags
    // prelink_image supports), searching the namespace directories
    // regardless.
    fn nodeflib_rule(_step: SearchStep, _elc: &ElfInfo) -> NodeflibRule {
        NodeflibRule::Search
    }
}

impl SearchCache for ld_config_txt::LdCache {
    // The Android linker namespace an object is loaded in, where it can be
    // the ld.config.txt namespace name, or None for the default one.  A dependency
    // is resolved from the namespace of the object that requests it, and not always
    // from the default one.  So a library loaded through a namespace link resolves
    // its own dependencies with the linked namespace search paths.
    type Namespace = Option<String>;

    fn summary(&self) -> String {
        format!("{} namespaces", self.namespaces_count())
    }

    // The search paths of the NAMESPACE alone: the dependencies go through
    // Android::find_library, which also follows the namespace links.
    fn resolve<'a>(
        &'a self,
        dtneeded: &str,
        platform: Option<&String>,
        elc: &'a ElfInfo,
        namespace: &Option<String>,
    ) -> Option<Resolution<'a>> {
        let current_ns = match namespace {
            Some(name) => self.get_namespace(name)?,
            None => self.get_default_namespace()?,
        };
        search_dirs(
            &current_ns.search_paths,
            dtneeded,
            elc,
            platform,
            DepMode::LdCache,
            namespace,
        )
    }
}

// What the linker does with a dependency name.
pub(in crate::elf) enum Lookup<'a> {
    // It is already loaded, at this tree node.
    Loaded(usize),
    // The object it loads, or why it fails (None when it is not found).
    Search(Box<Option<Resolution<'a>>>),
}

// A linker namespace: one of the configuration, or the default one when no
// ld.config.txt applies, which searches the default directories
// (init_default_namespace_no_config).
struct Namespace<'a> {
    key: Option<String>,
    config: Option<&'a ld_config_txt::NamespaceConfig>,
    search_paths: &'a search_path::SearchPathVec,
    mode: DepMode,
}

impl<'a> Namespace<'a> {
    fn get(config: &'a Config, key: Option<String>) -> Option<Namespace<'a>> {
        match config.ld_cache {
            Some(cache) => {
                let ns = match &key {
                    Some(name) => cache.get_namespace(name)?,
                    None => cache.get_default_namespace()?,
                };
                Some(Namespace {
                    key,
                    config: Some(ns),
                    search_paths: &ns.search_paths,
                    mode: DepMode::LdCache,
                })
            }
            None => Some(Namespace {
                key: None,
                config: None,
                search_paths: &config.system_dirs,
                mode: DepMode::SystemDirs,
            }),
        }
    }

    fn links(&self) -> &'a [ld_config_txt::NamespaceLink] {
        self.config.map_or(&[], |ns| &ns.namespaces)
    }

    // Only the default namespace has the LD_LIBRARY_PATH directories.
    fn ld_library_paths(&self, config: &'a Config) -> Option<&'a search_path::SearchPathVec> {
        self.key.is_none().then_some(&config.ld_library_path)
    }
}

// The outcome of the bionic load_library on a namespace: done, or failed
// (with the error, None when nothing was found), which moves on to the next
// namespace.
enum Load<'a> {
    Done(Lookup<'a>),
    Failed(Option<String>),
}

impl Android {
    // The bionic find_library_internal for NAME, a dependency of the ELC
    // object loaded on NAMESPACE (the executable and the preload entries are
    // on the default one).  An object already loaded with NAME as soname on
    // the namespace, or on a linked one that shares it, is taken.  Otherwise
    // the name is searched on the namespace, and then on each linked
    // namespace whose link shares it, where the object would be loaded.
    pub(in crate::elf) fn find_library<'a>(
        config: &'a Config,
        loaded: &bionic::LoadedObjects,
        elc: &'a ElfInfo,
        namespace: &Option<String>,
        name: &'a String,
    ) -> Lookup<'a> {
        let cache = config.ld_cache.as_ref();
        let Some(ns) = Namespace::get(config, namespace.clone()) else {
            return Lookup::Search(Box::new(None));
        };

        if let Some(node) = loaded.find_by_soname(cache, &ns.key, name, true) {
            return Lookup::Loaded(node);
        }

        let error = match load_library(config, loaded, elc, &ns, name, true) {
            Load::Done(lookup) => return lookup,
            Load::Failed(error) => error,
        };

        for link in ns.links() {
            let Some(linked) = Namespace::get(config, bionic::namespace_key(&link.namespace))
            else {
                continue;
            };
            // find_library_in_linked_namespace: the link must share the
            // soname of the object loaded there, or else the file name.
            let candidate = loaded.find_by_soname(cache, &linked.key, name, false);
            let soname = match candidate {
                Some(_) => name.clone(),
                None => pathutils::get_name(&Path::new(name)),
            };
            if !link.is_accessible(&soname) {
                continue;
            }
            if let Some(node) = candidate {
                return Lookup::Loaded(node);
            }
            if let Load::Done(lookup) = load_library(config, loaded, elc, &linked, name, false) {
                return lookup;
            }
        }

        // The error of the first namespace is the one reported.
        Lookup::Search(Box::new(error.map(Err)))
    }
}

// The bionic load_library of NAME on the NS namespace: an object already
// loaded from the file found (on the namespace, or with SEARCH_LINKED on a
// linked one that shares it) is taken, otherwise the file is loaded.
fn load_library<'a>(
    config: &'a Config,
    loaded: &bionic::LoadedObjects,
    elc: &'a ElfInfo,
    ns: &Namespace<'a>,
    name: &'a String,
    search_linked: bool,
) -> Load<'a> {
    use std::os::unix::fs::MetadataExt;

    let Some((dir, mode, path)) = open_library(config, elc, ns, name) else {
        return Load::Failed(None);
    };

    let file_id = fs::metadata(&path).ok().map(|m| (m.dev(), m.ino()));
    if let Some(node) = file_id
        .and_then(|id| loaded.find_by_file(config.ld_cache.as_ref(), &ns.key, id, search_linked))
    {
        return Load::Done(Lookup::Loaded(node));
    }

    match open_dependency(&path, elc, config.platform) {
        Ok(delc) => Load::Done(Lookup::Search(Box::new(Some(Ok(ResolvedDependency {
            elc: delc,
            path: dir.into(),
            filename: pathutils::get_name(&path),
            mode,
            namespace: ns.key.clone(),
        }))))),
        Err(Rejection::Skip(e) | Rejection::Fatal(e)) => {
            Load::Failed(Some(format!("{}: {e}", path.display())))
        }
    }
}

// The bionic open_library: the file NAME is on the NS namespace, the path
// itself for a name with a slash, or else the first one of the
// LD_LIBRARY_PATH directories (default namespace only), the DT_RUNPATH ones
// of the ELC requesting object, and the namespace search paths.
fn open_library<'a>(
    config: &'a Config,
    elc: &'a ElfInfo,
    ns: &Namespace<'a>,
    name: &'a String,
) -> Option<(&'a String, DepMode, PathBuf)> {
    let candidate = |path: &PathBuf| open_dependency(path, elc, config.platform).is_ok();

    if name.contains('/') {
        let path = PathBuf::from(name);
        return candidate(&path).then_some((name, DepMode::Direct, path));
    }

    let first = |dirs: &'a search_path::SearchPathVec, mode: DepMode| {
        dirs.iter().find_map(|dir| {
            let path = Android::dependency_path(&dir.path, name);
            candidate(&path).then_some((&dir.path, mode, path))
        })
    };
    ns.ld_library_paths(config)
        .and_then(|dirs| first(dirs, DepMode::LdLibraryPath))
        .or_else(|| first(&elc.runpath, DepMode::DtRunpath))
        .or_else(|| first(ns.search_paths, ns.mode))
}
