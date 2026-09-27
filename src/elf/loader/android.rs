// The bionic linker.

use super::*;
use crate::elf::android::{self as bionic, AndroidRelease};

pub(in crate::elf) struct Android;

// The release of the device, None on the host tests, where the rules of the
// latest release apply.
#[cfg(target_os = "android")]
fn release() -> Option<AndroidRelease> {
    crate::elf::android::SystemProperties::current().map(|props| props.release)
}

#[cfg(not(target_os = "android"))]
fn release() -> Option<AndroidRelease> {
    None
}

impl Loader for Android {
    type Cache = ld_config_txt::LdCache;

    #[cfg(target_os = "android")]
    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        binary: &P,
        elc: &ElfInfo,
    ) {
        let Some(props) = crate::elf::android::SystemProperties::current() else {
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

    fn resolve<'a>(
        &'a self,
        dtneeded: &str,
        platform: Option<&String>,
        elc: &'a ElfInfo,
        namespace: &Option<String>,
    ) -> Option<Resolution<'a>> {
        // The search starts on the namespace the requesting object was loaded in
        // (the default one for the executable itself) and follows the namespaces
        // it links against, without following further links.  An object resolved
        // through a link is loaded on the linked namespace, which is the one its
        // own dependencies are then resolved from.
        let current_ns = match namespace {
            Some(name) => self.get_namespace(name)?,
            None => self.get_default_namespace()?,
        };

        if let Some(resolved) = search_dirs(
            &current_ns.search_paths,
            dtneeded,
            elc,
            platform,
            DepMode::LdCache,
            namespace,
        ) {
            return Some(resolved);
        }

        for link in &current_ns.namespaces {
            // A link only makes the libraries on its shared_libs list
            // accessible (unless it allows all of them).
            if !link.is_accessible(dtneeded) {
                continue;
            }

            if let Some(linked_ns) = self.get_namespace(&link.namespace) {
                if !linked_ns.is_accessible(dtneeded) {
                    continue;
                }

                if let Some(resolved) = search_dirs(
                    &linked_ns.search_paths,
                    dtneeded,
                    elc,
                    platform,
                    DepMode::LdCache,
                    &Some(link.namespace.clone()),
                ) {
                    return Some(resolved);
                }
            }
        }

        None
    }
}
