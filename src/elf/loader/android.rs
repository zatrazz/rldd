// The bionic linker.

use super::*;

pub(in crate::elf) struct Android;

impl Loader for Android {
    type Cache = ld_config_txt::LdCache;

    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        binary: &P,
        elc: &ElfInfo,
    ) {
        if let Some(ld_config_path) =
            ld_config_txt::get_ld_config_path(binary, elc.e_machine, elc.ei_class)
        {
            // On Android 10 and forward each executable might have a associated ld.config.txt
            // file in different paths, so we need to reload for each argument.
            // A shared library has no PT_INTERP segment, so no sanitizer applies.
            *ld_cache = ld_config_txt::parse_ld_config_txt(
                &Path::new(&ld_config_path),
                binary,
                elc.interp.as_deref(),
                elc.ei_class,
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
        dtneeded: &'a String,
        platform: Option<&String>,
        elc: &'a ElfInfo,
        namespace: &Option<String>,
    ) -> Option<ResolvedDependency<'a>> {
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
