// The glibc and musl loaders.

use super::*;

pub(in crate::elf) struct Linux;

impl Loader for Linux {
    type Cache = ld_so_cache::LdCache;

    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        _binary: &P,
        elc: &ElfInfo,
    ) {
        if interp::is_glibc(&elc.interp) {
            // glibc's ld.so.cache is shared between all executables, so there is no need
            // to reload for multiple entries.
            if ld_cache.is_none() {
                *ld_cache = ld_so_cache::parse_ld_so_cache(
                    &Path::new("/etc/ld.so.cache"),
                    elc.ei_class,
                    elc.e_machine,
                    elc.e_flags,
                )
                .ok();
            }
        };
    }

    fn load_ld_so_preload(interp: &Option<String>) -> Vec<String> {
        if interp::is_glibc(interp) {
            return ld_preload::parse_ld_so_preload(&Path::new("/etc/ld.so.preload"));
        }
        Vec::new()
    }

    fn handle_loader(elc: &mut ElfInfo) {
        elc.is_musl = interp::is_musl(&elc.interp)
            || elc.deps.iter().any(|dep| dep.starts_with("libc.musl-"))
            || (elc.interp.is_none() && is_musl_system());
    }

    // The musl loader takes DT_RUNPATH over DT_RPATH, but searches it the way
    // it searches DT_RPATH.  For the object own dependencies and, walking the
    // chain of the objects that needed a library, for the indirect ones.
    fn handle_search_paths(elc: &mut ElfInfo) {
        if elc.is_musl && elc.has_runpath {
            elc.rpath = std::mem::take(&mut elc.runpath);
            elc.has_runpath = false;
        }
    }

    fn parse_elf_dyn_searchpath_lib<Elf: FileHeader>(
        endian: Elf::Endian,
        elf: &Elf,
        dynstr: &mut String,
    ) {
        if let Ok(libdir) = system_dirs::get_slibdir(
            elf.e_machine(endian),
            elf.e_ident().class,
            elf.e_flags(endian),
        ) {
            *dynstr = replace_dyn_str(dynstr, "LIB", libdir);
        }
    }

    // musl loader and libc is on the same shared object, so adds a synthetic dependendy for
    // the binary so it is also shown and to be returned in case a objects has libc.so
    // as needed.
    fn resolve_binary_arch(elc: &ElfInfo, deptree: &mut DepTree, depp: usize) -> Result<(), Error> {
        if !elc.is_musl {
            return Ok(());
        }

        let interp = match &elc.interp {
            Some(interp) => Some(interp.clone()),
            None => find_musl_loader(),
        };
        if let Some(interp) = interp {
            let path = Path::new(&interp);
            deptree.addnode(DepNode::from_path(&path, DepMode::SystemDirs), depp);
        }
        Ok(())
    }

    // The dynamic loader is always loaded, and ldd always shows it.  The libc.so is
    // explicitly lists it as a dependency, but an object might not depend on libc at
    // all.  Objects without any dependency are skipped, since the loader is not
    // involved.
    fn add_loader_dependency(
        config: &Config,
        elc: &ElfInfo,
        deptree: &mut DepTree,
        root_depp: usize,
    ) {
        if !interp::is_glibc(&elc.interp) || deptree.arena[root_depp].children.is_empty() {
            return;
        }
        if deptree
            .arena
            .iter()
            .any(|n| interp::is_glibc_name(&n.val.name))
        {
            return;
        }

        // For an executable the PT_INTERP segment has the loader path.
        if let Some(interp) = &elc.interp {
            let path = Path::new(interp);
            if path.exists() {
                deptree.addnode(DepNode::from_path(&path, DepMode::Direct), root_depp);
                return;
            }
        }

        // Otherwise resolve the loader soname through the loader cache and the
        // system directories (only the soname matching the object architecture
        // resolves).  The object search paths do not apply, since the loader is
        // not subject to the dependency search.
        for name in interp::glibc_names() {
            let dtneeded = name.to_string();
            if let Some(dep) = resolve_loader(config, elc, &dtneeded) {
                deptree.addnode(
                    DepNode::new(Some(dep.path.to_string()), dep.filename.clone(), dep.mode),
                    root_depp,
                );
                return;
            }
        }
    }

    fn rpath_search(elc: &ElfInfo) -> bool {
        !elc.has_runpath
    }
}

impl SearchCache for ld_so_cache::LdCache {
    type Namespace = NoNamespace;

    fn summary(&self) -> String {
        format!("{} entries", self.len())
    }

    fn resolve<'a>(
        &'a self,
        dtneeded: &'a String,
        platform: Option<&String>,
        elc: &'a ElfInfo,
        _namespace: &NoNamespace,
    ) -> Option<ResolvedDependency<'a>> {
        let dir = self.get(dtneeded)?;
        search_dir(
            dir,
            dtneeded,
            elc,
            platform,
            DepMode::LdCache,
            &Default::default(),
        )
    }
}
