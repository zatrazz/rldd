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
        // Only the glibc loader reads the cache, so an object for another
        // loader does not use the one of a previous object.
        if !interp::is_glibc(&elc.interp) {
            *ld_cache = None;
            return;
        }
        // glibc's ld.so.cache is shared between all executables, so there is no need
        // to reload for multiple entries, but the entries apply to the object ABI.
        if ld_cache.is_none() {
            *ld_cache = ld_so_cache::parse_ld_so_cache(&Path::new("/etc/ld.so.cache")).ok();
        }
        if let Some(cache) = ld_cache {
            cache.select(
                elc.ei_class,
                elc.ei_data,
                elc.e_machine,
                elc.e_flags,
                elc.interp.as_deref(),
            );
        }
    }

    fn load_ld_so_preload(interp: &Option<String>) -> Vec<String> {
        if interp::is_glibc(interp) {
            return ld_preload::parse_ld_so_preload(&Path::new("/etc/ld.so.preload"));
        }
        Vec::new()
    }

    fn handle_loader(elc: &mut ElfInfo) {
        elc.is_musl = interp::is_musl(&elc.interp)
            || elc
                .needed
                .iter()
                .any(|(dep, _)| dep.starts_with("libc.musl-"))
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

    // The musl loader expands the tokens of the whole list at once
    // (fixup_rpath), and splits it on colons and newlines skipping the empty
    // entries (path_open).
    fn search_list(
        list: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Vec<Result<String, String>> {
        if elc.is_musl {
            let Some(list) = musl_expand(list, elc.origin.as_deref()) else {
                return vec![Err(list.to_string())];
            };
            return list
                .split([':', '\n'])
                .filter(|entry| !entry.is_empty())
                .map(|entry| Ok(entry.to_string()))
                .collect();
        }
        list.split(':')
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                Self::expand_tokens(entry, site, elc, platform).ok_or_else(|| entry.to_string())
            })
            .collect()
    }

    // The glibc loader expands $ORIGIN, $PLATFORM and $LIB on the search lists
    // and the dependency names, while the musl one only expands the search
    // lists.
    fn expand_tokens(
        input: &str,
        _site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Option<String> {
        if elc.is_musl {
            return Some(input.to_string());
        }
        let platform = platform
            .map(String::as_str)
            .or_else(|| platform::get(elc.e_machine, elc.ei_data));
        let lib = system_dirs::get_slibdir(elc.e_machine, elc.ei_class, elc.e_flags).ok();
        glibc_expand(input, elc.origin.as_deref(), platform, lib)
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
            if let Some(dep) = resolve_loader(config, elc, name) {
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
        dtneeded: &str,
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

// The length of the NAME dynamic string token at the start of INPUT (right
// after the '$'), braces included, following the ELF gABI rules the glibc
// is_dst checks: ${NAME}, or $NAME not followed by an identifier character.
fn dst_len(input: &str, name: &str) -> Option<usize> {
    match input.strip_prefix('{') {
        Some(input) => input
            .strip_prefix(name)?
            .starts_with('}')
            .then_some(name.len() + 2),
        None => {
            let rest = input.strip_prefix(name)?;
            (!rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
                .then_some(name.len())
        }
    }
}

// Expand the $ORIGIN, $PLATFORM and $LIB tokens of INPUT the way the glibc
// loader does (_dl_dst_substitute): anything else starting with a '$' is kept
// as is, and a token without a value drops the whole entry (None).
fn glibc_expand(
    input: &str,
    origin: Option<&str>,
    platform: Option<&str>,
    lib: Option<&str>,
) -> Option<String> {
    let mut r = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find('$') {
        r.push_str(&rest[..pos]);
        rest = &rest[pos + 1..];
        let token = [("ORIGIN", origin), ("PLATFORM", platform), ("LIB", lib)]
            .into_iter()
            .find_map(|(name, value)| dst_len(rest, name).map(|len| (len, value)));
        match token {
            Some((len, value)) => {
                r.push_str(value?);
                rest = &rest[len..];
            }
            None => r.push('$'),
        }
    }
    r.push_str(rest);
    Some(r)
}

// Expand the $ORIGIN tokens of a search LIST the way the musl loader does
// (fixup_rpath): the prefix is matched as is (so $ORIGINAL expands to the
// origin followed by 'AL'), and any other use of a '$' makes the loader
// ignore the whole list (None).
fn musl_expand(list: &str, origin: Option<&str>) -> Option<String> {
    let mut r = String::with_capacity(list.len());
    let mut rest = list;
    while let Some(pos) = rest.find('$') {
        r.push_str(&rest[..pos]);
        rest = &rest[pos..];
        let len = if rest.starts_with("$ORIGIN") {
            "$ORIGIN".len()
        } else if rest.starts_with("${ORIGIN}") {
            "${ORIGIN}".len()
        } else {
            return None;
        };
        r.push_str(origin?);
        rest = &rest[len..];
    }
    r.push_str(rest);
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glibc_tokens() {
        let expand = |input| glibc_expand(input, Some("/o"), Some("x86_64"), Some("lib64"));
        assert_eq!(expand("$ORIGIN/../$LIB").as_deref(), Some("/o/../lib64"));
        assert_eq!(expand("${ORIGIN}/${LIB}").as_deref(), Some("/o/lib64"));
        assert_eq!(expand("/a/$PLATFORM/b").as_deref(), Some("/a/x86_64/b"));
        assert_eq!(expand("$ORIGIN$LIB").as_deref(), Some("/olib64"));
        // Not a token: followed by an identifier character, or not closed.
        assert_eq!(expand("$ORIGINAL").as_deref(), Some("$ORIGINAL"));
        assert_eq!(expand("$LIB_X/$LIB2").as_deref(), Some("$LIB_X/$LIB2"));
        assert_eq!(expand("${ORIGIN/x").as_deref(), Some("${ORIGIN/x"));
        assert_eq!(expand("$ORIGIN-x").as_deref(), Some("/o-x"));
        assert_eq!(expand("$FOO/$").as_deref(), Some("$FOO/$"));
        assert_eq!(expand("/usr/lib").as_deref(), Some("/usr/lib"));
        // A known token without a value drops the entry.
        assert_eq!(glibc_expand("/a/$PLATFORM", Some("/o"), None, None), None);
        assert_eq!(glibc_expand("$ORIGIN/lib", None, None, None), None);
        assert_eq!(
            glibc_expand("$PLATFORMX", Some("/o"), None, None).as_deref(),
            Some("$PLATFORMX")
        );
    }

    #[test]
    fn musl_tokens() {
        let expand = |list| musl_expand(list, Some("/o"));
        assert_eq!(expand("$ORIGIN/lib:/x").as_deref(), Some("/o/lib:/x"));
        assert_eq!(expand("${ORIGIN}/lib").as_deref(), Some("/o/lib"));
        assert_eq!(expand("$ORIGINAL").as_deref(), Some("/oAL"));
        assert_eq!(expand("/usr/lib").as_deref(), Some("/usr/lib"));
        // Any other token drops the whole list.
        assert_eq!(expand("$ORIGIN/lib:/$LIB"), None);
        assert_eq!(expand("/$PLATFORM"), None);
        assert_eq!(musl_expand("$ORIGIN/lib", None), None);
    }
}
