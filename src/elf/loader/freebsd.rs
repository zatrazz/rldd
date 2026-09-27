// The FreeBSD run-time linker.

use std::borrow::Cow;

use super::*;

pub(in crate::elf) struct FreeBsd;

impl Loader for FreeBsd {
    type Cache = search_path::SearchPathVec;

    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        _binary: &P,
        elc: &ElfInfo,
    ) {
        // The 32-bit compat objects use a separate hints file (the rtld
        // COMPAT_libcompat suffix), so the cache is reloaded for each binary.
        let hints = if compat32(elc) {
            "/var/run/ld-elf32.so.hints"
        } else {
            "/var/run/ld-elf.so.hints"
        };
        *ld_cache = ld_hints_freebsd::parse_ld_so_hints(&Path::new(hints)).ok();
    }

    // Every rtld search list, LD_LIBRARY_PATH included, is split on both
    // colons and semicolons, skipping the empty entries (path_enumerate).  The
    // tokens of a DT_RPATH or DT_RUNPATH list are expanded on the whole list
    // (digest_dynamic2), while the LD_LIBRARY_PATH ones are not expanded.
    fn search_list(
        list: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Vec<Result<String, String>> {
        let list = match Self::expand_tokens(list, site, elc, platform) {
            Some(list) => list,
            None => return vec![Err(list.to_string())],
        };
        list.split([':', ';'])
            .filter(|entry| !entry.is_empty())
            .map(|entry| Ok(entry.to_string()))
            .collect()
    }

    // rtld expands the tokens of the DT_RPATH and DT_RUNPATH lists and of the
    // dependency names with a slash (origin_subst), but not the ones of
    // LD_LIBRARY_PATH or of the preload names.
    fn expand_tokens(
        input: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Option<String> {
        let expand = match site {
            TokenSite::SearchPath => true,
            TokenSite::Needed => input.contains('/'),
            TokenSite::LibraryPath | TokenSite::Preload => false,
        };
        if !expand {
            return Some(input.to_string());
        }
        let [osname, osrel, machine] = uname_values();
        let platform = platform.map(String::as_str).or(machine.as_deref());
        let lib = if compat32(elc) { "lib32" } else { "lib" };
        Some(origin_subst(
            input,
            &[
                ("ORIGIN", elc.origin.as_deref()),
                ("OSNAME", osname.as_deref()),
                ("OSREL", osrel.as_deref()),
                ("PLATFORM", platform),
                ("LIB", Some(lib)),
            ],
        ))
    }

    fn origin_directory<P: AsRef<Path>>(filename: &P, _melc: Option<&ElfInfo>) -> Option<String> {
        canonical_origin_directory(filename)
    }

    // rtld takes the first file of the search that exists (try_library_path),
    // and fails the load when it is not an object it can load (map_object)
    // instead of going on with the search.  check_elf_headers checks the
    // class, data encoding, version, type and machine, and not the EI_OSABI
    // field.
    fn check_candidate(
        _data: &[u8],
        parsed: &Result<ElfInfo, &'static str>,
        melc: &ElfInfo,
    ) -> Result<(), Rejection> {
        match parsed {
            Ok(elc) if elc.ei_class != melc.ei_class || elc.ei_data != melc.ei_data => {
                Err(Rejection::Fatal("unsupported file layout".to_string()))
            }
            Ok(elc) if elc.e_machine != melc.e_machine => {
                Err(Rejection::Fatal("unsupported machine".to_string()))
            }
            Ok(_) => Ok(()),
            Err(e) => Err(Rejection::Fatal(e.to_string())),
        }
    }

    // find_library: rtld maps the dependency name with libmap.conf for the
    // requesting object once it knows no object is loaded under that name
    // (load_object), and opens a name with a slash as is.  Otherwise it
    // searches each list with each directory mapped by libmap.conf too
    // (path_enumerate).  A preloaded object has no requesting object, so its
    // name is not mapped (the directories only get the unconstrained
    // mappings), and only the LD_LIBRARY_PATH and hints directories are
    // searched.
    fn resolve_dependency<'a>(
        dependency: &'a String,
        config: &'a Config,
        elc: &'a ElfInfo,
        refpath: &str,
        namespace: &ObjectNamespace,
        preload: bool,
    ) -> Option<Resolution<'a>> {
        let refobj = (!preload).then_some(refpath);
        let name = match refobj.and_then(|refpath| libmap_find(config, Some(refpath), dependency)) {
            // The tokens of a name mapped to a path are expanded too.
            Some(name) => Cow::Owned(
                Self::expand_tokens(&name, TokenSite::Needed, elc, config.platform).unwrap_or(name),
            ),
            None => Cow::Borrowed(dependency.as_str()),
        };
        if name.contains('/') {
            return Some(open_path_dependency(name, config, elc, namespace, preload));
        }

        let search = |dirs: Vec<&'a search_path::SearchPath>, mode: DepMode| {
            dirs.into_iter().find_map(|dir| {
                let dir = match libmap_find(config, refobj, &dir.path) {
                    Some(mapped) => Cow::Owned(mapped),
                    None => Cow::Borrowed(dir.path.as_str()),
                };
                search_dir(dir, &name, elc, config.platform, mode, namespace)
            })
        };
        let all = |list: &'a search_path::SearchPathVec| list.iter().collect::<Vec<_>>();
        // DF_1_NODEFLIB skips the standard directories, and the hints ones
        // that are standard directories too.
        let nodeflib = !preload && elc.nodeflibs;
        let hints = config
            .ld_cache
            .as_ref()
            .and_then(|cache| cache.directories())
            .map(|hints| gethints(hints, &config.system_dirs, nodeflib));
        let lists = [
            ((!preload).then(|| all(&elc.rpath)), DepMode::DtRpath),
            (Some(all(&config.ld_library_path)), DepMode::LdLibraryPath),
            ((!preload).then(|| all(&elc.runpath)), DepMode::DtRunpath),
            (hints, DepMode::LdCache),
            (
                (!preload && !nodeflib).then(|| all(&config.system_dirs)),
                DepMode::SystemDirs,
            ),
        ];
        lists
            .into_iter()
            .find_map(|(dirs, mode)| dirs.and_then(|dirs| search(dirs, mode)))
    }

    // Only shown on the locations searched for a dependency not found, the
    // search itself being the resolve_dependency one.
    fn nodeflib_rule(step: SearchStep, _elc: &ElfInfo) -> NodeflibRule {
        match step {
            SearchStep::Cache => NodeflibRule::OutsideSystemDirs,
            SearchStep::SystemDirs => NodeflibRule::Skip,
            _ => NodeflibRule::Search,
        }
    }
}

// The HINTS directories searched: with NOSTDLIB (DF_1_NODEFLIB), without the
// ones that are also STANDARD directories (gethints(true)).
fn gethints<'a>(
    hints: &'a search_path::SearchPathVec,
    standard: &search_path::SearchPathVec,
    nostdlib: bool,
) -> Vec<&'a search_path::SearchPath> {
    hints
        .iter()
        .filter(|dir| !nostdlib || !standard.iter().any(|std| std.path == dir.path))
        .collect()
}

// The lm_find mapping of NAME, a library name or a search directory, for the
// REFOBJ object path (None for no object), when the libmap.conf has one.
fn libmap_find(config: &Config, refobj: Option<&str>, name: &str) -> Option<String> {
    config.libmap.as_ref()?.borrow_mut().find(refobj, name)
}

// Whether ELC is loaded by the 32-bit compat rtld of a 64-bit system
// (ld-elf32.so.1, built with the "32" COMPAT_libcompat suffix).
fn compat32(elc: &ElfInfo) -> bool {
    cfg!(target_pointer_width = "64") && elc.ei_class == ELFCLASS32
}

// Replace the TOKENS of INPUT in order, each one along with its braced form,
// the way origin_subst does.  A token without a value is kept as written
// (the $ORIGIN of an object whose path can not be resolved).
fn origin_subst(input: &str, tokens: &[(&str, Option<&str>)]) -> String {
    let mut r = input.to_string();
    for (token, value) in tokens {
        if let Some(value) = value {
            r = replace_token(&r, token, value);
        }
    }
    r
}

// The uname(3) sysname, release and machine strings (the kern.ostype,
// kern.osrelease and hw.machine sysctls), which the $OSNAME, $OSREL and
// $PLATFORM tokens expand to.
#[cfg(target_os = "freebsd")]
fn uname_values() -> &'static [Option<String>; 3] {
    use std::sync::OnceLock;
    static VALUES: OnceLock<[Option<String>; 3]> = OnceLock::new();
    VALUES.get_or_init(|| [c"kern.ostype", c"kern.osrelease", c"hw.machine"].map(sysctl_string))
}

#[cfg(not(target_os = "freebsd"))]
fn uname_values() -> &'static [Option<String>; 3] {
    static VALUES: [Option<String>; 3] = [None, None, None];
    &VALUES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;
    use std::cell::RefCell;

    // The search configuration with the LIBRARY_PATH directories and the
    // LIBMAP contents.
    fn config<'a>(
        tmpdir: &TempDir,
        ld_cache: &'a Option<LoaderCache>,
        library_path: &[&Path],
        libmap: &str,
    ) -> std::io::Result<Config<'a>> {
        use search_path::SearchPathVecExt;
        let conf = tmpdir.path().join("libmap.conf");
        fs::write(&conf, libmap)?;
        let mut ld_library_path = search_path::SearchPathVec::new();
        for dir in library_path {
            ld_library_path.add_path(dir.to_str().unwrap());
        }
        Ok(Config {
            ld_preload: &[],
            ld_library_path,
            ld_cache,
            system_dirs: search_path::SearchPathVec::new(),
            platform: None,
            all: false,
            libmap: ld_libmap_freebsd::parse_libmap(&conf).map(RefCell::new),
        })
    }

    // The candidate file for NAME the FreeBSD rules take for the REFPATH
    // object: the fixture files are empty, which the candidate check fails
    // on, reporting their path.
    fn candidate(config: &Config, refpath: &str, name: &str, preload: bool) -> Option<String> {
        let elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        let name = name.to_string();
        let dep =
            FreeBsd::resolve_dependency(&name, config, &elc, refpath, &Default::default(), preload);
        match dep? {
            Err(e) => e.split(": ").next().map(str::to_string),
            Ok(dep) => panic!("{} resolved", dep.filename),
        }
    }

    // The dependency names and the search directories are mapped for the
    // requesting object, and a mapping of its section then applies to every
    // object, while a preloaded object name is not mapped.
    #[test]
    fn libmap_names_and_directories() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let (a, b) = (tmpdir.path().join("a"), tmpdir.path().join("b"));
        fs::create_dir(&a)?;
        fs::create_dir(&b)?;
        fs::write(a.join("libbar.so.1"), [])?;
        fs::write(b.join("libbaz.so.1"), [])?;
        let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());

        let ld_cache = None;
        let config = config(
            &tmpdir,
            &ld_cache,
            &[Path::new(a)],
            &format!(
                "[/bin/prog]\n\
                 libfoo.so.1 libbar.so.1\n\
                 libpath.so.1 {a}/libbar.so.1\n\
                 [/bin/dirprog]\n\
                 {a} {b}\n"
            ),
        )?;
        let bar = format!("{a}/libbar.so.1");
        let baz = format!("{b}/libbaz.so.1");

        assert_eq!(candidate(&config, "/bin/other", "libfoo.so.1", false), None);
        assert_eq!(
            candidate(&config, "/bin/prog", "libfoo.so.1", false),
            Some(bar.clone())
        );
        assert_eq!(
            candidate(&config, "/bin/other", "libfoo.so.1", false),
            Some(bar.clone())
        );
        assert_eq!(candidate(&config, "/bin/prog", "libfoo.so.1", true), None);
        assert_eq!(
            candidate(&config, "/bin/prog", "libpath.so.1", false),
            Some(bar)
        );

        assert_eq!(candidate(&config, "/bin/other", "libbaz.so.1", false), None);
        assert_eq!(
            candidate(&config, "/bin/dirprog", "libbaz.so.1", false),
            Some(baz.clone())
        );
        assert_eq!(
            candidate(&config, "/bin/other", "libbaz.so.1", true),
            Some(baz)
        );
        Ok(())
    }

    // DF_1_NODEFLIB skips the standard directories, and the hints ones that
    // are standard directories too.
    #[test]
    fn nodeflib_directories() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let a = tmpdir.path().join("a");
        fs::create_dir(&a)?;
        fs::write(a.join("libbar.so.1"), [])?;
        let a = a.to_str().unwrap();

        let ld_cache = None;
        let mut config = config(&tmpdir, &ld_cache, &[], "")?;
        config.system_dirs = search_path::fixed_list([a]);
        let mut elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        let name = "libbar.so.1".to_string();
        let resolve = |elc: &ElfInfo| {
            FreeBsd::resolve_dependency(
                &name,
                &config,
                elc,
                "/bin/prog",
                &Default::default(),
                false,
            )
            .is_some()
        };
        assert!(resolve(&elc));
        elc.nodeflibs = true;
        assert!(!resolve(&elc));

        let hints = search_path::fixed_list(["/lib", "/usr/local/lib", "/usr/lib"]);
        let standard = search_path::fixed_list(["/lib", "/usr/lib"]);
        let paths = |dirs: Vec<&search_path::SearchPath>| -> Vec<String> {
            dirs.into_iter().map(|dir| dir.path.clone()).collect()
        };
        assert_eq!(paths(gethints(&hints, &standard, true)), ["/usr/local/lib"]);
        assert_eq!(paths(gethints(&hints, &standard, false)).len(), 3);
        Ok(())
    }

    #[test]
    fn origin_subst_tokens() {
        let tokens = [
            ("ORIGIN", Some("/o")),
            ("OSNAME", Some("FreeBSD")),
            ("OSREL", Some("14.3-RELEASE")),
            ("PLATFORM", Some("amd64")),
            ("LIB", Some("lib32")),
        ];
        let cases = [
            ("$ORIGIN/../lib:${ORIGIN}", "/o/../lib:/o"),
            // The replacement ignores what follows the token.
            ("$ORIGINAL", "/oAL"),
            ("/$OSNAME/${OSREL}/$PLATFORM", "/FreeBSD/14.3-RELEASE/amd64"),
            ("/usr/$LIB", "/usr/lib32"),
            ("$FOO/$", "$FOO/$"),
        ];
        for (input, expanded) in cases {
            assert_eq!(origin_subst(input, &tokens), expanded, "{input}");
        }
        assert_eq!(
            origin_subst("$ORIGIN/$LIB", &[("ORIGIN", None), ("LIB", Some("lib"))]),
            "$ORIGIN/lib"
        );
    }

    // A candidate of another class, data encoding or machine, or which is not
    // an object, fails the load, whatever its OS ABI.
    #[test]
    fn candidate_mismatch_is_fatal() {
        let melc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        let check =
            |parsed: Result<ElfInfo, &'static str>| FreeBsd::check_candidate(&[], &parsed, &melc);
        let mut gnu = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        gnu.ei_osabi = ELFOSABI_GNU;
        assert_eq!(check(Ok(gnu)), Ok(()));
        let mut elf32 = ElfInfo::for_test(EM_386, FileFlags(0));
        elf32.ei_class = ELFCLASS32;
        let fatal = |e: &str| Err(Rejection::Fatal(e.to_string()));
        assert_eq!(check(Ok(elf32)), fatal("unsupported file layout"));
        assert_eq!(
            check(Ok(ElfInfo::for_test(EM_AARCH64, FileFlags(0)))),
            fatal("unsupported machine")
        );
        assert_eq!(check(Err("Invalid object")), fatal("Invalid object"));
    }

    // The lists are split on both separators, the DT_RPATH and DT_RUNPATH
    // ones expanded, and the dependency names only with a slash.
    #[test]
    fn search_lists() {
        let elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        let list = |list, site| -> Vec<String> {
            FreeBsd::search_list(list, site, &elc, None)
                .into_iter()
                .map(|entry| entry.unwrap())
                .collect()
        };
        assert_eq!(
            list(";$ORIGIN/a::/b;/$LIB", TokenSite::SearchPath),
            ["/o/a", "/b", "/lib"]
        );
        assert_eq!(
            list("$ORIGIN/a;/b", TokenSite::LibraryPath),
            ["$ORIGIN/a", "/b"]
        );
        let expand = |input, site| FreeBsd::expand_tokens(input, site, &elc, None);
        assert_eq!(
            expand("$ORIGIN/libx.so", TokenSite::Needed).as_deref(),
            Some("/o/libx.so")
        );
        assert_eq!(
            expand("lib$ORIGIN.so", TokenSite::Needed).as_deref(),
            Some("lib$ORIGIN.so")
        );
        assert_eq!(
            expand("$ORIGIN/libx.so", TokenSite::Preload).as_deref(),
            Some("$ORIGIN/libx.so")
        );
    }
}
