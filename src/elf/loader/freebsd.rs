// The FreeBSD run-time linker.

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

    // Remap the dependency name using the libmap.conf mappings for the referencing
    // object path.
    fn libmap_dependency(config: &Config, refpath: &str, dependency: &String) -> String {
        match &config.libmap {
            Some(libmap) => libmap
                .lookup(refpath, dependency)
                .map(|target| target.to_string())
                .unwrap_or_else(|| dependency.to_string()),
            None => dependency.to_string(),
        }
    }
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
