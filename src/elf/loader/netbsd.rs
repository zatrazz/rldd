// The NetBSD run-time linker.

use super::*;

pub(in crate::elf) struct NetBsd;

impl Loader for NetBsd {
    type Cache = search_path::SearchPathVec;

    // The NetBSD loader searches the LD_LIBRARY_PATH directories, then the
    // ld.so.conf ones, then the requesting object DT_RPATH/DT_RUNPATH, and at last
    // the default directories.
    const SEARCH_ORDER: &'static [SearchStep] = &[
        SearchStep::LibraryPath,
        SearchStep::Cache,
        SearchStep::Rpath,
        SearchStep::SystemDirs,
    ];

    // The ld.so.conf directories expand the tokens for the executable (its
    // $ORIGIN included), so the file is read again for each input object.
    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        _binary: &P,
        elc: &ElfInfo,
    ) {
        *ld_cache = ld_so_conf_netbsd::parse_ld_so_conf(&Path::new("/etc/ld.so.conf"), |dir| {
            Self::expand_tokens(dir, TokenSite::LibraryPath, elc, None)
        })
        .ok()
    }

    // The NetBSD loader expands the tokens of the DT_RPATH and DT_RUNPATH
    // lists, with $ORIGIN the directory of the object, and of the
    // LD_LIBRARY_PATH and ld.so.conf ones, with the executable directory
    // (_rtld_add_paths), but not the ones of the dependency or preload names.
    // An entry that expands to nothing is dropped (_rtld_append_path).
    fn expand_tokens(
        input: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Option<String> {
        if matches!(site, TokenSite::Needed | TokenSite::Preload) {
            return Some(input.to_string());
        }
        let [osname, osrel, machine_arch] = system_values();
        let platform = match platform {
            Some(platform) => Some(platform.as_str()),
            None => machine_arch
                .as_deref()
                .map(|arch| compat_machine_arch(arch, elc)),
        };
        let expanded = expand_path(input, |token| match token {
            "ORIGIN" => elc.origin.as_deref(),
            "OSNAME" => Some(osname.as_deref().unwrap_or("")),
            "OSREL" => Some(osrel.as_deref().unwrap_or("")),
            "PLATFORM" => Some(platform.unwrap_or("")),
            // $HWCAP and $ISALIST are not implemented, and expand to nothing.
            _ => Some(""),
        })?;
        (!expanded.is_empty()).then_some(expanded)
    }

    // The NetBSD loader records DT_RPATH and DT_RUNPATH in the same slot, so
    // the last entry of either wins (_rtld_digest_dynamic), searched as the
    // object rpath.
    fn handle_search_paths(elc: &mut ElfInfo) {
        single_search_list(elc);
    }

    // The NetBSD loader does not check the EI_OSABI field.
    fn check_elf_header(_elc: &ElfInfo) -> bool {
        true
    }

    // The NetBSD loader does not implement DF_1_NODEFLIB (_rtld_digest_dynamic
    // only reads DF_1_NOW, DF_1_NODELETE, DF_1_INITFIRST and DF_1_NOOPEN), so
    // every step is searched.
    fn nodeflib_rule(_step: SearchStep, _elc: &ElfInfo) -> NodeflibRule {
        NodeflibRule::Search
    }
}

// The tokens _rtld_expand_path knows, in the order it tries them.
const TOKENS: [&str; 6] = ["HWCAP", "ISALIST", "ORIGIN", "OSNAME", "OSREL", "PLATFORM"];

// Expand the tokens of INPUT the way _rtld_expand_path does, with VALUE giving
// the expansion of each one (None when it can not be expanded): a $NAME not
// followed by a letter or a ${NAME} of a known token, any other '$' being
// kept as written.
fn expand_path<'a>(input: &str, value: impl Fn(&str) -> Option<&'a str>) -> Option<String> {
    let mut r = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find('$') {
        r.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let braced = after.starts_with('{');
        let name = if braced { &after[1..] } else { after };
        let token = TOKENS.iter().find(|token| {
            let next = name.strip_prefix(**token).map(|next| next.bytes().next());
            match next {
                Some(next) if braced => next == Some(b'}'),
                Some(next) => !next.is_some_and(|c| c.is_ascii_alphabetic()),
                None => false,
            }
        });
        match token {
            Some(token) => {
                r.push_str(value(token)?);
                rest = &name[token.len() + usize::from(braced)..];
            }
            None => {
                r.push('$');
                rest = after;
            }
        }
    }
    r.push_str(rest);
    Some(r)
}

// The kern.ostype, kern.osrelease and hw.machine_arch values the tokens
// expand to.
#[cfg(target_os = "netbsd")]
fn system_values() -> &'static [Option<String>; 3] {
    use std::sync::OnceLock;
    static VALUES: OnceLock<[Option<String>; 3]> = OnceLock::new();
    VALUES
        .get_or_init(|| [c"kern.ostype", c"kern.osrelease", c"hw.machine_arch"].map(sysctl_string))
}

#[cfg(not(target_os = "netbsd"))]
fn system_values() -> &'static [Option<String>; 3] {
    static VALUES: [Option<String>; 3] = [None, None, None];
    &VALUES
}

// The hw.machine_arch of the loader of ELC, where the 32-bit compat loaders
// of the 64-bit ARCH systems get the netbsd32 value (machine_arch32).  Only the
// ports where it is a constant are known.
fn compat_machine_arch<'a>(arch: &'a str, elc: &ElfInfo) -> &'a str {
    if elc.ei_class != ELFCLASS32 {
        return arch;
    }
    match (arch, elc.e_machine) {
        ("x86_64", EM_386) => "i386",
        ("sparc64", EM_SPARC | EM_SPARC32PLUS) => "sparc",
        ("powerpc64", EM_PPC) => "powerpc",
        _ => arch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(rpath: &[&str], runpath: &[&str], runpath_last: bool) -> ElfInfo {
        let mut elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        elc.rpath = search_path::fixed_list(rpath.iter().copied());
        elc.runpath = search_path::fixed_list(runpath.iter().copied());
        elc.has_runpath = !runpath.is_empty();
        elc.runpath_last = runpath_last;
        elc
    }

    // A single rpath list, from the last of the DT_RPATH and DT_RUNPATH
    // entries.
    #[test]
    fn last_search_list_entry_wins() {
        for (mut elc, rpath) in [
            (object(&["/r"], &["/u"], true), "/u"),
            (object(&["/r"], &["/u"], false), "/r"),
            (object(&[], &["/u"], true), "/u"),
            (object(&["/r"], &[], false), "/r"),
        ] {
            NetBsd::handle_search_paths(&mut elc);
            assert_eq!(elc.rpath, search_path::fixed_list([rpath]));
            assert!(elc.runpath.is_empty());
            assert!(!elc.has_runpath);
        }
    }

    #[test]
    fn nodeflib_ignored() {
        let elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        for step in NetBsd::SEARCH_ORDER {
            assert_eq!(NetBsd::nodeflib_rule(*step, &elc), NodeflibRule::Search);
        }
    }

    #[test]
    fn expand_path_tokens() {
        let expand = |input| {
            expand_path(input, |token| match token {
                "ORIGIN" => Some("/o"),
                "OSNAME" => Some("NetBSD"),
                "OSREL" => Some("10.1"),
                "PLATFORM" => Some("x86_64"),
                _ => Some(""),
            })
        };
        let cases = [
            ("$ORIGIN/lib", "/o/lib"),
            ("${ORIGIN}/lib", "/o/lib"),
            // Only a letter after the name makes it another one.
            ("$ORIGIN1", "/o1"),
            ("$ORIGINAL", "$ORIGINAL"),
            ("${ORIGIN", "${ORIGIN"),
            ("${ORIGIN}}", "/o}"),
            ("/lib/$OSNAME-${OSREL}/$PLATFORM", "/lib/NetBSD-10.1/x86_64"),
            ("/x/$HWCAP/${ISALIST}", "/x//"),
            ("$LIB/$", "$LIB/$"),
        ];
        for (input, expanded) in cases {
            assert_eq!(expand(input).as_deref(), Some(expanded), "{input}");
        }
        assert_eq!(expand_path("/a/$ORIGIN", |_| None), None);
        assert_eq!(expand_path("/a/$LIB", |_| None).as_deref(), Some("/a/$LIB"));
    }

    // The tokens of the search lists, but not the ones of the dependency
    // names, where an entry expanding to nothing is dropped.
    #[test]
    fn expand_token_sites() {
        let elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        let expand = |input, site, platform: Option<&str>| {
            let platform = platform.map(str::to_string);
            NetBsd::expand_tokens(input, site, &elc, platform.as_ref())
        };
        assert_eq!(
            expand("$ORIGIN/../lib", TokenSite::SearchPath, None).as_deref(),
            Some("/o/../lib")
        );
        assert_eq!(
            expand("$ORIGIN/lib", TokenSite::LibraryPath, None).as_deref(),
            Some("/o/lib")
        );
        assert_eq!(
            expand("$ORIGIN/libx.so", TokenSite::Needed, None).as_deref(),
            Some("$ORIGIN/libx.so")
        );
        assert_eq!(
            expand("/lib/$PLATFORM", TokenSite::SearchPath, Some("i386")).as_deref(),
            Some("/lib/i386")
        );
        assert_eq!(expand("$HWCAP", TokenSite::SearchPath, None), None);
    }

    #[test]
    fn compat_platform() {
        let mut elc = ElfInfo::for_test(EM_386, FileFlags(0));
        elc.ei_class = ELFCLASS32;
        assert_eq!(compat_machine_arch("x86_64", &elc), "i386");
        let elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        assert_eq!(compat_machine_arch("x86_64", &elc), "x86_64");
    }

    // A library expands $ORIGIN to the directory of the path it was found
    // at, whatever object loads it.
    #[test]
    fn origin_of_the_object() {
        let melc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        assert_eq!(
            NetBsd::origin_directory(&"/usr/pkg/lib/../lib/libx.so.1", Some(&melc)).as_deref(),
            Some("/usr/pkg/lib/../lib")
        );
    }
}
