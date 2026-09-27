// The OpenBSD run-time linker.

use super::*;

pub(in crate::elf) struct OpenBsd;

impl Loader for OpenBsd {
    type Cache = search_path::SearchPathVec;

    // The _dl_load_shlib order: the LD_LIBRARY_PATH directories, the requesting
    // object DT_RUNPATH or, without one, its DT_RPATH followed by the main
    // program one, and at last the hints and the default directories.
    const SEARCH_ORDER: &'static [SearchStep] = &[
        SearchStep::LibraryPath,
        SearchStep::Runpath,
        SearchStep::Rpath,
        SearchStep::Cache,
        SearchStep::SystemDirs,
    ];

    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        _binary: &P,
        _ecl: &ElfInfo,
    ) {
        if ld_cache.is_none() {
            *ld_cache = ld_hints_openbsd::parse_ld_so_hints(&Path::new("/var/run/ld.so.hints")).ok()
        }
    }

    // _dl_find_shlib scans the hints directory list, and only without a valid
    // hints file the default /usr/lib.
    fn load_system_dirs(ld_cache: &Option<Self::Cache>) -> bool {
        ld_cache.is_none()
    }

    // Every list is split on colons and semicolons, skipping the empty entries
    // (_dl_split_path).
    fn search_list(
        list: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Vec<Result<String, String>> {
        list.split([':', ';'])
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                Self::expand_tokens(entry, site, elc, platform).ok_or_else(|| entry.to_string())
            })
            .collect()
    }

    // ld.so only expands the tokens of the DT_RPATH and DT_RUNPATH entries
    // (_dl_origin_subst), none at all when the object directory can not be
    // resolved.
    fn expand_tokens(
        input: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Option<String> {
        let origin = match (site, elc.origin.as_deref()) {
            (TokenSite::SearchPath, Some(origin)) => origin,
            _ => return Some(input.to_string()),
        };
        let [sysname, release, machine] = uname_values();
        let platform = platform.map(String::as_str).or(machine.as_deref());
        Some(origin_subst_path(input, |token| match token {
            "ORIGIN" => origin,
            "OSNAME" => sysname.as_deref().unwrap_or(""),
            "OSREL" => release.as_deref().unwrap_or(""),
            "PLATFORM" => platform.unwrap_or(""),
            _ => "",
        }))
    }

    fn origin_directory<P: AsRef<Path>>(filename: &P, _melc: Option<&ElfInfo>) -> Option<String> {
        canonical_origin_directory(filename)
    }

    // _dl_tryload_shlib fails the load of the file found unless it is an ELF
    // shared object (ET_DYN) of the loader machine, whatever its OS ABI.
    fn check_candidate(
        data: &[u8],
        parsed: &Result<ElfInfo, &'static str>,
        melc: &ElfInfo,
    ) -> Result<(), Rejection> {
        let e_type = data.get(16..18).map(|e_type| {
            let e_type = [e_type[0], e_type[1]];
            FileType(match DataEncoding(data[5]) {
                ELFDATA2MSB => u16::from_be_bytes(e_type),
                _ => u16::from_le_bytes(e_type),
            })
        });
        match parsed {
            Ok(elc) if e_type == Some(ET_DYN) && match_elf_header(melc, elc) => Ok(()),
            _ => Err(Rejection::Fatal("not an ELF shared object".to_string())),
        }
    }

    // The OpenBSD loader matches a library by name and major version, picking the best
    // minor available on the directory (even for the dlopen argument). Mimic it for
    // shared library inputs (executables are executed directly, with no redirection).
    fn redirect_root(
        filename: PathBuf,
        elc: ElfInfo,
        platform: Option<&String>,
    ) -> (PathBuf, ElfInfo) {
        if elc.interp.is_some() {
            return (filename, elc);
        }
        let (Some(dir), Some(name)) = (
            filename.parent().and_then(|p| p.to_str()),
            filename.file_name().and_then(|n| n.to_str()),
        ) else {
            return (filename, elc);
        };
        let candidate = Self::dependency_path(dir, name);
        if candidate != filename {
            if let Ok(nelc) = open_elf_file(&candidate, None, platform, false) {
                return (candidate, nelc);
            }
        }
        (filename, elc)
    }

    // The OpenBSD ldd lists the loader (/usr/libexec/ld.so) for executables (the
    // dlopen trace used for shared libraries does not show it).
    fn add_loader_dependency(
        _config: &Config,
        elc: &ElfInfo,
        deptree: &mut DepTree,
        root_depp: usize,
    ) {
        if let Some(interp) = &elc.interp {
            let path = Path::new(interp);
            if path.exists() {
                deptree.addnode(DepNode::from_path(&path, DepMode::Direct), root_depp);
            }
        }
    }

    // OpenBSD shared objects do not have a DT_SONAME and the DT_NEEDED entries carry
    // the full libname.so.major.minor name, with the loader matching the major version
    // and picking the best minor available on the directory.
    fn dependency_path(dir: &str, dtneeded: &str) -> PathBuf {
        fn parse_version(name: &str) -> Option<(&str, u64)> {
            let idx = name.find(".so.")?;
            let stem = &name[..idx + 3];
            // The version might be either major.minor or only the major.
            let major = match name[idx + 4..].split_once('.') {
                Some((major, minor)) => {
                    minor.parse::<u64>().ok()?;
                    major
                }
                None => &name[idx + 4..],
            };
            Some((stem, major.parse().ok()?))
        }

        if let Some((stem, major)) = parse_version(dtneeded) {
            let prefix = format!("{stem}.{major}.");
            let mut best: Option<(u64, PathBuf)> = None;
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Some(minor) = entry
                        .file_name()
                        .to_str()
                        .and_then(|filename| filename.strip_prefix(&prefix))
                        .and_then(|minor| minor.parse::<u64>().ok())
                    {
                        if best.as_ref().is_none_or(|(m, _)| minor > *m) {
                            best = Some((minor, entry.path()));
                        }
                    }
                }
            }
            if let Some((_, path)) = best {
                return path;
            }
        }
        Path::new(dir).join(dtneeded)
    }

    // An object with DT_RUNPATH only searches it: neither its own DT_RPATH nor
    // the main program one inherited are searched.
    fn rpath_search(elc: &ElfInfo) -> bool {
        !elc.has_runpath
    }

    // The executable DT_RPATH is kept even when it has DT_RUNPATH, as the
    // fallback of the libraries without DT_RUNPATH (_dl_finalize_object with
    // OBJTYPE_EXE).
    fn keep_main_rpath(elc: &ElfInfo) -> bool {
        elc.interp.is_some()
    }

    // The OpenBSD loader does not implement DF_1_NODEFLIB, so every step is
    // searched.
    fn nodeflib_rule(_step: SearchStep, _elc: &ElfInfo) -> NodeflibRule {
        NodeflibRule::Search
    }
}

// Expand the tokens of the INPUT entry the way _dl_origin_subst_path does,
// with VALUE giving the expansion of each name: a '$' followed by a name of
// letters, digits and underscores, which might be within braces, where an
// unknown name expands to nothing.
fn origin_subst_path<'a>(input: &str, value: impl Fn(&str) -> &'a str) -> String {
    let mut r = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find('$') {
        r.push_str(&rest[..pos]);
        let mut after = &rest[pos + 1..];
        let braced = after.starts_with('{');
        if braced {
            after = &after[1..];
        }
        let end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        r.push_str(value(&after[..end]));
        rest = &after[end..];
        if braced {
            rest = rest.strip_prefix('}').unwrap_or(rest);
        }
    }
    r.push_str(rest);
    r
}

// The uname(3) sysname, release and machine strings, which $OSNAME, $OSREL
// and $PLATFORM expand to.
#[cfg(target_os = "openbsd")]
fn uname_values() -> &'static [Option<String>; 3] {
    use std::ffi::{c_char, c_int};
    use std::sync::OnceLock;
    // The struct utsname fields, each of SYS_NMLN characters.
    const SYS_NMLN: usize = 256;
    extern "C" {
        fn uname(name: *mut [c_char; SYS_NMLN]) -> c_int;
    }
    static VALUES: OnceLock<[Option<String>; 3]> = OnceLock::new();
    VALUES.get_or_init(|| {
        let mut uts = [[0 as c_char; SYS_NMLN]; 5];
        // SAFETY: UTS has the layout of struct utsname, the five fields in
        // order.
        if unsafe { uname(uts.as_mut_ptr()) } != 0 {
            return [None, None, None];
        }
        let field = |field: &[c_char; SYS_NMLN]| {
            let bytes: Vec<u8> = field.iter().map(|&c| c as u8).collect();
            let value = bytes.split(|c| *c == 0).next()?;
            String::from_utf8(value.to_vec()).ok()
        };
        [field(&uts[0]), field(&uts[2]), field(&uts[4])]
    })
}

#[cfg(not(target_os = "openbsd"))]
fn uname_values() -> &'static [Option<String>; 3] {
    static VALUES: [Option<String>; 3] = [None, None, None];
    &VALUES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;

    // The executable keeps its DT_RPATH with DT_RUNPATH, which it does not
    // search itself.
    #[test]
    fn main_rpath_with_runpath() {
        let mut elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        elc.has_runpath = true;
        assert!(!OpenBsd::keep_main_rpath(&elc));
        elc.interp = Some("/usr/libexec/ld.so".to_string());
        assert!(OpenBsd::keep_main_rpath(&elc));
        assert!(!OpenBsd::rpath_search(&elc));
    }

    // A candidate that is not a shared object of the loader machine fails
    // the load, whatever its OS ABI.
    #[test]
    fn candidate_mismatch_is_fatal() {
        let header = |e_type: u16| {
            let mut data = vec![0u8; 64];
            data[..4].copy_from_slice(&ELFMAG);
            data[4] = ELFCLASS64.0;
            data[5] = ELFDATA2LSB.0;
            data[16..18].copy_from_slice(&e_type.to_le_bytes());
            data
        };
        let melc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        let mut gnu = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        gnu.ei_osabi = ELFOSABI_GNU;
        let fatal = Err(Rejection::Fatal("not an ELF shared object".to_string()));
        let check = |data: &[u8], parsed| OpenBsd::check_candidate(data, &parsed, &melc);
        assert_eq!(check(&header(ET_DYN.0), Ok(gnu)), Ok(()));
        assert_eq!(
            check(
                &header(ET_EXEC.0),
                Ok(ElfInfo::for_test(EM_X86_64, FileFlags(0)))
            ),
            fatal
        );
        assert_eq!(
            check(
                &header(ET_DYN.0),
                Ok(ElfInfo::for_test(EM_386, FileFlags(0)))
            ),
            fatal
        );
        assert_eq!(check(&[], Err("Invalid object")), fatal);
    }

    #[test]
    fn origin_subst_path_tokens() {
        let expand = |input| {
            origin_subst_path(input, |token| match token {
                "ORIGIN" => "/o",
                "OSNAME" => "OpenBSD",
                "OSREL" => "7.7",
                "PLATFORM" => "amd64",
                _ => "",
            })
        };
        let cases = [
            ("$ORIGIN/../lib", "/o/../lib"),
            ("${ORIGIN}/lib", "/o/lib"),
            ("${ORIGIN/lib", "/o/lib"),
            // The name ends at the first character that can not be part of
            // it, and an unknown one expands to nothing.
            ("$ORIGINAL/lib", "/lib"),
            ("/$OSNAME-$OSREL/$PLATFORM", "/OpenBSD-7.7/amd64"),
            ("/a/$/b/${}", "/a//b/"),
        ];
        for (input, expanded) in cases {
            assert_eq!(expand(input), expanded, "{input}");
        }
    }

    // The DT_RPATH and DT_RUNPATH entries alone expand their tokens, and the
    // lists are split on both separators.
    #[test]
    fn search_lists() {
        let elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        let list = |list, site| -> Vec<String> {
            OpenBsd::search_list(list, site, &elc, None)
                .into_iter()
                .map(|entry| entry.unwrap())
                .collect()
        };
        assert_eq!(
            list(";$ORIGIN/a::/b;", TokenSite::SearchPath),
            ["/o/a", "/b"]
        );
        assert_eq!(
            list("$ORIGIN/a;/b", TokenSite::LibraryPath),
            ["$ORIGIN/a", "/b"]
        );
        let mut unresolved = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        unresolved.origin = None;
        assert_eq!(
            OpenBsd::expand_tokens("$ORIGIN/a", TokenSite::SearchPath, &unresolved, None)
                .as_deref(),
            Some("$ORIGIN/a")
        );
    }

    #[test]
    fn nodeflib_ignored() {
        let elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        for step in OpenBsd::SEARCH_ORDER {
            assert_eq!(OpenBsd::nodeflib_rule(*step, &elc), NodeflibRule::Search);
        }
    }

    // The file picked in a directory: the major must match, and the highest
    // minor wins.
    #[test]
    fn dependency_minor_version() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        for name in [
            "libfoo.so.1.0",
            "libfoo.so.1.2",
            "libfoo.so.1.10",
            "libfoo.so.1.11.1",
            "libfoo.so.1.x",
            "libfoo.so.2.0",
            "libfoobar.so.1.20",
        ] {
            fs::write(tmpdir.path().join(name), [])?;
        }
        let dir = tmpdir.path().to_str().unwrap();
        let resolve = |dtneeded| pathutils::get_name(&OpenBsd::dependency_path(dir, dtneeded));

        assert_eq!(resolve("libfoo.so.1.1"), "libfoo.so.1.10");
        assert_eq!(resolve("libfoo.so.1.20"), "libfoo.so.1.10");
        assert_eq!(resolve("libfoo.so.1"), "libfoo.so.1.10");
        assert_eq!(resolve("libfoo.so.2.5"), "libfoo.so.2.0");
        // Without a match, the name as is.
        assert_eq!(resolve("libfoo.so.3.0"), "libfoo.so.3.0");
        assert_eq!(resolve("libfoo.so"), "libfoo.so");
        Ok(())
    }
}
