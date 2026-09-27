// The OpenBSD run-time linker.

use std::borrow::Cow;

use super::*;

pub(in crate::elf) struct OpenBsd;

impl Loader for OpenBsd {
    type Cache = ld_hints_openbsd::Hints;

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

    // The OpenBSD ldd dlopens a shared library, which ld.so matches in its
    // directory like any name with a slash (the hints are not loaded yet):
    // the best minor of the major, at least the one of the name, and then
    // any minor.  Executables are executed directly, with no redirection.
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
        let mut req = Sod::parse(name);
        let found = find_in_dir(dir, &req).or_else(|| {
            req.minor = -1;
            find_in_dir(dir, &req)
        });
        if let Some((name, _)) = found {
            let candidate = Path::new(dir).join(name);
            if candidate != filename {
                if let Ok(nelc) = open_elf_file(&candidate, None, platform, false) {
                    return (candidate, nelc);
                }
            }
        }
        (filename, elc)
    }

    // _dl_find_loaded_shlib: a name without a slash matches a loaded object
    // of the same name and major, with a minor at least the requested one,
    // and then with any minor, with a warning.
    fn find_loaded(name: &str, deptree: &DepTree) -> Option<usize> {
        if name.contains('/') {
            return None;
        }
        let requested = Sod::parse(name);
        let loaded: Vec<(usize, Sod)> = deptree
            .arena
            .iter()
            .enumerate()
            .filter(|(_, node)| !node.val.found && node.val.mode != DepMode::NotFound)
            .map(|(index, node)| (index, Sod::parse(&node.val.name)))
            .collect();
        let lookup = |req: &Sod| loaded.iter().find(|(_, sod)| req.matches(sod));
        if let Some((index, _)) = lookup(&requested) {
            return Some(*index);
        }
        if !requested.library || requested.minor == -1 {
            return None;
        }
        let (index, found) = lookup(&Sod {
            minor: -1,
            ..requested.clone()
        })?;
        minor_warning(&requested, found);
        Some(*index)
    }

    // _dl_load_shlib: a name with a slash is matched in its directory, and a
    // name without one is first matched against the loaded objects (see
    // find_loaded), and then searched on the LD_LIBRARY_PATH directories, the
    // requesting object DT_RUNPATH or, without one, its DT_RPATH and the main
    // program one, and at last the standard locations.  The search is made
    // twice: first with the hints and for a minor version at least the one of
    // the name, and then without the hints for any minor version, with a
    // warning.  The file found is loaded, or the load fails, without going on
    // with the search.
    fn resolve_dependency<'a>(
        dependency: &'a String,
        config: &'a Config,
        elc: &'a ElfInfo,
        _refpath: &str,
        namespace: &ObjectNamespace,
        _preload: bool,
    ) -> Option<Resolution<'a>> {
        let hints = config.ld_cache.as_ref();
        let (lists, name) = match dependency.rsplit_once('/') {
            Some((_, "")) => return None,
            Some((dir, name)) => (vec![SearchList::Path(dir)], name),
            None => {
                let mut lists = vec![SearchList::Dirs(
                    &config.ld_library_path,
                    DepMode::LdLibraryPath,
                )];
                if elc.has_runpath {
                    lists.push(SearchList::Dirs(&elc.runpath, DepMode::DtRunpath));
                } else {
                    lists.push(SearchList::Dirs(&elc.rpath, DepMode::DtRpath));
                }
                lists.push(SearchList::Standard(&config.system_dirs));
                (lists, dependency.as_str())
            }
        };

        let requested = Sod::parse(name);
        let mut req = requested.clone();
        for with_hints in [true, false] {
            if !with_hints {
                req.minor = -1;
            }
            for list in &lists {
                let Some((dir, file, mode, found)) = find_shlib(&req, list, hints, with_hints)
                else {
                    continue;
                };
                minor_warning(&requested, &found);
                return Some(tryload(dir, &file, elc, config, mode, namespace));
            }
        }
        None
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

// The shared object description of a name (_dl_build_sod): the NAME of a
// libNAME.so[.MAJOR[.MINOR]] library, with -1 for an absent version, or any
// other name as is, with the versions 0.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Sod {
    name: String,
    library: bool,
    major: i32,
    minor: i32,
}

impl Sod {
    fn parse(name: &str) -> Sod {
        Self::parse_library(name).unwrap_or_else(|| Sod {
            name: name.to_string(),
            library: false,
            major: 0,
            minor: 0,
        })
    }

    fn parse_library(name: &str) -> Option<Sod> {
        let rest = name.strip_prefix("lib")?;
        if name.contains('/') || !rest.contains('.') || rest.ends_with('.') {
            return None;
        }
        let so = rest.find(".so")?;
        let mut sod = Sod {
            name: rest[..so].to_string(),
            library: true,
            major: -1,
            minor: -1,
        };
        // The dot separated parts from the one of ".so": an empty one, the
        // one of "so" (whatever follows it), the major, and the minor.
        for (part, version) in rest[so..].split('.').enumerate() {
            match part {
                0 | 1 => {}
                2 => sod.major = version.parse().ok()?,
                3 => sod.minor = version.parse().ok()?,
                _ => return None,
            }
        }
        Some(sod)
    }

    // _dl_match_file: the description of the FILE name matching the REQ
    // requested one: the same name, and the same major and at least the minor
    // when requested.
    fn match_file(req: &Sod, file: &str) -> Option<Sod> {
        let name = if req.library {
            file.strip_prefix("lib")?
        } else {
            file
        };
        if !name.starts_with(&req.name) {
            return None;
        }
        let sod = Sod::parse(file);
        req.matches(&sod).then_some(sod)
    }

    // Whether the SOD object description matches this requested one
    // (_dl_cmp_sod): the same name, and the same major and at least the minor
    // when requested.
    fn matches(&self, sod: &Sod) -> bool {
        sod.name == self.name
            && sod.library == self.library
            && (self.major == -1 || self.major == sod.major)
            && (self.minor == -1 || sod.minor >= self.minor)
    }
}

// The warning ld.so prints when it takes the FOUND version of the REQUESTED
// library, of a lower minor.
fn minor_warning(requested: &Sod, found: &Sod) {
    if found.minor < requested.minor {
        errln!(
            "warning: lib{}.so.{}.{}: minor version >= {} expected, using it anyway",
            requested.name,
            requested.major,
            found.minor,
            requested.minor
        );
    }
}

// The best match of the REQ description among the NAMES of a directory, in
// their order (_dl_find_shlib): an unversioned library is taken at once, and
// otherwise the highest major, and then the highest minor, the first one on
// a tie.
fn best_match<'n>(req: &Sod, names: impl IntoIterator<Item = &'n str>) -> Option<(&'n str, Sod)> {
    let mut best: Option<(&str, Sod)> = None;
    for name in names {
        let Some(sod) = Sod::match_file(req, name) else {
            continue;
        };
        let better = match &best {
            None => true,
            Some((_, best)) => {
                sod.major == -1
                    || sod.major > best.major
                    || (sod.major == best.major && sod.minor > best.minor)
            }
        };
        if better {
            let unversioned = sod.major == -1;
            best = Some((name, sod));
            if unversioned {
                break;
            }
        }
    }
    best
}

// The best match of REQ in the DIR directory, in the readdir order.
fn find_in_dir(dir: &str, req: &Sod) -> Option<(String, Sod)> {
    let names: Vec<String> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    best_match(req, names.iter().map(String::as_str)).map(|(name, sod)| (name.to_string(), sod))
}

// A list _dl_find_shlib searches.
enum SearchList<'a> {
    // The directory of a name with a slash.
    Path(&'a str),
    // A search list, whose objects are shown with the mode given.
    Dirs(&'a search_path::SearchPathVec, DepMode),
    // The standard locations: any hint, and then the hints directory list,
    // or the default directories given without a valid hints file.
    Standard(&'a search_path::SearchPathVec),
}

// _dl_find_shlib: the directory, the file name, the mode, and the description
// of the object matching REQ on LIST, the HINTS file giving the directories of
// the standard locations, and its hash table searched first when WITH_HINTS
// is set.
fn find_shlib<'a>(
    req: &Sod,
    list: &SearchList<'a>,
    hints: Option<&'a impl SearchCache>,
    with_hints: bool,
) -> Option<(Cow<'a, str>, String, DepMode, Sod)> {
    if let Some(hints) = hints.filter(|_| with_hints) {
        let hint = |dir: Option<&str>| hints.hint(&req.name, req.major, req.minor, dir);
        let hint = match list {
            SearchList::Path(dir) => hint(Some(dir)).map(|path| (path, DepMode::Direct)),
            SearchList::Dirs(dirs, mode) => dirs
                .iter()
                .find_map(|dir| hint(Some(&dir.path)))
                .map(|path| (path, *mode)),
            SearchList::Standard(_) => hint(None).map(|path| (path, DepMode::LdCache)),
        };
        if let Some((path, mode)) = hint {
            let (dir, file) = path.rsplit_once('/')?;
            return Some((Cow::Borrowed(dir), file.to_string(), mode, req.clone()));
        }
    }
    let dirs: Vec<(&'a str, DepMode)> = match list {
        SearchList::Path(dir) => vec![(dir, DepMode::Direct)],
        SearchList::Dirs(dirs, mode) => dirs.iter().map(|dir| (dir.path.as_str(), *mode)).collect(),
        SearchList::Standard(system_dirs) => match hints.and_then(|hints| hints.directories()) {
            Some(dirs) => dirs
                .iter()
                .map(|dir| (dir.path.as_str(), DepMode::LdCache))
                .collect(),
            None => system_dirs
                .iter()
                .map(|dir| (dir.path.as_str(), DepMode::SystemDirs))
                .collect(),
        },
    };
    dirs.into_iter().find_map(|(dir, mode)| {
        let (file, sod) = find_in_dir(dir, req)?;
        Some((Cow::Borrowed(dir), file, mode, sod))
    })
}

// _dl_tryload_shlib: load the FILE of the DIR directory, which fails the load
// when it can not be opened, or is not an object ld.so loads.
fn tryload<'a>(
    dir: Cow<'a, str>,
    file: &str,
    elc: &ElfInfo,
    config: &Config,
    mode: DepMode,
    namespace: &ObjectNamespace,
) -> Resolution<'a> {
    let path = pathutils::join(&dir, file);
    match search_dir(dir, file, elc, config.platform, mode, namespace) {
        // The object of a name with a slash is shown by its path.
        Some(Ok(mut dep)) if mode == DepMode::Direct => {
            dep.path = Cow::Owned(path);
            Ok(dep)
        }
        Some(resolution) => resolution,
        None => Err(format!("{path}: cannot open")),
    }
}

// The hints file: its directory list, along with the library hints.
impl SearchCache for ld_hints_openbsd::Hints {
    type Namespace = NoNamespace;

    fn summary(&self) -> String {
        search_path::format_list(&self.dirs)
    }

    fn resolve<'a>(
        &'a self,
        dtneeded: &str,
        platform: Option<&String>,
        elc: &'a ElfInfo,
        _namespace: &NoNamespace,
    ) -> Option<Resolution<'a>> {
        search_dirs(
            &self.dirs,
            dtneeded,
            elc,
            platform,
            DepMode::LdCache,
            &Default::default(),
        )
    }

    fn directories(&self) -> Option<&search_path::SearchPathVec> {
        Some(&self.dirs)
    }

    fn hint(&self, name: &str, major: i32, minor: i32, dir: Option<&str>) -> Option<&str> {
        self.find(name, major, minor, dir)
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

    fn sod(name: &str, library: bool, major: i32, minor: i32) -> Sod {
        Sod {
            name: name.to_string(),
            library,
            major,
            minor,
        }
    }

    #[test]
    fn build_sod() {
        let cases = [
            ("libfoo.so.1.2", sod("foo", true, 1, 2)),
            ("libfoo.so.1", sod("foo", true, 1, -1)),
            ("libfoo.so", sod("foo", true, -1, -1)),
            ("libfoo.bar.so.3.4", sod("foo.bar", true, 3, 4)),
            // Whatever follows ".so" is not checked.
            ("libfoo.sox.1", sod("foo", true, 1, -1)),
            // Anything else is a plain name.
            ("libfoo.so.1.2.3", sod("libfoo.so.1.2.3", false, 0, 0)),
            ("libfoo.so.x", sod("libfoo.so.x", false, 0, 0)),
            ("libfoo.so.", sod("libfoo.so.", false, 0, 0)),
            ("libfoo", sod("libfoo", false, 0, 0)),
            ("foo.so.1", sod("foo.so.1", false, 0, 0)),
        ];
        for (name, sod) in cases {
            assert_eq!(Sod::parse(name), sod, "{name}");
        }
    }

    // The best file of a directory: the major must match and the minor be
    // at least the one requested, where the highest major and then minor
    // wins, and an unversioned library at once.
    #[test]
    fn best_file() {
        let names = [
            "libfoo.so.1.0",
            "libfoo.so.1.10",
            "libfoo.so.1.2",
            "libfoo.so.1.11.1",
            "libfoo.so.1.x",
            "libfoo.so.2.0",
            "libfoobar.so.1.20",
            "foo.so",
        ];
        let best = |name, names: &[&'static str]| {
            best_match(&Sod::parse(name), names.iter().copied()).map(|(name, _)| name)
        };
        assert_eq!(best("libfoo.so.1.1", &names), Some("libfoo.so.1.10"));
        assert_eq!(best("libfoo.so.1.20", &names), None);
        assert_eq!(best("libfoo.so.1", &names), Some("libfoo.so.1.10"));
        assert_eq!(best("libfoo.so.2.5", &names), None);
        assert_eq!(best("libfoo.so", &names), Some("libfoo.so.2.0"));
        assert_eq!(
            best(
                "libfoo.so",
                &["libfoo.so.3.0", "libfoo.so", "libfoo.so.4.0"]
            ),
            Some("libfoo.so")
        );
        assert_eq!(best("foo.so", &names), Some("foo.so"));
        assert_eq!(best("foo.so.1", &names), None);
    }

    // The objects of a name, found in their search order, where the fixture
    // files are empty, which the candidate check fails on, reporting their
    // path.
    #[test]
    fn search_two_passes() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let dir = |name: &str, files: &[&str]| -> std::io::Result<String> {
            let dir = tmpdir.path().join(name);
            fs::create_dir(&dir)?;
            for file in files {
                fs::write(dir.join(file), [])?;
            }
            Ok(dir.to_str().unwrap().to_string())
        };
        let a = dir("a", &["libfoo.so.1.0"])?;
        let b = dir("b", &["libfoo.so.1.5"])?;
        let c = dir("c", &["libbar.so.2.0", "libbar.so.3.1"])?;
        let d = dir("d", &["libfoo.so.1.9"])?;

        let ld_cache = None;
        let config = Config {
            ld_preload: &[],
            ld_library_path: search_path::from_string(format!("{a}:{b}:{c}"), &[':']),
            ld_cache: &ld_cache,
            system_dirs: search_path::SearchPathVec::new(),
            platform: None,
            all: false,
            #[cfg(any(target_os = "freebsd", all(test, target_os = "linux")))]
            libmap: None,
        };
        let mut elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        elc.runpath = search_path::from_string(&d, &[':']);
        let candidate = |elc: &ElfInfo, name: &str| {
            let name = name.to_string();
            let dep =
                OpenBsd::resolve_dependency(&name, &config, elc, "", &Default::default(), false)?;
            let error = dep.expect_err("empty object loaded");
            error.split(": ").next().map(str::to_string)
        };

        // A minor high enough in any directory, and then any minor.
        assert_eq!(
            candidate(&elc, "libfoo.so.1.3"),
            Some(format!("{b}/libfoo.so.1.5"))
        );
        assert_eq!(
            candidate(&elc, "libfoo.so.1.7"),
            Some(format!("{a}/libfoo.so.1.0"))
        );
        assert_eq!(
            candidate(&elc, "libbar.so"),
            Some(format!("{c}/libbar.so.3.1"))
        );
        assert_eq!(candidate(&elc, "libbaz.so.1.0"), None);
        // A name with a slash is matched in its directory.
        assert_eq!(
            candidate(&elc, &format!("{d}/libfoo.so.1.3")),
            Some(format!("{d}/libfoo.so.1.9"))
        );
        // DT_RUNPATH instead of DT_RPATH.
        elc.has_runpath = true;
        assert_eq!(
            candidate(&elc, "libfoo.so.1.7"),
            Some(format!("{d}/libfoo.so.1.9"))
        );
        Ok(())
    }

    // A loaded library of the name and major, with a minor high enough, and
    // then any minor.
    #[test]
    fn loaded_library() {
        let mut deptree = DepTree::new();
        let root = deptree.addroot(DepNode::new(None, "prog".to_string(), DepMode::Executable));
        let lib = |name: &str| {
            DepNode::new(
                Some("/usr/lib".to_string()),
                name.to_string(),
                DepMode::SystemDirs,
            )
        };
        deptree.addnode(
            DepNode::not_found("libbar.so.1.0".to_string(), Vec::new()),
            root,
        );
        deptree.addnode(lib("libfoo.so.2.3").already_found(), root);
        let foo = deptree.addnode(lib("libfoo.so.2.3"), root);
        let baz = deptree.addnode(lib("libbaz.so.1.0"), root);
        let find = |name| OpenBsd::find_loaded(name, &deptree);
        assert_eq!(find("libfoo.so.2.1"), Some(foo));
        assert_eq!(find("libfoo.so.2"), Some(foo));
        assert_eq!(find("libfoo.so.2.7"), Some(foo));
        assert_eq!(find("libfoo.so.3.0"), None);
        assert_eq!(find("libbar.so.1.0"), None);
        assert_eq!(find("libbaz.so"), Some(baz));
        assert_eq!(find("/usr/lib/libfoo.so.2.3"), None);
    }

    // The hints first, for the directories of the list, or anywhere for the
    // standard locations, which are otherwise the hints directory list.
    #[test]
    fn search_hints() -> std::io::Result<()> {
        let tmpdir = TempDir::new()?;
        let a = tmpdir.path().join("a");
        fs::create_dir(&a)?;
        fs::write(a.join("libfoo.so.1.2"), [])?;
        let a = a.to_str().unwrap();
        let hints = ld_hints_openbsd::Hints::with_libraries(
            search_path::from_string(a, &[':']),
            &[("foo", "/usr/local/lib/libfoo.so.1.5", 1, 5)],
        );
        let found = |list: &SearchList, name: &str, with_hints| {
            find_shlib(&Sod::parse(name), list, Some(&hints), with_hints)
                .map(|(dir, file, _, _)| format!("{dir}/{file}"))
        };
        let standard = search_path::SearchPathVec::new();
        let dirs = search_path::fixed_list(["/usr/local/lib"]);
        assert_eq!(
            found(&SearchList::Standard(&standard), "libfoo.so.1.3", true).as_deref(),
            Some("/usr/local/lib/libfoo.so.1.5")
        );
        assert_eq!(
            found(&SearchList::Standard(&standard), "libfoo.so.1.0", false),
            Some(format!("{a}/libfoo.so.1.2"))
        );
        assert_eq!(
            found(
                &SearchList::Dirs(&dirs, DepMode::DtRpath),
                "libfoo.so.1.0",
                true
            )
            .as_deref(),
            Some("/usr/local/lib/libfoo.so.1.5")
        );
        assert_eq!(
            found(
                &SearchList::Dirs(&dirs, DepMode::DtRpath),
                "libfoo.so.1.6",
                true
            ),
            None
        );
        Ok(())
    }
}
