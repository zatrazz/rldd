// The illumos and Solaris run-time linker.

use super::*;

pub(in crate::elf) struct Solaris;

impl Loader for Solaris {
    type Cache = search_path::SearchPathVec;

    // The illumos loader searches the LD_LIBRARY_PATH directories, then the
    // requesting object DT_RUNPATH or DT_RPATH, and at last the default
    // directories: the get_next_dir search_rules, without the crle(1)
    // configuration ones.
    const SEARCH_ORDER: &'static [SearchStep] = &[
        SearchStep::LibraryPath,
        SearchStep::Rpath,
        SearchStep::SystemDirs,
    ];

    // The illumos loader records DT_RPATH and DT_RUNPATH in the same slot
    // (RPATH), so the last entry of either wins (elf_new_lmp), searched as the
    // object rpath.
    fn handle_search_paths(elc: &mut ElfInfo) {
        single_search_list(elc);
    }

    // The illumos loader splits a search list on colons and semicolons, where
    // an empty entry is the current directory, and makes an entry with
    // $ISALIST one for each instruction set (expand_paths).  The tokens of
    // the LD_LIBRARY_PATH list are expanded too.
    fn search_list(
        list: &str,
        _site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Vec<Result<String, String>> {
        expand_list(list, &TokenValues::new(elc, platform))
    }

    // The illumos loader expands the tokens of the dependency and preload
    // names too, where $ISALIST is the first instruction set.
    fn expand_tokens(
        input: &str,
        _site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Option<String> {
        expand_entry(input, &TokenValues::new(elc, platform), None).map(|(entry, _)| entry)
    }

    // The illumos loader expands $ORIGIN to the directory of the object
    // resolved path (fullpath, with resolvepath(2)).
    fn origin_directory<P: AsRef<Path>>(filename: &P, _melc: Option<&ElfInfo>) -> Option<String> {
        canonical_origin_directory(filename)
    }

    fn check_elf_header(elc: &ElfInfo) -> bool {
        elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_SOLARIS
    }

    // DF_1_NODEFLIB only skips the default directories (the DEFAULT rule of
    // get_dir_list), and the illumos rules have no cache.
    fn nodeflib_rule(step: SearchStep, _elc: &ElfInfo) -> NodeflibRule {
        match step {
            SearchStep::SystemDirs => NodeflibRule::Skip,
            _ => NodeflibRule::Search,
        }
    }
}

// The values of the system tokens: the sysinfo(2) SI_PLATFORM (uname -i),
// SI_MACHINE (uname -m), SI_SYSNAME and SI_RELEASE (uname -s and -r) strings,
// and the SI_ISALIST instruction sets, which the kernel returns whatever the
// data model of the caller.
struct SystemValues {
    platform: Option<String>,
    machine: Option<String>,
    osname: Option<String>,
    osrel: Option<String>,
    isalist: Vec<String>,
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn system_values() -> &'static SystemValues {
    use std::sync::OnceLock;
    const SI_SYSNAME: std::ffi::c_int = 1;
    const SI_RELEASE: std::ffi::c_int = 3;
    const SI_MACHINE: std::ffi::c_int = 5;
    const SI_PLATFORM: std::ffi::c_int = 513;
    const SI_ISALIST: std::ffi::c_int = 514;
    static VALUES: OnceLock<SystemValues> = OnceLock::new();
    VALUES.get_or_init(|| SystemValues {
        platform: sysinfo_string(SI_PLATFORM),
        machine: sysinfo_string(SI_MACHINE),
        osname: sysinfo_string(SI_SYSNAME),
        osrel: sysinfo_string(SI_RELEASE),
        isalist: sysinfo_string(SI_ISALIST)
            .map(|list| list.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
    })
}

#[cfg(not(any(target_os = "illumos", target_os = "solaris")))]
fn system_values() -> &'static SystemValues {
    static VALUES: SystemValues = SystemValues {
        platform: None,
        machine: None,
        osname: None,
        osrel: None,
        isalist: Vec::new(),
    };
    &VALUES
}

// The COMMAND sysinfo(2) string.
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn sysinfo_string(command: std::ffi::c_int) -> Option<String> {
    use std::ffi::{c_char, c_int, c_long};
    extern "C" {
        fn sysinfo(command: c_int, buf: *mut c_char, count: c_long) -> c_int;
    }
    let mut buf = vec![0u8; 257];
    loop {
        // SAFETY: BUF is valid for the length the call is given.
        let size = unsafe { sysinfo(command, buf.as_mut_ptr().cast(), buf.len() as c_long) };
        // The size the whole string needs, which might be larger than BUF.
        let size = usize::try_from(size).ok()?;
        if size > buf.len() {
            buf.resize(size, 0);
            continue;
        }
        let value = buf.split(|c| *c == 0).next()?;
        return String::from_utf8(value.to_vec()).ok();
    }
}

// The token values for the ELC object.
struct TokenValues<'a> {
    origin: Option<&'a str>,
    platform: Option<&'a str>,
    machine: Option<&'a str>,
    osname: Option<&'a str>,
    osrel: Option<&'a str>,
    isalist: &'a [String],
}

impl<'a> TokenValues<'a> {
    fn new(elc: &'a ElfInfo, platform: Option<&'a String>) -> Self {
        let values = system_values();
        Self {
            origin: elc.origin.as_deref(),
            platform: platform.map(String::as_str).or(values.platform.as_deref()),
            machine: values.machine.as_deref(),
            osname: values.osname.as_deref(),
            osrel: values.osrel.as_deref(),
            isalist: &values.isalist,
        }
    }
}

// The tokens expand knows, in the order it tries them.  A token is the name
// right after the '$', without braces and whatever follows it.
const TOKENS: [&str; 8] = [
    "ORIGIN",
    "PLATFORM",
    "MACHINE",
    "OSNAME",
    "OSREL",
    "ISALIST",
    "CAPABILITY",
    "HWCAP",
];

// Expand the tokens of the INPUT entry the way expand does, with $ISALIST as
// ISA (the first instruction set without one), along with whether it had
// $ISALIST.  A '$' of no token is kept, and None is returned when a token
// can not be expanded, which fails the entry: a token without a value, a
// second $ISALIST, and $CAPABILITY or $HWCAP (the capability directories
// are not supported).
fn expand_entry(input: &str, values: &TokenValues, isa: Option<&str>) -> Option<(String, bool)> {
    let mut r = String::with_capacity(input.len());
    let mut rest = input;
    let mut isalist = false;
    while let Some(pos) = rest.find('$') {
        r.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let Some(token) = TOKENS.iter().find(|token| after.starts_with(**token)) else {
            r.push('$');
            rest = after;
            continue;
        };
        let value = match *token {
            "ORIGIN" => values.origin,
            "PLATFORM" => values.platform,
            "MACHINE" => values.machine,
            "OSNAME" => values.osname,
            "OSREL" => values.osrel,
            "ISALIST" if !isalist => {
                isalist = true;
                isa.or(values.isalist.first().map(String::as_str))
            }
            _ => None,
        };
        r.push_str(value?);
        rest = &after[token.len()..];
    }
    r.push_str(rest);
    Some((r, isalist))
}

// The entries of LIST the way expand_paths splits it: on colons and
// semicolons (a semicolon starting an entry is skipped), where an empty
// entry between colons, or at an end of the list, is the current directory.
fn split_list(list: &str) -> Vec<&str> {
    let bytes = list.as_bytes();
    let mut r = Vec::new();
    let mut i = 0;
    // An empty entry follows the colon ending the list.
    let mut final_empty = false;
    while i < bytes.len() || final_empty {
        if bytes.get(i) == Some(&b';') {
            i += 1;
        }
        if bytes.get(i) == Some(&b':') || final_empty {
            final_empty = !final_empty && i + 1 >= bytes.len();
            i += 1;
            r.push(".");
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b':' && bytes[i] != b';' {
            i += 1;
        }
        final_empty = bytes.get(i) == Some(&b':') && i + 1 == bytes.len();
        r.push(&list[start..i]);
        i += 1;
    }
    r
}

// The directories of the LIST search list, each entry with $ISALIST being
// one for each instruction set, or the entry when its expansion fails.
fn expand_list(list: &str, values: &TokenValues) -> Vec<Result<String, String>> {
    let mut r = Vec::new();
    for entry in split_list(list) {
        match expand_entry(entry, values, None) {
            Some((dir, isalist)) => {
                r.push(Ok(dir));
                if isalist {
                    for isa in values.isalist.iter().skip(1) {
                        let dir = expand_entry(entry, values, Some(isa)).map(|(dir, _)| dir);
                        r.push(dir.ok_or_else(|| entry.to_string()));
                    }
                }
            }
            None => r.push(Err(entry.to_string())),
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    // A single rpath list, from the last of the DT_RPATH and DT_RUNPATH
    // entries, searched after the LD_LIBRARY_PATH directories.
    #[test]
    fn last_search_list_entry_wins() {
        let mut elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        elc.rpath = search_path::fixed_list(["/r"]);
        elc.runpath = search_path::fixed_list(["/u"]);
        elc.has_runpath = true;
        elc.runpath_last = false;
        Solaris::handle_search_paths(&mut elc);
        assert_eq!(elc.rpath, search_path::fixed_list(["/r"]));
        assert!(elc.runpath.is_empty() && !elc.has_runpath);
        assert!(matches!(
            Solaris::SEARCH_ORDER,
            [
                SearchStep::LibraryPath,
                SearchStep::Rpath,
                SearchStep::SystemDirs
            ]
        ));
    }

    fn test_values(isalist: &[String]) -> TokenValues<'_> {
        TokenValues {
            origin: Some("/o"),
            platform: Some("i86pc"),
            machine: Some("i86pc"),
            osname: Some("SunOS"),
            osrel: Some("5.11"),
            isalist,
        }
    }

    #[test]
    fn expand_entry_tokens() {
        let isalist = vec!["amd64".to_string(), "i386".to_string()];
        let values = test_values(&isalist);
        let expand = |input| expand_entry(input, &values, None).map(|(entry, _)| entry);
        let cases = [
            ("$ORIGIN/../lib", "/o/../lib"),
            // No braces, and a token does not end the name.
            ("${ORIGIN}", "${ORIGIN}"),
            ("$ORIGINAL", "/oAL"),
            ("/p/$PLATFORM/$MACHINE", "/p/i86pc/i86pc"),
            ("/$OSNAME/$OSREL", "/SunOS/5.11"),
            ("/lib/$ISALIST", "/lib/amd64"),
            ("$LIB/$", "$LIB/$"),
        ];
        for (input, expanded) in cases {
            assert_eq!(expand(input).as_deref(), Some(expanded), "{input}");
        }
        for input in ["/a/$ISALIST/$ISALIST", "/a/$CAPABILITY", "/a/$HWCAP"] {
            assert_eq!(expand(input), None, "{input}");
        }
        let unknown = test_values(&[]);
        assert_eq!(expand_entry("/lib/$ISALIST", &unknown, None), None);
    }

    #[test]
    fn split_search_list() {
        assert_eq!(split_list("/a:/b;/c"), ["/a", "/b", "/c"]);
        assert_eq!(split_list(":/a::/b:"), [".", "/a", ".", "/b", "."]);
        assert_eq!(split_list("/a;;/b"), ["/a", "/b"]);
        assert_eq!(split_list("/a::"), ["/a", ".", "."]);
        assert!(split_list("").is_empty());
    }

    // An entry with $ISALIST is one for each instruction set, in order.
    #[test]
    fn expand_search_list() {
        let isalist = vec!["amd64".to_string(), "i386".to_string()];
        let values = test_values(&isalist);
        assert_eq!(
            expand_list("/a/$ISALIST/lib:/b:/c/$HWCAP", &values),
            [
                Ok("/a/amd64/lib".to_string()),
                Ok("/a/i386/lib".to_string()),
                Ok("/b".to_string()),
                Err("/c/$HWCAP".to_string())
            ]
        );
    }

    #[test]
    fn nodeflib_skips_the_default_directories() {
        let elc = ElfInfo::for_test(EM_X86_64, FileFlags(0));
        let rule = |step| Solaris::nodeflib_rule(step, &elc);
        assert_eq!(rule(SearchStep::SystemDirs), NodeflibRule::Skip);
        assert_eq!(rule(SearchStep::LibraryPath), NodeflibRule::Search);
        assert_eq!(rule(SearchStep::Rpath), NodeflibRule::Search);
    }

    // $ORIGIN is the directory of the resolved path.
    #[cfg(unix)]
    #[test]
    fn origin_of_the_resolved_path() -> std::io::Result<()> {
        use crate::tempdir::TempDir;
        let tmpdir = TempDir::new()?;
        let lib = tmpdir.path().join("lib");
        fs::create_dir(&lib)?;
        fs::write(lib.join("libx.so.1"), [])?;
        std::os::unix::fs::symlink(lib.join("libx.so.1"), tmpdir.path().join("libx.so.1"))?;
        let origin = Solaris::origin_directory(&tmpdir.path().join("libx.so.1"), None);
        assert_eq!(origin.map(PathBuf::from), Some(fs::canonicalize(&lib)?));
        Ok(())
    }
}
