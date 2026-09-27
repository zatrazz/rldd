// The glibc and musl loaders.

use super::*;

pub(in crate::elf) struct Linux;

impl Loader for Linux {
    type Cache = ld_so_cache::LdCache;

    // The musl loader searches LD_LIBRARY_PATH before the rpath chain of the
    // objects that needed the library, has no cache, and does not search
    // any rpath for a preloaded object, which no object needs
    // (load_library).
    fn search_order(elc: &ElfInfo, preload: bool) -> &'static [SearchStep] {
        match (elc.is_musl, preload) {
            (false, _) => Self::SEARCH_ORDER,
            (true, false) => &[
                SearchStep::LibraryPath,
                SearchStep::Rpath,
                SearchStep::SystemDirs,
            ],
            (true, true) => &[SearchStep::LibraryPath, SearchStep::SystemDirs],
        }
    }

    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        _binary: &P,
        elc: &ElfInfo,
        _platform: Option<&String>,
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

    // The musl loader always loads the preloaded objects (load_preload runs
    // before load_deps).
    fn preload_without_needed(elc: &ElfInfo) -> bool {
        elc.is_musl
    }

    // The glibc loader splits LD_PRELOAD on spaces and colons only, and
    // silently skips an entry that does not fit a path (handle_preload_list),
    // while the musl one splits it on any whitespace or colon (load_preload).
    fn preload_list(list: &str, elc: &ElfInfo) -> Vec<String> {
        const PATH_MAX: usize = 4096;
        let entries: Vec<&str> = if elc.is_musl {
            // The C isspace set, along with the colon.
            list.split([' ', '\t', '\n', '\x0b', '\x0c', '\r', ':'])
                .collect()
        } else {
            list.split([' ', ':'])
                .filter(|entry| entry.len() < PATH_MAX)
                .collect()
        };
        entries
            .into_iter()
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect()
    }

    // The objects are loaded by the loader of the input object, whatever
    // their own PT_INTERP or dependencies say, so they follow its rules.
    fn handle_loader(elc: &mut ElfInfo, melc: Option<&ElfInfo>) {
        if let Some(melc) = melc {
            elc.is_musl = melc.is_musl;
            elc.dst_lib = melc.dst_lib.clone();
            elc.loader_platform = melc.loader_platform;
            elc.loader_flags = melc.loader_flags;
            elc.search_subdirs = Rc::clone(&melc.search_subdirs);
            return;
        }
        elc.is_musl = interp::is_musl(&elc.interp)
            || elc
                .needed
                .iter()
                .any(|(dep, _)| dep.starts_with("libc.musl-"))
            || (elc.interp.is_none() && is_musl_system());
    }

    // A shared library is loaded through the path it is opened with, without
    // resolving a symlink (_dl_new_object, and fixup_rpath on musl), the way
    // dlopen and ldd (which runs the loader on it) do.
    fn root_origin_directory(given: &Path, filename: &Path, elc: &ElfInfo) -> Option<String> {
        match std::path::absolute(given) {
            Ok(path) if elc.interp.is_none() => Self::origin_directory(&path, None),
            _ => Self::origin_directory(&filename, None),
        }
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

    // The glibc loader takes an empty entry as the current directory
    // (fillin_rpath), although a list without any entry is ignored
    // (decompose_rpath), and also splits LD_LIBRARY_PATH on semicolons
    // (_dl_init_paths).  The musl loader expands the tokens of a DT_RPATH or
    // DT_RUNPATH list at once (fixup_rpath), but none on LD_LIBRARY_PATH, and
    // splits them on colons and newlines skipping the empty entries
    // (path_open).
    fn search_list(
        list: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Vec<Result<String, String>> {
        if elc.is_musl {
            let list = match site {
                TokenSite::SearchPath => match musl_expand(list, elc.origin.as_deref()) {
                    Some(list) => list,
                    None => return vec![Err(list.to_string())],
                },
                _ => list.to_string(),
            };
            return list
                .split([':', '\n'])
                .filter(|entry| !entry.is_empty())
                .map(|entry| Ok(entry.to_string()))
                .collect();
        }
        if list.is_empty() {
            return Vec::new();
        }
        let separators: &[char] = match site {
            TokenSite::LibraryPath => &[':', ';'],
            _ => &[':'],
        };
        list.split(separators)
            .map(|entry| match entry {
                "" => Ok(".".to_string()),
                _ => {
                    Self::expand_tokens(entry, site, elc, platform).ok_or_else(|| entry.to_string())
                }
            })
            .collect()
    }

    // The glibc loader expands $ORIGIN, $PLATFORM and $LIB on the search lists
    // (LD_LIBRARY_PATH included), the dependency names, and the preload
    // entries naming a path (the bare names are searched as is), while the
    // musl one only expands the DT_RPATH and DT_RUNPATH lists.
    fn expand_tokens(
        input: &str,
        site: TokenSite,
        elc: &ElfInfo,
        platform: Option<&String>,
    ) -> Option<String> {
        if elc.is_musl || (site == TokenSite::Preload && !input.contains('/')) {
            return Some(input.to_string());
        }
        let platform = platform
            .map(String::as_str)
            .or(elc.loader_platform)
            .or_else(|| platform::get(elc.e_machine, elc.ei_data));
        glibc_expand(
            input,
            elc.origin.as_deref(),
            platform,
            elc.dst_lib.as_deref(),
        )
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
            if let Some(Ok(dep)) = resolve_loader(config, elc, name) {
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

    // The glibc loader skips a file of another class or machine, and fails
    // the load on anything else wrong.  The musl one takes the first file it
    // opens, checking nothing but its program headers (map_library), so any
    // problem fails the load.
    fn check_candidate(
        data: &[u8],
        parsed: &Result<ElfInfo, &'static str>,
        melc: &ElfInfo,
    ) -> Result<(), Rejection> {
        if !melc.is_musl {
            return glibc_verify(data, parsed, melc);
        }
        match parsed {
            Ok(elc) if match_elf_header(melc, elc) => Ok(()),
            _ => Err(Rejection::Fatal("Exec format error".to_string())),
        }
    }

    // The glibc loader skips the default directories, and the cache entries
    // below them (a cache entry elsewhere, such as an ld.so.conf directory,
    // is still used), see _dl_map_object.  The musl loader ignores the flag.
    fn nodeflib_rule(step: SearchStep, elc: &ElfInfo) -> NodeflibRule {
        match step {
            _ if elc.is_musl => NodeflibRule::Search,
            SearchStep::Cache => NodeflibRule::OutsideSystemDirs,
            SearchStep::SystemDirs => NodeflibRule::Skip,
            _ => NodeflibRule::Search,
        }
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
    ) -> Option<Resolution<'a>> {
        // The glibc-hwcaps subdirectories are cache entries of their own, so
        // an entry is not searched for them.
        let dir = self.get(dtneeded)?;
        search_dir(
            dir.as_str(),
            dtneeded,
            elc,
            platform,
            DepMode::LdCache,
            &Default::default(),
        )
    }
}

// The checks of the glibc loader on DATA, a candidate file for a dependency of
// MELC parsed as PARSED, in the order it makes them: open_verify skips a file
// of another class or machine, and fails the load on any other mismatch, as
// does _dl_map_object_from_fd on an object it can not load.
fn glibc_verify(
    data: &[u8],
    parsed: &Result<ElfInfo, &'static str>,
    melc: &ElfInfo,
) -> Result<(), Rejection> {
    let fatal = |error: &str| Err(Rejection::Fatal(error.to_string()));

    let class64 = melc.ei_class == ELFCLASS64;
    if data.len() < if class64 { 64 } else { 52 } {
        return fatal("file too short");
    }
    // The e_ident fields.
    if data[..4] != ELFMAG {
        return fatal("invalid ELF header");
    }
    if FileClass(data[4]) != melc.ei_class {
        let other = if class64 { "ELFCLASS32" } else { "ELFCLASS64" };
        return Err(Rejection::Skip(format!("wrong ELF class: {other}")));
    }
    let big_endian = melc.ei_data == ELFDATA2MSB;
    if DataEncoding(data[5]) != melc.ei_data {
        return fatal(if big_endian {
            "ELF file data encoding not big-endian"
        } else {
            "ELF file data encoding not little-endian"
        });
    }
    if data[6] != EV_CURRENT.0 {
        return fatal("ELF file version ident does not match current one");
    }
    // The OS ABI fields the loader architecture takes.
    let (os_abi, abi_version) = (OsAbi(data[7]), data[8]);
    if !gnu_osabi_valid(melc.e_machine, os_abi) {
        return fatal("ELF file OS ABI invalid");
    }
    if !gnu_abiversion_valid(melc.e_machine, os_abi, abi_version) {
        return fatal("ELF file ABI version invalid");
    }
    if data[9..16].iter().any(|&b| b != 0) {
        return fatal("nonzero padding in e_ident");
    }

    let u16_at = |offset: usize| {
        let bytes = [data[offset], data[offset + 1]];
        if big_endian {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        }
    };
    let u32_at = |offset: usize| {
        let bytes = [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ];
        if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    };
    let e_type = FileType(u16_at(16));
    let e_machine = Machine(u16_at(18));
    let e_version = u32_at(20);
    let e_flags = FileFlags(u32_at(if class64 { 48 } else { 36 }));
    let e_phentsize = u16_at(if class64 { 54 } else { 42 });

    // The ARM float ABI is checked along with the identification, which the
    // diagnostics do not tell apart (VALID_ELF_HEADER).
    if melc.e_machine == EM_ARM && !arm_float_abi_valid(melc.loader_flags, e_flags) {
        return fatal("internal error");
    }
    if e_version != u32::from(EV_CURRENT.0) {
        return fatal("ELF file version does not match current one");
    }
    if !machine_matches_host(melc, e_machine, e_flags) {
        return Err(Rejection::Skip(
            "cannot open shared object file: No such file or directory".to_string(),
        ));
    }
    if e_type != ET_DYN && e_type != ET_EXEC {
        return fatal("only ET_DYN and ET_EXEC can be loaded");
    }
    if e_phentsize != if class64 { 56 } else { 32 } {
        return fatal("ELF file's phentsize not the expected size");
    }
    if e_type == ET_EXEC {
        return fatal("cannot dynamically load executable");
    }
    match parsed {
        Err("No dynamic segments found" | "Object file has no dynamic section") => {
            fatal("object file has no dynamic section")
        }
        Err(e) => fatal(e),
        Ok(elc) if elc.pie => fatal("cannot dynamically load position-independent executable"),
        Ok(_) => Ok(()),
    }
}

// Whether the loader for the objects of MELC takes an object of the
// E_MACHINE and E_FLAGS, where the ABI variant (and so the loader) follows the
// input object (elf_machine_matches_host).
fn machine_matches_host(melc: &ElfInfo, e_machine: Machine, e_flags: FileFlags) -> bool {
    const EM_S390_OLD: Machine = Machine(0xa390);
    let loader_flags = melc.loader_flags;
    match melc.e_machine {
        EM_MIPS | EM_MIPS_RS3_LE => {
            // The o32 and n32 objects are not mixed, nor the NaN encodings, and
            // the old o32 FP64 ABI is not supported.
            let abi2 = |flags: FileFlags| flags.contains(EF_MIPS_ABI2);
            let nan2008 = |flags: FileFlags| flags.contains(EF_MIPS_NAN2008);
            matches!(e_machine, EM_MIPS | EM_MIPS_RS3_LE)
                && (melc.ei_class != ELFCLASS32 || abi2(e_flags) == abi2(loader_flags))
                && nan2008(e_flags) == nan2008(loader_flags)
                && !e_flags.contains(EF_MIPS_FP64)
        }
        EM_RISCV => {
            // The float ABI is either the double or the soft one.
            let float_abi = |flags: FileFlags| flags & FileFlags(EF_RISCV_FLOAT_ABI);
            let double = float_abi(loader_flags) == EF_RISCV_FLOAT_ABI_DOUBLE;
            e_machine == EM_RISCV
                && float_abi(e_flags)
                    == if double {
                        EF_RISCV_FLOAT_ABI_DOUBLE
                    } else {
                        EF_RISCV_FLOAT_ABI_SOFT
                    }
        }
        EM_PPC64 => {
            // An unspecified ABI version is the ELFv1 one on big-endian.
            let loader_abi = match loader_flags.ppc64_abi() {
                0 if melc.ei_data == ELFDATA2MSB => 1,
                0 => 2,
                abi => abi,
            };
            e_machine == EM_PPC64 && (e_flags.ppc64_abi() == 0 || e_flags.ppc64_abi() == loader_abi)
        }
        EM_SPARC | EM_SPARC32PLUS => matches!(e_machine, EM_SPARC | EM_SPARC32PLUS),
        EM_S390 | EM_S390_OLD => matches!(e_machine, EM_S390 | EM_S390_OLD),
        machine => e_machine == machine,
    }
}

// Whether the ARM loader following the LOADER_FLAGS float ABI takes an EABI
// version 5 object of E_FLAGS (VALID_FLOAT_ABI): a hard-float loader rejects
// the soft-float objects, and the other way around.
fn arm_float_abi_valid(loader_flags: FileFlags, e_flags: FileFlags) -> bool {
    let hard = loader_flags.contains(FileFlags(EF_ARM_ABI_FLOAT_HARD));
    let other = if hard {
        EF_ARM_ABI_FLOAT_SOFT
    } else {
        EF_ARM_ABI_FLOAT_HARD
    };
    e_flags.arm_eabi() != EF_ARM_EABI_VER5 || !e_flags.contains(FileFlags(other))
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

    fn glibc_object() -> ElfInfo {
        ElfInfo::for_test(EM_X86_64, FileFlags(0))
    }

    fn musl_object() -> ElfInfo {
        let mut elc = glibc_object();
        elc.is_musl = true;
        elc
    }

    fn entries(list: &[Result<String, String>]) -> Vec<String> {
        list.iter()
            .map(|entry| match entry {
                Ok(dir) => dir.clone(),
                Err(entry) => format!("dropped {entry}"),
            })
            .collect()
    }

    #[test]
    fn search_lists() {
        let glibc = |list, site| entries(&Linux::search_list(list, site, &glibc_object(), None));
        let musl = |list, site| entries(&Linux::search_list(list, site, &musl_object(), None));
        let site = TokenSite::SearchPath;
        // An empty entry is the current directory for glibc, but a list
        // without entries is ignored.
        assert_eq!(glibc("/a::$ORIGIN/$LIB", site), ["/a", ".", "/o/lib64"]);
        assert_eq!(glibc("/a:", site), ["/a", "."]);
        assert!(glibc("", site).is_empty());
        assert_eq!(glibc("/a;/b", site), ["/a;/b"]);
        assert_eq!(glibc("/a;/b:", TokenSite::LibraryPath), ["/a", "/b", "."]);
        // No $PLATFORM value (RISC-V) drops the entry.
        let riscv = ElfInfo::for_test(EM_RISCV, FileFlags(0));
        assert_eq!(
            entries(&Linux::search_list("/$PLATFORM:/b", site, &riscv, None)),
            ["dropped /$PLATFORM", "/b"]
        );
        // musl skips the empty entries, splits on newlines too, and ignores
        // a DT_RPATH with any other token than $ORIGIN.
        assert_eq!(musl("/a::\n$ORIGIN/b", site), ["/a", "/o/b"]);
        assert_eq!(musl("$ORIGIN/a:/$LIB", site), ["dropped $ORIGIN/a:/$LIB"]);
        assert_eq!(musl("$ORIGIN/a", TokenSite::LibraryPath), ["$ORIGIN/a"]);
    }

    #[test]
    fn preload_entries() {
        let glibc = glibc_object();
        let expand = |input, elc| Linux::expand_tokens(input, TokenSite::Preload, elc, None);
        assert_eq!(
            expand("$ORIGIN/libfoo.so", &glibc).as_deref(),
            Some("/o/libfoo.so")
        );
        // A bare name is searched as is.
        assert_eq!(expand("lib$LIB.so", &glibc).as_deref(), Some("lib$LIB.so"));
        assert_eq!(
            expand("$ORIGIN/x.so", &musl_object()).as_deref(),
            Some("$ORIGIN/x.so")
        );

        // glibc splits on spaces and colons only, and skips an entry that
        // does not fit a path.
        let long = "x".repeat(4096);
        assert_eq!(
            Linux::preload_list(&format!("a b::c\td {long} e"), &glibc),
            ["a", "b", "c\td", "e"]
        );
        assert_eq!(
            Linux::preload_list("a\tb\x0bc:d", &musl_object()),
            ["a", "b", "c", "d"]
        );
    }

    #[test]
    fn search_rules() {
        let glibc = glibc_object();
        let musl = musl_object();
        assert_eq!(
            Linux::nodeflib_rule(SearchStep::Cache, &glibc),
            NodeflibRule::OutsideSystemDirs
        );
        assert_eq!(
            Linux::nodeflib_rule(SearchStep::SystemDirs, &glibc),
            NodeflibRule::Skip
        );
        assert_eq!(
            Linux::nodeflib_rule(SearchStep::Rpath, &glibc),
            NodeflibRule::Search
        );
        assert_eq!(
            Linux::nodeflib_rule(SearchStep::SystemDirs, &musl),
            NodeflibRule::Search
        );

        let order = |elc, preload| {
            Linux::search_order(elc, preload)
                .iter()
                .map(|step| format!("{step:?}"))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            order(&glibc, true),
            ["Rpath", "LibraryPath", "Runpath", "Cache", "SystemDirs"]
        );
        assert_eq!(order(&musl, false), ["LibraryPath", "Rpath", "SystemDirs"]);
        assert_eq!(order(&musl, true), ["LibraryPath", "SystemDirs"]);
    }

    #[test]
    fn machine_variants() {
        let matches = |machine, loader_flags: u32, e_machine, e_flags: u32| {
            let elc = ElfInfo::for_test(machine, FileFlags(loader_flags));
            machine_matches_host(&elc, e_machine, FileFlags(e_flags))
        };
        let double = EF_RISCV_FLOAT_ABI_DOUBLE.0;
        assert!(matches(EM_RISCV, double, EM_RISCV, double));
        assert!(!matches(EM_RISCV, double, EM_RISCV, 0));
        assert!(!matches(EM_RISCV, 0, EM_RISCV, double));
        assert!(matches(EM_PPC64, 2, EM_PPC64, 0));
        assert!(!matches(EM_PPC64, 2, EM_PPC64, 1));
        assert!(!matches(EM_X86_64, 0, EM_AARCH64, 0));
        let nan2008 = EF_MIPS_NAN2008.0;
        assert!(!matches(EM_MIPS, nan2008, EM_MIPS, 0));
        assert!(matches(EM_MIPS, nan2008, EM_MIPS_RS3_LE, nan2008));

        let hard = EF_ARM_EABI_VER5.0 | EF_ARM_ABI_FLOAT_HARD;
        let soft = EF_ARM_EABI_VER5.0 | EF_ARM_ABI_FLOAT_SOFT;
        assert!(arm_float_abi_valid(FileFlags(hard), FileFlags(hard)));
        assert!(!arm_float_abi_valid(FileFlags(hard), FileFlags(soft)));
        assert!(!arm_float_abi_valid(FileFlags(soft), FileFlags(hard)));
        assert!(arm_float_abi_valid(
            FileFlags(hard),
            FileFlags(EF_ARM_ABI_FLOAT_SOFT)
        ));
    }
}
