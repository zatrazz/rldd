// The OpenBSD run-time linker.

use super::*;

pub(in crate::elf) struct OpenBsd;

impl Loader for OpenBsd {
    type Cache = search_path::SearchPathVec;

    fn load_so_cache<P: AsRef<Path>>(
        ld_cache: &mut Option<Self::Cache>,
        _binary: &P,
        _ecl: &ElfInfo,
    ) {
        if ld_cache.is_none() {
            *ld_cache = ld_hints_openbsd::parse_ld_so_hints(&Path::new("/var/run/ld.so.hints")).ok()
        }
    }

    fn origin_directory<P: AsRef<Path>>(filename: &P, _melc: Option<&ElfInfo>) -> String {
        canonical_origin_directory(filename)
    }

    fn check_elf_header(elc: &ElfInfo) -> bool {
        elc.ei_osabi == ELFOSABI_SYSV || elc.ei_osabi == ELFOSABI_OPENBSD
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
}
