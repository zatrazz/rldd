use object::macho::*;

// A slice architecture: the cpu type along with the subtype, which is None
// for the architectures dyld does not grade (i386 and PowerPC), where any
// subtype matches.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Slice {
    cputype: CpuType,
    cpusubtype: Option<u32>,
}

impl Slice {
    const fn new(cputype: CpuType, cpusubtype: u32) -> Slice {
        Slice {
            cputype,
            cpusubtype: Some(cpusubtype),
        }
    }

    const fn any(cputype: CpuType) -> Slice {
        Slice {
            cputype,
            cpusubtype: None,
        }
    }

    // Whether a slice is this architecture, compared the way dyld's
    // Architecture::operator== does: the subtype capability bits are
    // ignored, except on arm64 where the high byte holds the arm64e pointer
    // authentication ABI version, which has to match as well.
    fn matches(&self, cputype: CpuType, cpusubtype: CpuSubtype) -> bool {
        match self.cpusubtype {
            _ if self.cputype != cputype => false,
            None => true,
            Some(subtype) if cputype == CPU_TYPE_ARM64 => subtype == cpusubtype.0,
            Some(subtype) => CpuSubtype(subtype).id() == cpusubtype.id(),
        }
    }

    // Whether a slice has the subtype identity of this architecture,
    // regardless of the capability and ABI version bits.
    fn matches_id(&self, cputype: CpuType, cpusubtype: CpuSubtype) -> bool {
        self.cputype == cputype
            && self
                .cpusubtype
                .is_none_or(|subtype| CpuSubtype(subtype).id() == cpusubtype.id())
    }
}

const X86_64: Slice = Slice::new(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL.0);
const X86_64H: Slice = Slice::new(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H.0);
const ARM64: Slice = Slice::new(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL.0);
// The non-standard arm64 subtype dyld also takes (Architecture::arm64_alt).
const ARM64_V8: Slice = Slice::new(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8.0);
// arm64e with the pointer authentication ABI version 0, and the version 1
// one, which dyld only loads in a process with the keys off.
const ARM64E: Slice = Slice::new(
    CPU_TYPE_ARM64,
    CPU_SUBTYPE_PTRAUTH_ABI.0 | CPU_SUBTYPE_ARM64E.0,
);
const ARM64E_V1: Slice = Slice::new(
    CPU_TYPE_ARM64,
    CPU_SUBTYPE_PTRAUTH_ABI.0 | 1 << 24 | CPU_SUBTYPE_ARM64E.0,
);

// The dyld graded architectures (mach_o/GradedArchitectures.cpp), the
// slices a process loads, best first.  An arm64e main executable runs with
// the pointer authentication keys on and only loads arm64e images, while
// any other arm64 process also loads them, in preference to the arm64 ones.
static LOAD_ARM64E: &[Slice] = &[ARM64E];
static LOAD_ARM64E_KEYS_OFF: &[Slice] = &[ARM64E, ARM64E_V1, ARM64, ARM64_V8];
static LOAD_MAC: &[Slice] = &[X86_64];
static LOAD_MAC_HASWELL: &[Slice] = &[X86_64H, X86_64];
// The main executable slice an Apple Silicon host launches, where an x86_64
// one runs under Rosetta (launch_macAppleSilicon).
static LAUNCH_APPLE_SILICON: &[Slice] = &[ARM64E, ARM64, X86_64];

// The dyld shared cache names, in preference order.  There is a single
// arm64e cache for all the arm64 processes.
static ARM64E_CACHE: &[&str] = &["arm64e"];
static X86_64_CACHE: &[&str] = &["x86_64", "x86_64h"];
static X86_64H_CACHE: &[&str] = &["x86_64h", "x86_64"];

// The architecture names accepted by --arch, mimicking dyld_info and otool.
static ARCH_NAMES: &[(&str, Slice)] = &[
    ("arm64", ARM64),
    ("arm64e", ARM64E),
    ("x86_64", X86_64),
    ("x86_64h", X86_64H),
    ("i386", Slice::any(CPU_TYPE_X86)),
    ("ppc", Slice::any(CPU_TYPE_POWERPC)),
    ("ppc64", Slice::any(CPU_TYPE_POWERPC64)),
];

// An architecture along with the slices it takes, either the one selecting
// the input slice (the one requested with the --arch option, or the one the
// host launches), or the one of the process running the input, which the
// dependencies have to match.
#[derive(Debug)]
pub struct Arch {
    name: &'static str,
    // The slices taken, best first.
    graded: Vec<Slice>,
    // Whether the architecture was explicitly requested with --arch, where
    // the input file has to hold a slice of the requested cpu type.
    explicit: bool,
    cache_names: &'static [&'static str],
}

impl Arch {
    pub fn new(name: Option<&str>) -> Result<Arch, String> {
        let Some(name) = name else {
            return Ok(Arch::host());
        };
        ARCH_NAMES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(n, slice)| Arch {
                name: n,
                graded: vec![*slice],
                explicit: true,
                cache_names: cache_names(slice.cputype, *slice == X86_64H),
            })
            .ok_or_else(|| {
                format!(
                    "unknown architecture '{name}' (supported: {})",
                    ARCH_NAMES
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<&str>>()
                        .join(", ")
                )
            })
    }

    // The main executable slices the host launches, best first
    // (GradedArchitectures::currentLaunch).
    fn host() -> Arch {
        let (name, graded) = match std::env::consts::ARCH {
            "aarch64" => ("arm64", LAUNCH_APPLE_SILICON),
            "x86_64" => ("x86_64", LOAD_MAC),
            _ => ("unknown", &[][..]),
        };
        Arch {
            name,
            graded: graded.to_vec(),
            explicit: false,
            cache_names: graded
                .first()
                .map_or(&[][..], |slice| cache_names(slice.cputype, false)),
        }
    }

    // The architecture of a process running an image of CPUTYPE and
    // CPUSUBTYPE (the input slice) of the FILETYPE, which grades the slices
    // of its dependencies (ProcessConfig::Process::getMainArchs) and selects
    // the dyld cache flavor.  An input that is not a main executable (a
    // dylib, or a bundle) may be loaded by any process of its cpu type, so
    // it takes the images an arm64 process with the keys off loads.
    pub fn process(cputype: CpuType, cpusubtype: CpuSubtype, filetype: FileType) -> Arch {
        let haswell = cputype == CPU_TYPE_X86_64 && cpusubtype.id() == CPU_SUBTYPE_X86_64_H;
        let graded = match cputype {
            CPU_TYPE_ARM64 if filetype == MH_EXECUTE && cpusubtype.id() == CPU_SUBTYPE_ARM64E => {
                LOAD_ARM64E.to_vec()
            }
            CPU_TYPE_ARM64 => LOAD_ARM64E_KEYS_OFF.to_vec(),
            CPU_TYPE_X86_64 if haswell => LOAD_MAC_HASWELL.to_vec(),
            CPU_TYPE_X86_64 => LOAD_MAC.to_vec(),
            _ => vec![Slice::any(cputype)],
        };
        Arch {
            name: slice_name(cputype, cpusubtype),
            graded,
            explicit: false,
            cache_names: cache_names(cputype, haswell),
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    // The dyld shared cache names for the architecture, in preference order.
    pub fn cache_names(&self) -> &'static [&'static str] {
        self.cache_names
    }

    // The slice of a universal file the process loads: the first one of the
    // best graded architecture (Universal::bestSlice), or None when there is
    // no slice the process loads.  A thin file is taken as its only slice.
    pub fn best_slice(&self, slices: &[(CpuType, CpuSubtype)]) -> Option<usize> {
        self.graded.iter().find_map(|graded| {
            slices
                .iter()
                .position(|(cputype, cpusubtype)| graded.matches(*cputype, *cpusubtype))
        })
    }

    // The slice of the input file: the best graded one, then one with the
    // subtype identity of a graded architecture regardless of the
    // capability and ABI version bits, then any one of its cpu type.  When
    // no architecture was requested, the first slice is at last taken, so a
    // foreign binary can still be inspected.
    pub fn input_slice(&self, slices: &[(CpuType, CpuSubtype)]) -> Option<usize> {
        let find = |matches: fn(&Slice, CpuType, CpuSubtype) -> bool| {
            self.graded.iter().find_map(|graded| {
                slices
                    .iter()
                    .position(|(cputype, cpusubtype)| matches(graded, *cputype, *cpusubtype))
            })
        };
        find(Slice::matches)
            .or_else(|| find(Slice::matches_id))
            .or_else(|| find(|graded, cputype, _| graded.cputype == cputype))
            .or_else(|| (!self.explicit && !slices.is_empty()).then_some(0))
    }
}

// The dyld shared cache names of a cpu type, in preference order.
fn cache_names(cputype: CpuType, haswell: bool) -> &'static [&'static str] {
    match cputype {
        CPU_TYPE_ARM64 => ARM64E_CACHE,
        CPU_TYPE_X86_64 if haswell => X86_64H_CACHE,
        CPU_TYPE_X86_64 => X86_64_CACHE,
        _ => &[],
    }
}

// The name dyld_info and lipo print for a slice.
fn slice_name(cputype: CpuType, cpusubtype: CpuSubtype) -> &'static str {
    match (cputype, cpusubtype.id()) {
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E) => "arm64e",
        (CPU_TYPE_ARM64, _) => "arm64",
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H) => "x86_64h",
        (CPU_TYPE_X86_64, _) => "x86_64",
        (CPU_TYPE_X86, _) => "i386",
        (CPU_TYPE_ARM, _) => "arm",
        (CPU_TYPE_POWERPC, _) => "ppc",
        (CPU_TYPE_POWERPC64, _) => "ppc64",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice(slice: Slice) -> (CpuType, CpuSubtype) {
        (slice.cputype, CpuSubtype(slice.cpusubtype.unwrap()))
    }

    fn process(slice: Slice, filetype: FileType) -> Arch {
        let (cputype, cpusubtype) = self::slice(slice);
        Arch::process(cputype, cpusubtype, filetype)
    }

    #[test]
    fn slice_equality() {
        let (arm64e, arm64e_v1) = (slice(ARM64E), slice(ARM64E_V1));
        assert!(ARM64E.matches(arm64e.0, arm64e.1));
        // The arm64e ABI version has to match, and the unversioned subtype
        // is another architecture.
        assert!(!ARM64E.matches(arm64e_v1.0, arm64e_v1.1));
        assert!(!ARM64E.matches(CPU_TYPE_ARM64, CpuSubtype(CPU_SUBTYPE_ARM64E.0)));
        assert!(ARM64E.matches_id(CPU_TYPE_ARM64, CpuSubtype(CPU_SUBTYPE_ARM64E.0)));
        // The x86_64 capability bits are ignored.
        let lib64 = CpuSubtype(CPU_SUBTYPE_LIB64.0 | CPU_SUBTYPE_X86_64_ALL.0);
        assert!(X86_64.matches(CPU_TYPE_X86_64, lib64));
        assert!(!X86_64.matches(slice(X86_64H).0, slice(X86_64H).1));
        assert!(Slice::any(CPU_TYPE_X86).matches(CPU_TYPE_X86, CpuSubtype(4)));
        assert!(!Slice::any(CPU_TYPE_X86).matches(CPU_TYPE_X86_64, CpuSubtype(3)));
    }

    #[test]
    fn process_architecture() {
        // An arm64e main executable only loads arm64e images, any other
        // arm64 process prefers them over the arm64 ones.
        let keys_on = process(ARM64E, MH_EXECUTE);
        assert_eq!(keys_on.name(), "arm64e");
        assert_eq!(keys_on.graded, [ARM64E]);
        assert_eq!(keys_on.cache_names(), ["arm64e"]);
        for (arch, filetype) in [(ARM64, MH_EXECUTE), (ARM64E, MH_DYLIB), (ARM64, MH_BUNDLE)] {
            let keys_off = process(arch, filetype);
            assert_eq!(keys_off.graded, LOAD_ARM64E_KEYS_OFF);
            assert_eq!(keys_off.cache_names(), ["arm64e"]);
        }

        let x86_64 = process(X86_64, MH_EXECUTE);
        assert_eq!(x86_64.name(), "x86_64");
        assert_eq!(x86_64.cache_names()[0], "x86_64");
        let x86_64h = process(X86_64H, MH_EXECUTE);
        assert_eq!(x86_64h.name(), "x86_64h");
        assert_eq!(x86_64h.graded, [X86_64H, X86_64]);
        assert_eq!(x86_64h.cache_names(), ["x86_64h", "x86_64"]);

        let i386 = Arch::process(CPU_TYPE_X86, CpuSubtype(3), MH_EXECUTE);
        assert_eq!(i386.name(), "i386");
        assert!(i386.cache_names().is_empty());
        assert_eq!(i386.best_slice(&[(CPU_TYPE_X86, CpuSubtype(4))]), Some(0));
    }

    #[test]
    fn dependency_slice() {
        let keys_off = process(ARM64, MH_EXECUTE);
        let keys_on = process(ARM64E, MH_EXECUTE);
        let x86_64 = process(X86_64, MH_EXECUTE);

        // A thin file of another architecture is not loaded.
        assert_eq!(keys_off.best_slice(&[slice(X86_64)]), None);
        assert_eq!(x86_64.best_slice(&[slice(ARM64)]), None);
        assert_eq!(keys_on.best_slice(&[slice(ARM64)]), None);
        assert_eq!(keys_off.best_slice(&[slice(ARM64_V8)]), Some(0));

        // The best graded slice wins over the FAT header order.
        let fat = [slice(X86_64), slice(ARM64), slice(ARM64E)];
        assert_eq!(keys_off.best_slice(&fat), Some(2));
        assert_eq!(keys_on.best_slice(&fat), Some(2));
        assert_eq!(x86_64.best_slice(&fat), Some(0));
        let fat = [slice(ARM64), slice(X86_64H)];
        assert_eq!(keys_off.best_slice(&fat), Some(0));
        assert_eq!(keys_on.best_slice(&fat), None);
        assert_eq!(x86_64.best_slice(&fat), None);
        let x86_64h = process(X86_64H, MH_EXECUTE);
        assert_eq!(x86_64h.best_slice(&fat), Some(1));
        assert_eq!(
            x86_64h.best_slice(&[slice(X86_64), slice(X86_64H)]),
            Some(1)
        );
    }

    #[test]
    fn input_slice() {
        let apple_silicon = Arch {
            name: "arm64",
            graded: LAUNCH_APPLE_SILICON.to_vec(),
            explicit: false,
            cache_names: ARM64E_CACHE,
        };
        let fat = [slice(X86_64), slice(ARM64), slice(ARM64E)];
        assert_eq!(apple_silicon.input_slice(&fat), Some(2));
        assert_eq!(apple_silicon.input_slice(&fat[..2]), Some(1));
        assert_eq!(apple_silicon.input_slice(&fat[..1]), Some(0));
        // Without a slice the host runs, a foreign one is still inspected,
        // preferring one of the host cpu type.
        let old = (CPU_TYPE_ARM64, CpuSubtype(CPU_SUBTYPE_ARM64E.0));
        let fat = [
            (CPU_TYPE_X86, CpuSubtype(3)),
            (CPU_TYPE_POWERPC, CpuSubtype(0)),
            old,
        ];
        assert_eq!(apple_silicon.input_slice(&fat), Some(2));
        assert_eq!(apple_silicon.input_slice(&fat[..2]), Some(0));

        // A requested architecture takes the matching subtype, then any
        // subtype of its cpu type, and nothing else.
        let arm64e = Arch::new(Some("arm64e")).unwrap();
        assert_eq!(
            arm64e.input_slice(&[slice(ARM64), slice(ARM64E_V1)]),
            Some(1)
        );
        assert_eq!(arm64e.input_slice(&[slice(X86_64), slice(ARM64)]), Some(1));
        assert_eq!(arm64e.input_slice(&[slice(X86_64)]), None);
        let x86_64 = Arch::new(Some("x86_64")).unwrap();
        assert_eq!(
            x86_64.input_slice(&[slice(X86_64H), slice(X86_64)]),
            Some(1)
        );
        assert_eq!(x86_64.input_slice(&[slice(X86_64H)]), Some(0));
        assert_eq!(x86_64.cache_names()[0], "x86_64");
        assert_eq!(
            Arch::new(Some("x86_64h")).unwrap().cache_names()[0],
            "x86_64h"
        );
        assert!(Arch::new(Some("sparc")).is_err());
    }
}
