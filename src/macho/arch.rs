use object::macho::*;

// The architecture used to select the Mach-O slice and the dyld cache,
// either the host one or the one requested with the --arch option.
#[derive(Debug)]
pub struct Arch {
    name: &'static str,
    cputype: CpuType,
    // The subtype identity (without the capability bits), used to select
    // the preferred slice of a FAT object.
    cpusubtype: Option<u32>,
    // Whether the architecture was explicitly requested with --arch, where
    // thin objects are also checked against the requested cpu type.
    explicit: bool,
}

// The architecture names accepted by --arch, mimicking dyld_info and otool.
static ARCH_NAMES: &[(&str, CpuType, Option<u32>)] = &[
    ("arm64", CPU_TYPE_ARM64, Some(CPU_SUBTYPE_ARM64_ALL.0)),
    ("arm64e", CPU_TYPE_ARM64, Some(CPU_SUBTYPE_ARM64E.0)),
    ("x86_64", CPU_TYPE_X86_64, Some(CPU_SUBTYPE_X86_64_ALL.0)),
    ("x86_64h", CPU_TYPE_X86_64, Some(CPU_SUBTYPE_X86_64_H.0)),
    ("i386", CPU_TYPE_X86, None),
    ("ppc", CPU_TYPE_POWERPC, None),
    ("ppc64", CPU_TYPE_POWERPC64, None),
];

impl Arch {
    pub fn new(name: Option<&str>) -> Result<Arch, String> {
        let Some(name) = name else {
            return Ok(Arch::host());
        };
        ARCH_NAMES
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(n, cputype, cpusubtype)| Arch {
                name: n,
                cputype: *cputype,
                cpusubtype: *cpusubtype,
                explicit: true,
            })
            .ok_or_else(|| {
                format!(
                    "unknown architecture '{name}' (supported: {})",
                    ARCH_NAMES
                        .iter()
                        .map(|(n, _, _)| *n)
                        .collect::<Vec<&str>>()
                        .join(", ")
                )
            })
    }

    // The host architecture matches any subtype, preserving the behavior of
    // analyzing thin objects of a foreign architecture (e.g. an x86_64
    // binary under Rosetta).
    fn host() -> Arch {
        let (name, cputype) = match std::env::consts::ARCH {
            "aarch64" => ("arm64", CPU_TYPE_ARM64),
            "arm" => ("arm", CPU_TYPE_ARM),
            "x86_64" => ("x86_64", CPU_TYPE_X86_64),
            "x86" => ("i386", CPU_TYPE_X86),
            "powerpc64" => ("ppc64", CPU_TYPE_POWERPC64),
            "powerpc" => ("ppc", CPU_TYPE_POWERPC),
            _ => ("unknown", CPU_TYPE_ANY),
        };
        Arch {
            name,
            cputype,
            cpusubtype: None,
            explicit: false,
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn explicit(&self) -> bool {
        self.explicit
    }

    pub fn matches_cputype(&self, cputype: CpuType) -> bool {
        self.cputype == cputype
    }

    // Whether a FAT slice matches, either exactly (also checking the
    // requested subtype) or by cpu type alone.
    pub fn matches_slice(&self, cputype: CpuType, cpusubtype: CpuSubtype, exact: bool) -> bool {
        if !self.matches_cputype(cputype) {
            return false;
        }
        match (exact, self.cpusubtype) {
            (true, Some(subtype)) => cpusubtype.id().0 == subtype,
            _ => true,
        }
    }

    // The dyld shared cache names for the architecture, in preference order.
    pub fn cache_names(&self) -> &'static [&'static str] {
        match self.cputype {
            CPU_TYPE_ARM64 => &["arm64e"],
            CPU_TYPE_X86_64 => {
                if self.cpusubtype == Some(CPU_SUBTYPE_X86_64_H.0) {
                    &["x86_64h", "x86_64"]
                } else {
                    &["x86_64", "x86_64h"]
                }
            }
            _ => &[],
        }
    }
}
