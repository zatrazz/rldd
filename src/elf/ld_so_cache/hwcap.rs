// The CPU capabilities the glibc loader selects its glibc-hwcaps
// subdirectories with, which also apply to the ld.so.cache entries.

use object::elf::*;

// The capabilities of this machine the glibc loader built for an object ABI
// uses.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LoaderHwcaps {
    // The glibc-hwcaps subdirectories the loader searches, best first.
    pub subdirs: Vec<&'static str>,
    // The x86 ISA levels the CPU supports (the GNU_PROPERTY_X86_ISA_1 bits),
    // which must include the one a glibc-hwcaps cache entry requires.  None
    // for the loaders that do not check it.
    pub isa_levels: Option<u32>,
    // The legacy hwcap bits the loaders before glibc 2.40 take.
    pub legacy: LegacyHwcaps,
}

// The TLS pseudo hwcap bit, set for the libraries of a tls subdirectory.
const HWCAP_TLS: u64 = 1 << 63;

// The legacy hwcap bits of the regular cache entries a loader before glibc
// 2.40 takes (search_cache hwcap_exclude): the AT_HWCAP bits the loader has
// and uses, the platform ones, and the TLS one, with the platform bit of an
// entry, if any, being the one of the machine.  ldconfig wrote them up to
// glibc 2.36 for the libraries of the legacy hwcaps subdirectories (tls,
// x86_64, haswell, and the like), while the loaders since 2.40 skip every
// entry with any of them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LegacyHwcaps {
    accepted: u64,
    platform_mask: u64,
    // The bit of the machine platform (GLRO(dl_platform)), all of them if
    // there is none.
    platform: u64,
}

impl LegacyHwcaps {
    // The bits of a loader with the HWCAP bits (GLRO(dl_hwcap)), of which it
    // uses the IMPORTANT ones (the glibc.cpu.hwcap_mask default), the platform
    // bits of PLATFORM_MASK (_DL_HWCAP_PLATFORM), and the PLATFORM of the
    // machine, if any.
    pub fn new(hwcap: u64, important: u64, platform_mask: u64, platform: Option<u64>) -> Self {
        LegacyHwcaps {
            accepted: (hwcap & important) | platform_mask | HWCAP_TLS,
            platform_mask,
            platform: platform.unwrap_or(u64::MAX),
        }
    }

    // Whether the loader takes a regular entry with the HWCAP field.
    pub fn check(&self, hwcap: u64) -> bool {
        let platform = hwcap & self.platform_mask;
        hwcap & !self.accepted == 0 && (platform == 0 || platform == self.platform)
    }
}

// The loaders whose hwcap bits are not known take the TLS one only.
impl Default for LegacyHwcaps {
    fn default() -> Self {
        LegacyHwcaps::new(0, 0, 0, None)
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod cpuid {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{__cpuid, __cpuid_count, _xgetbv};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

    use object::elf::{
        DataEncoding, FileClass, Machine, ELFCLASS32, ELFCLASS64, ELFDATA2LSB, EM_386, EM_X86_64,
        GNU_PROPERTY_X86_ISA_1_BASELINE, GNU_PROPERTY_X86_ISA_1_V2, GNU_PROPERTY_X86_ISA_1_V3,
        GNU_PROPERTY_X86_ISA_1_V4,
    };

    use super::{LegacyHwcaps, LoaderHwcaps};

    // The CPUID.(EAX=0) vendor of an Intel CPU, "GenuineIntel" on EBX, EDX
    // and ECX.
    const VENDOR_INTEL: [u32; 3] = [0x756e_6547, 0x4965_6e69, 0x6c65_746e];

    // CPUID.(EAX=1):EDX
    const CPUID_1_EDX_FPU: u32 = 1 << 0;
    const CPUID_1_EDX_CX8: u32 = 1 << 8;
    const CPUID_1_EDX_CMOV: u32 = 1 << 15;
    const CPUID_1_EDX_MMX: u32 = 1 << 23;
    const CPUID_1_EDX_FXSR: u32 = 1 << 24;
    const CPUID_1_EDX_SSE: u32 = 1 << 25;
    const CPUID_1_EDX_SSE2: u32 = 1 << 26;

    // CPUID.(EAX=1):ECX
    const CPUID_1_ECX_SSE3: u32 = 1 << 0;
    const CPUID_1_ECX_SSSE3: u32 = 1 << 9;
    const CPUID_1_ECX_FMA: u32 = 1 << 12;
    const CPUID_1_ECX_CMPXCHG16B: u32 = 1 << 13;
    const CPUID_1_ECX_SSE41: u32 = 1 << 19;
    const CPUID_1_ECX_SSE42: u32 = 1 << 20;
    const CPUID_1_ECX_MOVBE: u32 = 1 << 22;
    const CPUID_1_ECX_POPCNT: u32 = 1 << 23;
    const CPUID_1_ECX_OSXSAVE: u32 = 1 << 27;
    const CPUID_1_ECX_AVX: u32 = 1 << 28;
    const CPUID_1_ECX_F16C: u32 = 1 << 29;

    // CPUID.(EAX=7,ECX=0):EBX
    const CPUID_7_EBX_BMI1: u32 = 1 << 3;
    const CPUID_7_EBX_AVX2: u32 = 1 << 5;
    const CPUID_7_EBX_BMI2: u32 = 1 << 8;
    const CPUID_7_EBX_AVX512F: u32 = 1 << 16;
    const CPUID_7_EBX_AVX512DQ: u32 = 1 << 17;
    const CPUID_7_EBX_AVX512PF: u32 = 1 << 26;
    const CPUID_7_EBX_AVX512ER: u32 = 1 << 27;
    const CPUID_7_EBX_AVX512CD: u32 = 1 << 28;
    const CPUID_7_EBX_AVX512BW: u32 = 1 << 30;
    const CPUID_7_EBX_AVX512VL: u32 = 1 << 31;

    // CPUID.(EAX=80000001H):ECX
    const CPUID_EXT1_ECX_LAHF_SAHF: u32 = 1 << 0;
    const CPUID_EXT1_ECX_LZCNT: u32 = 1 << 5;

    const LEAF_EXTENDED: u32 = 0x8000_0000;

    // The XCR0 state components the OS enables.
    const XSTATE_SSE: u64 = 1 << 1;
    const XSTATE_YMM: u64 = 1 << 2;
    const XSTATE_OPMASK: u64 = 1 << 5;
    const XSTATE_ZMM_HI256: u64 = 1 << 6;
    const XSTATE_HI16_ZMM: u64 = 1 << 7;

    // The legacy hwcap bits of the x86 loaders (sysdeps/x86/dl-hwcap.h), and
    // their platforms (_dl_x86_platforms, from _DL_FIRST_PLATFORM).
    const HWCAP_X86_SSE2: u64 = 1 << 0;
    const HWCAP_X86_64: u64 = 1 << 1;
    const HWCAP_X86_AVX512_1: u64 = 1 << 2;
    const PLATFORM_I586: u64 = 1 << 48;
    const PLATFORM_I686: u64 = 1 << 49;
    const PLATFORM_HASWELL: u64 = 1 << 50;
    const PLATFORM_XEON_PHI: u64 = 1 << 51;

    // The feature registers required by the x86-64 microarchitecture levels,
    // zeroed when the CPU does not report the leaf, the state components
    // the OS enables (zero without XSAVE enabled), and whether it is an Intel
    // CPU.
    #[derive(Clone, Copy, Debug, Default)]
    struct Features {
        leaf1_edx: u32,
        leaf1_ecx: u32,
        leaf7_ebx: u32,
        ext1_ecx: u32,
        xcr0: u64,
        intel: bool,
    }

    impl Features {
        fn read() -> Self {
            // CPUID is unconditionally available on x86-64 and on the i686
            // baseline, so the leaf 0 query needs no prior check.
            let leaf0 = __cpuid(0);
            let max_basic = leaf0.eax;
            let (leaf1_edx, leaf1_ecx) = if max_basic >= 1 {
                let r = __cpuid(1);
                (r.edx, r.ecx)
            } else {
                (0, 0)
            };
            let leaf7_ebx = if max_basic >= 7 {
                __cpuid_count(7, 0).ebx
            } else {
                0
            };
            let max_extended = __cpuid(LEAF_EXTENDED).eax;
            let ext1_ecx = if max_extended > LEAF_EXTENDED {
                __cpuid(LEAF_EXTENDED + 1).ecx
            } else {
                0
            };
            let xcr0 = if leaf1_ecx & CPUID_1_ECX_OSXSAVE != 0 {
                // SAFETY: OSXSAVE means the CPU supports XSAVE and the OS
                // enabled it, so XGETBV is available.
                unsafe { _xgetbv(0) }
            } else {
                0
            };
            Self {
                leaf1_edx,
                leaf1_ecx,
                leaf7_ebx,
                ext1_ecx,
                xcr0,
                intel: [leaf0.ebx, leaf0.edx, leaf0.ecx] == VENDOR_INTEL,
            }
        }

        // The features the loader takes as usable (CPU_FEATURE_USABLE_P, set
        // by glibc update_active): the AVX ones need the OS to enable the SSE
        // and AVX states (and AVX2, FMA and F16C need AVX), and the AVX-512
        // ones the opmask and ZMM states as well (and AVX512F).
        fn usable(self) -> Self {
            const AVX_STATE: u64 = XSTATE_SSE | XSTATE_YMM;
            const AVX512_STATE: u64 = XSTATE_OPMASK | XSTATE_ZMM_HI256 | XSTATE_HI16_ZMM;
            let mut r = self;
            let avx_state = self.xcr0 & AVX_STATE == AVX_STATE;
            if !avx_state || self.leaf1_ecx & CPUID_1_ECX_AVX == 0 {
                r.leaf1_ecx &= !(CPUID_1_ECX_AVX | CPUID_1_ECX_FMA | CPUID_1_ECX_F16C);
                r.leaf7_ebx &= !CPUID_7_EBX_AVX2;
            }
            if !avx_state
                || self.xcr0 & AVX512_STATE != AVX512_STATE
                || self.leaf7_ebx & CPUID_7_EBX_AVX512F == 0
            {
                r.leaf7_ebx &= !(CPUID_7_EBX_AVX512F
                    | CPUID_7_EBX_AVX512BW
                    | CPUID_7_EBX_AVX512CD
                    | CPUID_7_EBX_AVX512DQ
                    | CPUID_7_EBX_AVX512ER
                    | CPUID_7_EBX_AVX512PF
                    | CPUID_7_EBX_AVX512VL);
            }
            r
        }

        // The legacy hwcap bits of the x86-64 and x32 loaders
        // (init_cpu_features before glibc 2.40): x86_64 always, avx512_1 on an
        // Intel CPU with AVX-512 other than a Xeon Phi, and the xeon_phi or
        // haswell platform on an Intel CPU with their features.
        fn legacy_x86_64(self) -> LegacyHwcaps {
            const AVX512_1: u32 =
                CPUID_7_EBX_AVX512BW | CPUID_7_EBX_AVX512DQ | CPUID_7_EBX_AVX512VL;
            const HASWELL_LEAF1: u32 = CPUID_1_ECX_FMA | CPUID_1_ECX_MOVBE | CPUID_1_ECX_POPCNT;
            const HASWELL_LEAF7: u32 = CPUID_7_EBX_AVX2 | CPUID_7_EBX_BMI1 | CPUID_7_EBX_BMI2;
            let usable = self.usable();
            let mut hwcap = HWCAP_X86_64;
            let mut platform = None;
            if self.intel {
                if usable.leaf7_ebx & CPUID_7_EBX_AVX512CD != 0 {
                    if usable.leaf7_ebx & CPUID_7_EBX_AVX512ER != 0 {
                        if usable.leaf7_ebx & CPUID_7_EBX_AVX512PF != 0 {
                            platform = Some(PLATFORM_XEON_PHI);
                        }
                    } else if usable.leaf7_ebx & AVX512_1 == AVX512_1 {
                        hwcap |= HWCAP_X86_AVX512_1;
                    }
                }
                if platform.is_none()
                    && usable.leaf1_ecx & HASWELL_LEAF1 == HASWELL_LEAF1
                    && usable.leaf7_ebx & HASWELL_LEAF7 == HASWELL_LEAF7
                    && usable.ext1_ecx & CPUID_EXT1_ECX_LZCNT != 0
                {
                    platform = Some(PLATFORM_HASWELL);
                }
            }
            LegacyHwcaps::new(
                hwcap,
                HWCAP_X86_64 | HWCAP_X86_AVX512_1,
                PLATFORM_I586 | PLATFORM_I686 | PLATFORM_HASWELL | PLATFORM_XEON_PHI,
                platform,
            )
        }

        // The legacy hwcap bits of the i386 loader: sse2, and the i686 (with
        // CMOV) or i586 (with CMPXCHG8B) platform.
        fn legacy_i386(self) -> LegacyHwcaps {
            let hwcap = if self.leaf1_edx & CPUID_1_EDX_SSE2 != 0 {
                HWCAP_X86_SSE2
            } else {
                0
            };
            let platform = if self.leaf1_edx & CPUID_1_EDX_CMOV != 0 {
                Some(PLATFORM_I686)
            } else if self.leaf1_edx & CPUID_1_EDX_CX8 != 0 {
                Some(PLATFORM_I586)
            } else {
                None
            };
            LegacyHwcaps::new(
                hwcap,
                HWCAP_X86_SSE2,
                PLATFORM_I586 | PLATFORM_I686,
                platform,
            )
        }

        fn check_basic(&self) -> bool {
            const MASK: u32 = CPUID_1_EDX_CMOV
                | CPUID_1_EDX_CX8
                | CPUID_1_EDX_FPU
                | CPUID_1_EDX_FXSR
                | CPUID_1_EDX_MMX
                | CPUID_1_EDX_SSE
                | CPUID_1_EDX_SSE2;
            self.leaf1_edx & MASK == MASK
        }

        fn check_v2(&self) -> bool {
            const MASK: u32 = CPUID_1_ECX_CMPXCHG16B
                | CPUID_1_ECX_POPCNT
                | CPUID_1_ECX_SSE3
                | CPUID_1_ECX_SSSE3
                | CPUID_1_ECX_SSE41
                | CPUID_1_ECX_SSE42;
            self.leaf1_ecx & MASK == MASK && self.ext1_ecx & CPUID_EXT1_ECX_LAHF_SAHF != 0
        }

        fn check_v3(&self) -> bool {
            const LEAF1_MASK: u32 =
                CPUID_1_ECX_AVX | CPUID_1_ECX_F16C | CPUID_1_ECX_FMA | CPUID_1_ECX_MOVBE;
            const LEAF7_MASK: u32 = CPUID_7_EBX_AVX2 | CPUID_7_EBX_BMI1 | CPUID_7_EBX_BMI2;
            self.leaf1_ecx & LEAF1_MASK == LEAF1_MASK
                && self.leaf7_ebx & LEAF7_MASK == LEAF7_MASK
                && self.ext1_ecx & CPUID_EXT1_ECX_LZCNT != 0
        }

        fn check_v4(&self) -> bool {
            const MASK: u32 = CPUID_7_EBX_AVX512F
                | CPUID_7_EBX_AVX512BW
                | CPUID_7_EBX_AVX512CD
                | CPUID_7_EBX_AVX512DQ
                | CPUID_7_EBX_AVX512VL;
            self.leaf7_ebx & MASK == MASK
        }

        // The ISA levels the CPU supports, as the GNU_PROPERTY_X86_ISA_1 bits
        // (glibc get_isa_level), each one requiring the previous ones.
        fn isa_level(self) -> u32 {
            let usable = self.usable();
            let levels = [
                (GNU_PROPERTY_X86_ISA_1_BASELINE, usable.check_basic()),
                (GNU_PROPERTY_X86_ISA_1_V2, usable.check_v2()),
                (GNU_PROPERTY_X86_ISA_1_V3, usable.check_v3()),
                (GNU_PROPERTY_X86_ISA_1_V4, usable.check_v4()),
            ];
            levels
                .iter()
                .take_while(|(_, supported)| *supported)
                .fold(0, |r, (level, _)| r | level)
        }
    }

    // The glibc-hwcaps subdirectories for the ISA levels, best first (glibc
    // sysdeps/x86_64/dl-hwcaps-subdirs.c).
    fn subdirs(isa_level: u32) -> Vec<&'static str> {
        [
            (GNU_PROPERTY_X86_ISA_1_V4, "x86-64-v4"),
            (GNU_PROPERTY_X86_ISA_1_V3, "x86-64-v3"),
            (GNU_PROPERTY_X86_ISA_1_V2, "x86-64-v2"),
        ]
        .iter()
        .filter(|(level, _)| isa_level & level != 0)
        .map(|(_, subdir)| *subdir)
        .collect()
    }

    // The x86-64 and x32 loaders have glibc-hwcaps subdirectories
    // (sysdeps/x86_64/dl-hwcaps-subdirs.c) while the i386 one has none, and
    // all of them check the ISA level of the glibc-hwcaps cache entries
    // (sysdeps/x86/dl-isa-level.h).
    pub fn loader_hwcaps(
        e_machine: Machine,
        ei_class: FileClass,
        ei_data: DataEncoding,
    ) -> LoaderHwcaps {
        let x86_64 = e_machine == EM_X86_64 && matches!(ei_class, ELFCLASS32 | ELFCLASS64);
        let i386 = e_machine == EM_386 && ei_class == ELFCLASS32;
        if ei_data != ELFDATA2LSB || !(x86_64 || i386) {
            return LoaderHwcaps::default();
        }
        let features = Features::read();
        let isa_level = features.isa_level();
        if x86_64 {
            LoaderHwcaps {
                // Priority sorted, best-fit first (the glibc _dl_hwcaps_subdirs order).
                subdirs: subdirs(isa_level),
                isa_levels: Some(isa_level),
                legacy: features.legacy_x86_64(),
            }
        } else {
            LoaderHwcaps {
                subdirs: Vec::new(),
                isa_levels: Some(isa_level),
                legacy: features.legacy_i386(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // A CPU with the CPUID features of the x86-64 LEVEL (1 for the
        // baseline) and every state component enabled.
        fn cpu(level: u32) -> Features {
            let mut f = Features {
                xcr0: 0xe7,
                ..Default::default()
            };
            if level >= 1 {
                f.leaf1_edx = CPUID_1_EDX_FPU
                    | CPUID_1_EDX_CX8
                    | CPUID_1_EDX_CMOV
                    | CPUID_1_EDX_MMX
                    | CPUID_1_EDX_FXSR
                    | CPUID_1_EDX_SSE
                    | CPUID_1_EDX_SSE2;
            }
            if level >= 2 {
                f.leaf1_ecx |= CPUID_1_ECX_SSE3
                    | CPUID_1_ECX_SSSE3
                    | CPUID_1_ECX_CMPXCHG16B
                    | CPUID_1_ECX_SSE41
                    | CPUID_1_ECX_SSE42
                    | CPUID_1_ECX_POPCNT;
                f.ext1_ecx |= CPUID_EXT1_ECX_LAHF_SAHF;
            }
            if level >= 3 {
                f.leaf1_ecx |= CPUID_1_ECX_FMA
                    | CPUID_1_ECX_MOVBE
                    | CPUID_1_ECX_OSXSAVE
                    | CPUID_1_ECX_AVX
                    | CPUID_1_ECX_F16C;
                f.leaf7_ebx |= CPUID_7_EBX_BMI1 | CPUID_7_EBX_AVX2 | CPUID_7_EBX_BMI2;
                f.ext1_ecx |= CPUID_EXT1_ECX_LZCNT;
            }
            if level >= 4 {
                f.leaf7_ebx |= CPUID_7_EBX_AVX512F
                    | CPUID_7_EBX_AVX512DQ
                    | CPUID_7_EBX_AVX512CD
                    | CPUID_7_EBX_AVX512BW
                    | CPUID_7_EBX_AVX512VL;
            }
            f
        }

        fn levels(f: Features) -> Vec<&'static str> {
            subdirs(f.isa_level())
        }

        #[test]
        fn isa_levels() {
            assert_eq!(levels(cpu(0)), Vec::<&str>::new());
            assert_eq!(levels(cpu(1)), Vec::<&str>::new());
            assert_eq!(levels(cpu(2)), ["x86-64-v2"]);
            assert_eq!(levels(cpu(3)), ["x86-64-v3", "x86-64-v2"]);
            assert_eq!(levels(cpu(4)), ["x86-64-v4", "x86-64-v3", "x86-64-v2"]);
            // Each level requires the previous ones.
            let mut f = cpu(4);
            f.ext1_ecx &= !CPUID_EXT1_ECX_LAHF_SAHF;
            assert_eq!(levels(f), Vec::<&str>::new());
        }

        #[test]
        fn isa_levels_need_avx2() {
            let mut f = cpu(4);
            f.leaf7_ebx &= !CPUID_7_EBX_AVX2;
            assert_eq!(levels(f), ["x86-64-v2"]);
        }

        #[test]
        fn isa_levels_need_the_os_vector_state() {
            // Without the AVX state, the AVX and AVX-512 features are not
            // usable, and without the AVX-512 state the latter are not.
            for xcr0 in [0, XSTATE_SSE, XSTATE_YMM] {
                let f = Features { xcr0, ..cpu(4) };
                assert_eq!(levels(f), ["x86-64-v2"]);
            }
            for xcr0 in [0x7, 0x67, 0xa7, 0xc7] {
                let f = Features { xcr0, ..cpu(4) };
                assert_eq!(levels(f), ["x86-64-v3", "x86-64-v2"]);
            }
            // The AVX-512 state without the AVX one.
            let f = Features {
                xcr0: 0xe3,
                ..cpu(4)
            };
            assert_eq!(levels(f), ["x86-64-v2"]);
        }

        #[test]
        fn legacy_hwcaps() {
            const TLS: u64 = super::super::HWCAP_TLS;
            // Any CPU has the x86_64 bit, and the TLS one is always taken.
            let amd = cpu(4).legacy_x86_64();
            assert!(amd.check(0) && amd.check(TLS) && amd.check(HWCAP_X86_64 | TLS));
            // Neither the i386 bit, nor an Intel only one, nor a platform
            // (there is none), nor any unknown one.
            for hwcap in [
                HWCAP_X86_SSE2,
                HWCAP_X86_AVX512_1,
                PLATFORM_HASWELL,
                PLATFORM_I686,
                1 << 3,
            ] {
                assert!(!amd.check(hwcap));
            }

            // An Intel CPU with AVX-512 has the avx512_1 bit and the haswell
            // platform, and the Xeon Phi one the xeon_phi platform instead.
            let intel = Features {
                intel: true,
                ..cpu(4)
            };
            let skylake = intel.legacy_x86_64();
            assert!(skylake.check(HWCAP_X86_64 | HWCAP_X86_AVX512_1 | PLATFORM_HASWELL));
            assert!(!skylake.check(PLATFORM_XEON_PHI));
            let mut knl = intel;
            knl.leaf7_ebx |= CPUID_7_EBX_AVX512ER | CPUID_7_EBX_AVX512PF;
            let knl = knl.legacy_x86_64();
            assert!(knl.check(PLATFORM_XEON_PHI));
            assert!(!knl.check(HWCAP_X86_AVX512_1) && !knl.check(PLATFORM_HASWELL));
            // Without the AVX state, neither.
            let legacy = Features { xcr0: 0, ..intel }.legacy_x86_64();
            assert!(!legacy.check(HWCAP_X86_AVX512_1) && !legacy.check(PLATFORM_HASWELL));

            // The i386 loader has the sse2 bit and the i686 platform.
            let i386 = cpu(1).legacy_i386();
            assert!(i386.check(HWCAP_X86_SSE2 | PLATFORM_I686 | TLS));
            assert!(!i386.check(PLATFORM_I586));
            assert!(!i386.check(HWCAP_X86_64) && !i386.check(PLATFORM_HASWELL));
        }

        #[test]
        fn loader_hwcaps_by_abi() {
            use object::elf::{ELFDATA2MSB, EM_PPC64};

            // The x86-64 and x32 loaders search the subdirectories of the CPU
            // levels, and the i386 one none, while all check the ISA level of
            // the cache entries.
            let isa_level = Features::read().isa_level();
            for ei_class in [ELFCLASS64, ELFCLASS32] {
                let hwcaps = loader_hwcaps(EM_X86_64, ei_class, ELFDATA2LSB);
                assert_eq!(hwcaps.subdirs, subdirs(isa_level));
                assert_eq!(hwcaps.isa_levels, Some(isa_level));
            }
            let i386 = loader_hwcaps(EM_386, ELFCLASS32, ELFDATA2LSB);
            assert!(i386.subdirs.is_empty());
            assert_eq!(i386.isa_levels, Some(isa_level));
            // The CPU does not run the other architectures objects.
            for (e_machine, ei_class, ei_data) in [
                (EM_PPC64, ELFCLASS64, ELFDATA2LSB),
                (EM_X86_64, ELFCLASS64, ELFDATA2MSB),
            ] {
                let hwcaps = loader_hwcaps(e_machine, ei_class, ei_data);
                assert_eq!(hwcaps, LoaderHwcaps::default());
            }
        }
    }
}

// The subdirectories of LEVELS (from the lowest, each with the capability
// bits it needs) the HWCAP bits support, best first: each level also needs
// the lower ones, as _dl_hwcaps_subdirs_active tests them.
#[cfg(any(test, target_arch = "powerpc64", target_arch = "s390x"))]
fn active_subdirs(hwcap: u64, levels: &[(&'static str, u64)]) -> Vec<&'static str> {
    let mut r: Vec<&'static str> = levels
        .iter()
        .take_while(|(_, mask)| hwcap & mask == *mask)
        .map(|(subdir, _)| *subdir)
        .collect();
    r.reverse();
    r
}

// The little-endian powerpc64 subdirectories for the AT_HWCAP2 bits (glibc
// sysdeps/powerpc/powerpc64/le/dl-hwcaps-subdirs.c).
#[cfg(any(test, target_arch = "powerpc64"))]
fn power_subdirs(hwcap2: u64) -> Vec<&'static str> {
    const PPC_FEATURE2_ARCH_3_00: u64 = 0x00800000; // ISA 3.0
    const PPC_FEATURE2_HAS_IEEE128: u64 = 0x00400000; // VSX IEEE Binary Float 128-bit
    const PPC_FEATURE2_ARCH_3_1: u64 = 0x00040000; // ISA 3.1
    const PPC_FEATURE2_MMA: u64 = 0x00020000; //  Matrix-Multiply Assist
    active_subdirs(
        hwcap2,
        &[
            ("power9", PPC_FEATURE2_ARCH_3_00 | PPC_FEATURE2_HAS_IEEE128),
            ("power10", PPC_FEATURE2_ARCH_3_1 | PPC_FEATURE2_MMA),
        ],
    )
}

// The s390x subdirectories for the AT_HWCAP bits (glibc
// sysdeps/s390/s390-64/dl-hwcaps-subdirs.c).  glibc 2.42 adds z17 above
// z16, which is not checked (it tests the facility list of the stfle
// instruction rather than an AT_HWCAP bit).
#[cfg(any(test, target_arch = "s390x"))]
fn s390_subdirs(hwcap: u64) -> Vec<&'static str> {
    const HWCAP_S390_VX: u64 = 1 << 11;
    const HWCAP_S390_VXD: u64 = 1 << 12;
    const HWCAP_S390_VXE: u64 = 1 << 13;
    const HWCAP_S390_GS: u64 = 1 << 14;
    const HWCAP_S390_VXRS_EXT2: u64 = 1 << 15;
    const HWCAP_S390_VXRS_PDE: u64 = 1 << 16;
    const HWCAP_S390_VXRS_PDE2: u64 = 1 << 19;
    active_subdirs(
        hwcap,
        &[
            ("z13", HWCAP_S390_VX),
            ("z14", HWCAP_S390_VXD | HWCAP_S390_VXE | HWCAP_S390_GS),
            ("z15", HWCAP_S390_VXRS_EXT2 | HWCAP_S390_VXRS_PDE),
            ("z16", HWCAP_S390_VXRS_PDE2),
        ],
    )
}

#[cfg(target_arch = "powerpc64")]
mod cpuid {
    mod auxv;

    use object::elf::{DataEncoding, FileClass, Machine, ELFCLASS64, ELFDATA2LSB, EM_PPC64};

    use super::LoaderHwcaps;

    // Only the little-endian ABI has glibc-hwcaps subdirectories
    // (sysdeps/powerpc/powerpc64/le/dl-hwcaps-subdirs.c).
    pub fn loader_hwcaps(
        e_machine: Machine,
        ei_class: FileClass,
        ei_data: DataEncoding,
    ) -> LoaderHwcaps {
        let mut r = LoaderHwcaps::default();
        if e_machine == EM_PPC64 && ei_class == ELFCLASS64 && ei_data == ELFDATA2LSB {
            // Priority sorted, best-fit first (the glibc _dl_hwcaps_subdirs order).
            r.subdirs = auxv::getauxval(auxv::AT_HWCAP2)
                .map(|hwcap2| super::power_subdirs(hwcap2 as u64))
                .unwrap_or_default();
        }
        r
    }
}

#[cfg(target_arch = "s390x")]
mod cpuid {
    mod auxv;

    use object::elf::{DataEncoding, FileClass, Machine, ELFCLASS64, ELFDATA2MSB, EM_S390};

    use super::LoaderHwcaps;

    // Only the 64-bit ABI has glibc-hwcaps subdirectories
    // (sysdeps/s390/s390-64/dl-hwcaps-subdirs.c).
    pub fn loader_hwcaps(
        e_machine: Machine,
        ei_class: FileClass,
        ei_data: DataEncoding,
    ) -> LoaderHwcaps {
        let mut r = LoaderHwcaps::default();
        if e_machine == EM_S390 && ei_class == ELFCLASS64 && ei_data == ELFDATA2MSB {
            // Priority sorted, best-fit first (the glibc _dl_hwcaps_subdirs order).
            r.subdirs = auxv::getauxval(auxv::AT_HWCAP)
                .map(|hwcap| super::s390_subdirs(hwcap as u64))
                .unwrap_or_default();
        }
        r
    }
}

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "powerpc64",
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "s390x"
    ))
))]
mod cpuid {
    use object::elf::{DataEncoding, FileClass, Machine};

    use super::LoaderHwcaps;

    // The other architectures have no glibc-hwcaps subdirectories, and the
    // host can only run the objects of its own (or a compatible) one.
    pub fn loader_hwcaps(
        _e_machine: Machine,
        _ei_class: FileClass,
        _ei_data: DataEncoding,
    ) -> LoaderHwcaps {
        LoaderHwcaps::default()
    }
}

// The capabilities of this machine the glibc loader for an object ABI (its
// machine, class and data encoding) uses.  Only the objects the host CPU runs
// get any, and none when they can not be read (the auxiliary vector on a
// chroot without /proc).
pub fn loader_hwcaps(
    e_machine: Machine,
    ei_class: FileClass,
    ei_data: DataEncoding,
) -> LoaderHwcaps {
    cpuid::loader_hwcaps(e_machine, ei_class, ei_data)
}

// The glibc-hwcaps subdirectories the glibc loader for an object ABI (its
// machine, class and data encoding) searches on this machine, best first:
// the glibc _dl_hwcaps_subdirs of the ABI the CPU supports
// (_dl_hwcaps_subdirs_active).  Only x86-64 (and x32), little-endian
// powerpc64 and s390x have them, and only the objects the host CPU runs get
// them, so the list is empty for any other ABI (i386 on a x86-64 host, for
// instance), and when the CPU capabilities can not be read.
pub fn glibc_hwcaps_subdirs(
    e_machine: Machine,
    ei_class: FileClass,
    ei_data: DataEncoding,
) -> Vec<&'static str> {
    loader_hwcaps(e_machine, ei_class, ei_data).subdirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glibc_hwcaps_subdirs_for_other_abis() {
        // The ABIs without glibc-hwcaps subdirectories, or one the host CPU
        // does not run.
        for (e_machine, ei_class, ei_data) in [
            (EM_386, ELFCLASS32, ELFDATA2LSB),
            (EM_X86_64, ELFCLASS64, ELFDATA2MSB),
            (EM_AARCH64, ELFCLASS64, ELFDATA2LSB),
            (EM_S390, ELFCLASS32, ELFDATA2MSB),
            (EM_PPC64, ELFCLASS64, ELFDATA2MSB),
            (EM_PPC, ELFCLASS32, ELFDATA2MSB),
            (EM_RISCV, ELFCLASS64, ELFDATA2LSB),
        ] {
            assert!(glibc_hwcaps_subdirs(e_machine, ei_class, ei_data).is_empty());
        }
    }

    #[test]
    fn power_levels() {
        // POWER10 needs POWER9 as well.
        assert!(power_subdirs(0).is_empty());
        assert!(power_subdirs(0x00060000).is_empty());
        assert_eq!(power_subdirs(0x00c00000), ["power9"]);
        assert_eq!(power_subdirs(0x00800000 | 0x00060000), Vec::<&str>::new());
        assert_eq!(power_subdirs(0x00c60000), ["power10", "power9"]);
    }

    #[test]
    fn s390_levels() {
        // Each level needs the lower ones.
        assert!(s390_subdirs(0).is_empty());
        assert!(s390_subdirs(1 << 19).is_empty());
        assert_eq!(s390_subdirs(1 << 11 | 1 << 19), ["z13"]);
        // z14 needs VXD, VXE and GS.
        assert_eq!(s390_subdirs(0x7 << 11), ["z13"]);
        assert_eq!(s390_subdirs(0xf << 11), ["z14", "z13"]);
        assert_eq!(s390_subdirs(0x3f << 11), ["z15", "z14", "z13"]);
        assert_eq!(
            s390_subdirs(0x3f << 11 | 1 << 19),
            ["z16", "z15", "z14", "z13"]
        );
    }
}
