#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod cpuid {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{__cpuid, __cpuid_count, _xgetbv};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

    use object::elf::{
        GNU_PROPERTY_X86_ISA_1_BASELINE, GNU_PROPERTY_X86_ISA_1_V2, GNU_PROPERTY_X86_ISA_1_V3,
        GNU_PROPERTY_X86_ISA_1_V4,
    };

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

    // The feature registers required by the x86-64 microarchitecture levels,
    // zeroed when the CPU does not report the leaf, and the state components
    // the OS enables (zero without XSAVE enabled).
    #[derive(Clone, Copy, Debug, Default)]
    struct Features {
        leaf1_edx: u32,
        leaf1_ecx: u32,
        leaf7_ebx: u32,
        ext1_ecx: u32,
        xcr0: u64,
    }

    impl Features {
        fn read() -> Self {
            // CPUID is unconditionally available on x86-64 and on the i686
            // baseline, so the leaf 0 query needs no prior check.
            let max_basic = __cpuid(0).eax;
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
                    | CPUID_7_EBX_AVX512VL);
            }
            r
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

    pub fn supported() -> Result<Vec<&'static str>, std::io::Error> {
        // Priority sorted, best-fit first (the glibc _dl_hwcaps_subdirs order).
        Ok(subdirs(Features::read().isa_level()))
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
    }
}

#[cfg(target_arch = "powerpc64")]
pub mod cpuid {
    mod auxv;

    pub const PPC_FEATURE2_ARCH_3_00: auxv::AuxvType = 0x00800000; // ISA 3.0
    pub const PPC_FEATURE2_HAS_IEEE128: auxv::AuxvType = 0x00400000; // VSX IEEE Binary Float 128-bit
    pub const PPC_FEATURE2_ARCH_3_1: auxv::AuxvType = 0x00040000; // ISA 3.1
    pub const PPC_FEATURE2_MMA: auxv::AuxvType = 0x00020000; //  Matrix-Multiply Assist

    pub fn supported() -> Result<Vec<&'static str>, std::io::Error> {
        // Priority sorted, best-fit first (the glibc _dl_hwcaps_subdirs order).
        let mut r = vec![];
        let hwcap2 = auxv::getauxval(auxv::AT_HWCAP2)?;
        if hwcap2 & PPC_FEATURE2_ARCH_3_1 != 0 && hwcap2 & PPC_FEATURE2_MMA != 0 {
            r.push("power10");
        }
        if hwcap2 & PPC_FEATURE2_ARCH_3_00 != 0 && hwcap2 & PPC_FEATURE2_HAS_IEEE128 != 0 {
            r.push("power9");
        }
        Ok(r)
    }
}

#[cfg(target_arch = "s390x")]
pub mod cpuid {
    mod auxv;

    // s390x AT_HWCAP
    pub const HWCAP_S390_VX: auxv::AuxvType = 1 << 11;
    pub const HWCAP_S390_VXD: auxv::AuxvType = 1 << 12;
    pub const HWCAP_S390_VXE: auxv::AuxvType = 1 << 13;
    pub const HWCAP_S390_GS: auxv::AuxvType = 1 << 14;
    pub const HWCAP_S390_VXRS_EXT2: auxv::AuxvType = 1 << 15;
    pub const HWCAP_S390_VXRS_PDE: auxv::AuxvType = 1 << 16;
    pub const HWCAP_S390_VXRS_PDE2: auxv::AuxvType = 1 << 19;

    pub fn supported() -> Result<Vec<&'static str>, std::io::Error> {
        // Priority sorted, best-fit first (the glibc _dl_hwcaps_subdirs order).
        let mut r = vec![];
        let hwcap = auxv::getauxval(auxv::AT_HWCAP)?;
        if hwcap & HWCAP_S390_VXRS_PDE2 != 0 {
            r.push("z16");
        }
        if hwcap & HWCAP_S390_VXRS_EXT2 != 0 && hwcap & HWCAP_S390_VXRS_PDE != 0 {
            r.push("z15");
        }
        if hwcap & HWCAP_S390_VXD != 0 && hwcap & HWCAP_S390_VXE != 0 && hwcap & HWCAP_S390_GS != 0
        {
            r.push("z14");
        }
        if hwcap & HWCAP_S390_VX != 0 {
            r.push("z13");
        }
        Ok(r)
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
pub mod cpuid {
    pub fn supported() -> Result<Vec<&'static str>, std::io::Error> {
        Ok(vec![])
    }
}

pub fn hwcap_supported() -> Result<Vec<&'static str>, std::io::Error> {
    cpuid::supported()
}
