#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod cpuid {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{__cpuid, __cpuid_count};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{__cpuid, __cpuid_count};

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
    const CPUID_1_ECX_AVX: u32 = 1 << 28;
    const CPUID_1_ECX_F16C: u32 = 1 << 29;

    // CPUID.(EAX=7,ECX=0):EBX
    const CPUID_7_EBX_BMI1: u32 = 1 << 3;
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

    // The feature registers required by the x86-64 microarchitecture levels,
    // zeroed when the CPU does not report the leaf.
    struct Features {
        leaf1_edx: u32,
        leaf1_ecx: u32,
        leaf7_ebx: u32,
        ext1_ecx: u32,
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
            let ext1_ecx = if max_extended >= LEAF_EXTENDED + 1 {
                __cpuid(LEAF_EXTENDED + 1).ecx
            } else {
                0
            };
            Self {
                leaf1_edx,
                leaf1_ecx,
                leaf7_ebx,
                ext1_ecx,
            }
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
            const LEAF7_MASK: u32 = CPUID_7_EBX_BMI1 | CPUID_7_EBX_BMI2;
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
    }

    pub fn supported() -> Result<Vec<&'static str>, std::io::Error> {
        // Priority sorted, best-fit first (the glibc _dl_hwcaps_subdirs order).
        let mut r = vec![];

        let features = Features::read();
        if features.check_basic() && features.check_v2() {
            if features.check_v3() {
                if features.check_v4() {
                    r.push("x86-64-v4");
                }
                r.push("x86-64-v3");
            }
            r.push("x86-64-v2");
        }
        Ok(r)
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
