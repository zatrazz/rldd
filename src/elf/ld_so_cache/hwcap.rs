#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod cpuid {
    use raw_cpuid::CpuId;

    fn check_basic(features: &raw_cpuid::FeatureInfo) -> bool {
        features.has_cmov()
            && features.has_cmpxchg8b()
            && features.has_fpu()
            && features.has_fxsave_fxstor()
            && features.has_mmx()
            && features.has_sse()
            && features.has_sse2()
    }

    fn check_v2(
        features: &raw_cpuid::FeatureInfo,
        extended: &raw_cpuid::ExtendedProcessorFeatureIdentifiers,
    ) -> bool {
        features.has_cmpxchg16b()
            && extended.has_lahf_sahf()
            && features.has_popcnt()
            && features.has_sse3()
            && features.has_ssse3()
            && features.has_sse41()
            && features.has_sse42()
    }

    fn check_v3(
        features: &raw_cpuid::FeatureInfo,
        extended_identifiers: &raw_cpuid::ExtendedProcessorFeatureIdentifiers,
        extended_features: &raw_cpuid::ExtendedFeatures,
    ) -> bool {
        features.has_avx()
            && extended_features.has_bmi1()
            && extended_features.has_bmi2()
            && features.has_f16c()
            && features.has_fma()
            && extended_identifiers.has_lzcnt()
            && features.has_movbe()
    }

    fn check_v4(extended: &raw_cpuid::ExtendedFeatures) -> bool {
        extended.has_avx512f()
            && extended.has_avx512bw()
            && extended.has_avx512cd()
            && extended.has_avx512dq()
            && extended.has_avx512vl()
    }

    pub fn supported() -> Result<Vec<&'static str>, std::io::Error> {
        let mut r = vec![];

        let cpuid = CpuId::new();

        if let (Some(features), Some(extended_identifiers)) = (
            cpuid.get_feature_info(),
            cpuid.get_extended_processor_and_feature_identifiers(),
        ) {
            if check_basic(&features) && check_v2(&features, &extended_identifiers) {
                if let Some(extended_features) = cpuid.get_extended_feature_info() {
                    if check_v3(&features, &extended_identifiers, &extended_features) {
                        if check_v4(&extended_features) {
                            r.push("x86-64-v4");
                        }
                        r.push("x86-64-v3");
                    }
                }
                r.push("x86-64-v2");
            }
        }
        Ok(r)
    }
}

#[cfg(any(target_arch = "powerpc64"))]
pub mod cpuid {
    mod auxv;

    pub const PPC_FEATURE2_ARCH_3_00: auxv::AuxvType = 0x00800000; // ISA 3.0
    pub const PPC_FEATURE2_HAS_IEEE128: auxv::AuxvType = 0x00400000; // VSX IEEE Binary Float 128-bit
    pub const PPC_FEATURE2_ARCH_3_1: auxv::AuxvType = 0x00040000; // ISA 3.1
    pub const PPC_FEATURE2_MMA: auxv::AuxvType = 0x00020000; //  Matrix-Multiply Assist

    pub fn supported() -> Result<Vec<&'static str>, std::io::Error> {
        let mut r = vec![];
        let hwcap2 = auxv::getauxval(auxv::AT_HWCAP2)?;
        if hwcap2 & PPC_FEATURE2_ARCH_3_00 != 0 && hwcap2 & PPC_FEATURE2_HAS_IEEE128 != 0 {
            r.push("power9");
        }
        if hwcap2 & PPC_FEATURE2_ARCH_3_1 != 0 && hwcap2 & PPC_FEATURE2_MMA != 0 {
            r.push("power10");
        }
        Ok(r)
    }
}

#[cfg(any(target_arch = "s390x"))]
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
        let mut r = vec![];
        let hwcap = auxv::getauxval(auxv::AT_HWCAP)?;
        if hwcap & HWCAP_S390_VX != 0 {
            r.push("z13");
        }
        if hwcap & HWCAP_S390_VXD != 0
            && hwcap & HWCAP_S390_VXE != 0
            && hwcap & HWCAP_S390_GS != 0
        {
            r.push("z14");
        }
        if hwcap & HWCAP_S390_VXRS_EXT2 != 0 && hwcap & HWCAP_S390_VXRS_PDE != 0 {
            r.push("z15");
        }
        if hwcap & HWCAP_S390_VXRS_PDE2 != 0 {
            r.push("z16");
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
    pub fn supported() -> Vec<&'static str> {
        vec![]
    }
}

pub fn hwcap_supported() -> Result<Vec<&'static str>, std::io::Error> {
    cpuid::supported()
}
