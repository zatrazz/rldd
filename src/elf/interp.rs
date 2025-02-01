// Program Interpreter handling functions

use std::path::Path;

use crate::pathutils;

const GLIBC_INTERP: &[&str] = &[
    "ld-linux-aarch64.so.1",         // AArch64 little-endian.
    "ld-linux-aarch64_be.so.1",      // Aarch64 big-endian.
    "ld-linux-arc.so.2",             // ARC little-endian.
    "ld-linux-arceb.so.2",           // ARC big-endian.
    "ld-linux-armhf.so.3",           // ARM with hard-fp.
    "ld-linux-cskyv2-hf.so.1",       // CSKY with hard-fp.
    "ld-linux-cskyv2.so.1",          // CSKY with soft-fp.
    "ld-linux-ia64.so.2",            // Itanium.
    "ld-linux-loongarch-lp64d.so.1", // loongarch with double fp.
    "ld-linux-loongarch-lp64s.so.1", // loongarch with single fp.
    "ld-linux-mipsn8.so.1",          // MIPS with NAN2008.
    "ld-linux-nios2.so.1",           // NIOS2.
    "ld-linux-or1k.so.1",            // OpenRISC.
    "ld-linux-riscv32-ilp32.so.1",   // riscv32 soft-fp.
    "ld-linux-riscv32-ilp32d.so.1",  // riscv32.
    "ld-linux-riscv64-lp64.so.1",    // riscv64 soft-fp.
    "ld-linux-riscv64-lp64d.so.1",   // riscv64.
    "ld-linux-x32.so.2",             // x86_64 x32.
    "ld-linux-x86-64.so.2",          // x86_64.
    "ld-linux.so.2",                 // sh, sparc, alpha, and i386.
    "ld-linux.so.3",                 // arm.
    "ld.so.1",                       // Default for 32 bits, mips, and hppa.
    "ld64.so.1",                     // powerpc64 ELFv1 and s390x.
    "ld64.so.2",                     // powerpc64 ELFv2.
];

pub fn is_glibc(interp: &Option<String>) -> bool {
    /*
    if let Some(interp) = get_interp_name(interp) {
        return GLIBC_INTERP.contains(&interp);
    }
    false
    */
    if let Some(interp) = interp {
        return GLIBC_INTERP.contains(&pathutils::get_name(&Path::new(interp)).as_str());
    }
    false
}

// musl interp is in the form of ld-musl-$(ARCH)$(SUBARCH).so.1
const MUSL_SUBARCH_MIPS: &[&str] = &["r6", "r6el", "el", "r6-sf", "r6el-sf", "el-sf"];

const MUSL_SUBARCH_SH: &[&str] = &[
    "eb",
    "-nofpu",
    "-fdpic",
    "eb-nofpu",
    "eb-nofpu",
    "eb-fdpic",
    "eb-nofpu-fdpic",
];

fn check_name_suffix(interp: &str, abi: &str, suffixes: Option<&Vec<&str>>) -> bool {
    if interp.starts_with(abi) {
        if interp.len() == abi.len() {
            return true;
        }
        if let Some(interp) = interp.get(abi.len()..) {
            if let Some(suffixes) = suffixes {
                for suffix in suffixes {
                    if interp == *suffix {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn is_musl_arch(interp: &str) -> bool {
    if interp.starts_with("arm") {
        return check_name_suffix(interp, "arm", Some(&vec!["eb", "hf", "ebhf"]));
    } else if interp.starts_with("aarch64") {
        return check_name_suffix(interp, "aarch64", Some(&vec!["_be"]));
    } else if interp.starts_with("m68k") {
        return check_name_suffix(interp, "arm", Some(&vec!["-fp64", "-sf"]));
    } else if interp.starts_with("mips64") {
        return check_name_suffix(interp, "mips64", Some(&MUSL_SUBARCH_MIPS.to_vec()));
    } else if interp.starts_with("mipsn32") {
        return check_name_suffix(interp, "mipsn32", Some(&MUSL_SUBARCH_MIPS.to_vec()));
    } else if interp.starts_with("mips") {
        return check_name_suffix(interp, "mips", Some(&MUSL_SUBARCH_MIPS.to_vec()));
    } else if interp.starts_with("powerpc64") {
        return check_name_suffix(interp, "powerpc64", Some(&vec!["le"]));
    } else if interp.starts_with("powerpc") {
        return check_name_suffix(interp, "powerpc", Some(&vec!["sf"]));
    } else if interp.starts_with("microblaze") {
        return check_name_suffix(interp, "microblaze", Some(&vec!["el"]));
    } else if interp.starts_with("riscv64") {
        return check_name_suffix(interp, "riscv64", Some(&vec!["sf", "-sf-sp", "-sp"]));
    } else if interp.starts_with("sh") {
        return check_name_suffix(interp, "riscv64", Some(&MUSL_SUBARCH_SH.to_vec()));
    } else if ["nt32", "nt64", "or1k", "s390x", "x86_64", "x32", "i386"].contains(&interp) {
        return true;
    }
    false
}

pub fn is_musl(interp: &Option<String>) -> bool {
    if let Some(interp) = interp {
        let interp = &pathutils::get_name(&Path::new(interp));
        if !interp.starts_with("ld-musl-") {
            return false;
        }
        let v: Vec<&str> = interp.split('.').collect();
        if v.len() != 3 || v[1] != "so" || v[2] != "1" {
            return false;
        }
        let interp = v[0];

        if let Some(interp) = interp.get("ld-musl-".len()..) {
            return is_musl_arch(interp);
        }
    };
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_is_musl() {
        assert_eq!(is_musl(&None), false);
        assert_eq!(is_musl(&Some("ld-linux-aarch64.so.1".to_string())), false);
        assert_eq!(is_musl(&Some("ld-musl-aarch64.so".to_string())), false);
        assert_eq!(is_musl(&Some("ld-musl-aarch64.so.1".to_string())), true);
        assert_eq!(is_musl(&Some("ld-musl-aarch64_be.so.1".to_string())), true);
        assert_eq!(
            is_musl(&Some("/lib/ld-musl-aarch64.so.1".to_string())),
            true
        );
        assert_eq!(is_musl(&Some("/lib/ld-musl-x86_64.so.1".to_string())), true);
    }
}
