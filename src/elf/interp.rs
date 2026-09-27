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

pub fn is_glibc_name(name: &str) -> bool {
    GLIBC_INTERP.contains(&name)
}

// The known glibc loader sonames, used to resolve the loader when the object
// does not have a PT_INTERP segment (only the one matching the object
// architecture resolves through the loader cache and system directories).
pub fn glibc_names() -> &'static [&'static str] {
    GLIBC_INTERP
}

pub fn is_glibc(interp: &Option<String>) -> bool {
    match interp {
        Some(interp) => is_glibc_name(pathutils::get_name(&Path::new(interp)).as_str()),
        // Shared libraries do not have a PT_INTERP segment, so assume the system
        // loader (glibc) to resolve their dependencies (it also mimics ldd, which
        // always uses the system loader).
        None => true,
    }
}

// musl interp is in the form of ld-musl-$(ARCH)$(SUBARCH).so.1, where the
// musl configure script appends the SUBARCH variants of each ARCH in this
// order (for instance the ISA revision, then the endianness, then the float
// ABI on MIPS).
const MUSL_SUBARCH_MIPS: &[&str] = &["", "r6", "el", "r6el", "-sf", "r6-sf", "el-sf", "r6el-sf"];

const MUSL_ARCHS: &[(&str, &[&str])] = &[
    ("aarch64", &["", "_be"]),
    ("arm", &["", "eb", "hf", "ebhf"]),
    ("i386", &[""]),
    // The soft and single float ABIs are exclusive.
    ("loongarch64", &["", "-sf", "-sp"]),
    ("m68k", &["", "-fp64", "-sf"]),
    ("microblaze", &["", "el"]),
    ("mips", MUSL_SUBARCH_MIPS),
    ("mips64", MUSL_SUBARCH_MIPS),
    ("mipsn32", MUSL_SUBARCH_MIPS),
    ("nt32", &[""]),
    ("nt64", &[""]),
    ("or1k", &[""]),
    ("powerpc", &["", "-sf"]),
    ("powerpc64", &["", "le"]),
    ("riscv32", &["", "-sf", "-sp"]),
    ("riscv64", &["", "-sf", "-sp"]),
    ("s390x", &[""]),
    // The -nofpu variant is the one without an FPU.
    (
        "sh",
        &[
            "",
            "eb",
            "-nofpu",
            "eb-nofpu",
            "-fdpic",
            "eb-fdpic",
            "-nofpu-fdpic",
            "eb-nofpu-fdpic",
        ],
    ),
    ("x32", &[""]),
    ("x86_64", &[""]),
];

fn is_musl_arch(interp: &str) -> bool {
    MUSL_ARCHS.iter().any(|(arch, suffixes)| {
        interp
            .strip_prefix(arch)
            .is_some_and(|suffix| suffixes.contains(&suffix))
    })
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

// The library names the musl loader provides itself.
const MUSL_RESERVED: &[&str] = &["c.", "pthread.", "rt.", "m.", "dl.", "util.", "xnet."];
pub const MUSL_RESERVED_COUNT: usize = 7;

pub fn musl_reserved_name(name: &str) -> Option<usize> {
    let rest = name.strip_prefix("lib")?;
    MUSL_RESERVED
        .iter()
        .position(|prefix| rest.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_musl_reserved_name() {
        assert_eq!(musl_reserved_name("libc.so"), Some(0));
        assert_eq!(musl_reserved_name("libc.musl-x86_64.so.1"), Some(0));
        assert_eq!(musl_reserved_name("libpthread.so.0"), Some(1));
        assert_eq!(musl_reserved_name("libm.so.6"), Some(3));
        assert_eq!(musl_reserved_name("libutil.c32"), Some(5));
        assert_eq!(musl_reserved_name("libxnet.so"), Some(6));
        assert_eq!(musl_reserved_name("libmenu.c32"), None);
        assert_eq!(musl_reserved_name("libcom32.c32"), None);
        assert_eq!(musl_reserved_name("libz.so.1"), None);
        assert_eq!(musl_reserved_name("ld-musl-x86_64.so.1"), None);
    }

    #[test]
    fn check_is_musl() {
        assert!(!is_musl(&None));
        assert!(!is_musl(&Some("ld-linux-aarch64.so.1".to_string())));
        assert!(!is_musl(&Some("ld-musl-aarch64.so".to_string())));
        assert!(is_musl(&Some("ld-musl-aarch64.so.1".to_string())));
        assert!(is_musl(&Some("ld-musl-aarch64_be.so.1".to_string())));
        assert!(is_musl(&Some("/lib/ld-musl-aarch64.so.1".to_string())));
        assert!(is_musl(&Some("/lib/ld-musl-x86_64.so.1".to_string())));
        assert!(is_musl(&Some("ld-musl-m68k.so.1".to_string())));
        assert!(is_musl(&Some("ld-musl-m68k-sf.so.1".to_string())));
        assert!(!is_musl(&Some("ld-musl-m68kel.so.1".to_string())));
        assert!(is_musl(&Some("ld-musl-sh.so.1".to_string())));
        assert!(is_musl(&Some("ld-musl-sh-nofpu-fdpic.so.1".to_string())));
        assert!(is_musl(&Some("ld-musl-sheb-nofpu.so.1".to_string())));
        assert!(!is_musl(&Some("ld-musl-shhf.so.1".to_string())));

        let musl = |arch: &str| is_musl(&Some(format!("/lib/ld-musl-{arch}.so.1")));
        // Every ISA revision, endianness and float ABI combination of the
        // three MIPS ABIs.
        for arch in ["mips", "mips64", "mipsn32"] {
            for suffix in ["", "r6", "el", "r6el", "-sf", "r6-sf", "el-sf", "r6el-sf"] {
                assert!(musl(&format!("{arch}{suffix}")));
            }
            assert!(!musl(&format!("{arch}sf")));
            assert!(!musl(&format!("{arch}elr6")));
        }
        assert!(!musl("mips64n32"));
        // The float ABI variants take a dash on powerpc, RISC-V and LoongArch.
        for arch in ["powerpc", "riscv32", "riscv64", "loongarch64"] {
            assert!(musl(arch));
            assert!(musl(&format!("{arch}-sf")));
            assert!(!musl(&format!("{arch}sf")));
            assert!(!musl(&format!("{arch}-sf-sp")));
        }
        for arch in ["riscv32", "riscv64", "loongarch64"] {
            assert!(musl(&format!("{arch}-sp")));
        }
        for arch in [
            "armebhf",
            "armhf",
            "microblazeel",
            "or1k",
            "s390x",
            "x32",
            "m68k-fp64",
            "powerpc64le",
            "i386",
            "sheb-nofpu-fdpic",
        ] {
            assert!(musl(arch));
        }
        assert!(!musl("x86_64el"));
        assert!(!musl("armhfeb"));
        assert!(!musl("powerpc64-sf"));
    }
}
