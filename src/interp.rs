// Program Interpreter handling functions

use std::path::Path;

const GLIBC_INTERP: &'static [&'static str] = &[
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
    if let Some(interp) = interp {
        // Map any translation error to a non-existent interpreter.
        let interp = Path::new(interp)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        return GLIBC_INTERP.contains(&interp);
    };
    false
}
