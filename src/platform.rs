// Maps the provided ELF architecture to PLATFORM expansion on rpath and runpath

use object::elf::*;

// glibc set the PLATFORM from AT_PLATFORM provided by the kernel through auxiliary vectors.
// Some architecture, like x86, might change the value depending of the underlying processor
// and not all architectures define PLATFORM.
//
// The kernel sets the AT_PLATFORM from a pre-defined value (fs/binfmt_elf.c::create_elf_tables),
// so it is possible to map some the possible value used on glibc from the ELF machine and
// endianness.
pub fn get(e_machine: u16, ei_endian: u8) -> String {
    let r = match e_machine {
        // Alpha return either "ev4",  "ev5", "ev56", "ev6", or "ev67" depending of the processor,
        // asssume the latest one.
        EM_ALPHA => "ev67",

        // ARM returns a value depending of the MIDR register search in list built based on the
        // supported platforms by the kernel (which depends on how the kernel is configured)
        // and the endianness.
        //
        // Possible values for a recent kernel (6.0) are: 'v4', 'v5', 'v5t', 'v6', 'v7', 'v7m',
        // or 'v8' (for arm64 kernel) and the endianess is either 'l' (little endian) or 'b'
        // (big endian).  So for a armv7-a little endian chip the value would be 'v7l', while
        // on a aarch64 compat mode it will be 'v8l'.  Assume latest 32-bit one.
        EM_ARM => match ei_endian {
            ELFDATA2LSB => "v7l",
            ELFDATA2MSB => "v7b",
            _ => "",
        },

        EM_AARCH64 => match ei_endian {
            ELFDATA2LSB => "aarch64",
            ELFDATA2MSB => "aarch64_be",
            _ => "",
        },

        EM_LOONGARCH => "loongarch",

        // MIPS returns a value depending of the CPU: "loongson2e", "loongson2f", "loongson3a",
        // "loongson3b", "bmips32", "bmips3300", "bmips4380", "bmips4350", "bmips5000", "octeon",
        // "octeon2", "octeon3", "gs264e" and "mips".
        //
        // Return "mips", which is the default.
        EM_MIPS => "mips",

        EM_PARISC => "PARISC",

        // PowerPC returns a value depending of the CPU: "pa6t", "power5", "power5+", "power6",
        // "power6x", "power7", "power7+", "power8", "power9", "power10, "powerpc", "ppc-cell-be",
        // "ppc405", "ppc440", "ppc440gp", "ppc470", "ppc603", "ppc604", "ppc7400", "ppc7450",
        // "ppc750", "ppc823", "ppc8540", "ppc8548", "ppc970", "ppce500mc", "ppce5500",
        // and "ppce6500".
        //
        // Return "power8" for 64 bits (which is the base ABI for ELFv2) and empty for 32 bits.
        EM_PPC64 => "power8",

        // s390 returns a value depending of the CPU: "z10", "z196", "zEC12", "z13", "z14", "z15",
        // and "z16"
        //
        // Return "z10", which is the default.
        EM_S390 => "z10",

        EM_SH => "sh",

        // i386 might return i386 for 32 bits kernels or i686 for 64 bits kernel.
        EM_386 => "i686",

        EM_X86_64 => "x86_64",

        _ => "",
    };

    r.to_string()
}
