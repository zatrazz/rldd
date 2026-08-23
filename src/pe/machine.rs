// The PE machine and subsystem types.

use object::pe;

// The 32 bit machines resolve the system directory to SysWOW64 instead of
// System32.
pub fn is_32bit(machine: pe::Machine) -> bool {
    matches!(
        machine,
        pe::IMAGE_FILE_MACHINE_I386
            | pe::IMAGE_FILE_MACHINE_ARM
            | pe::IMAGE_FILE_MACHINE_ARMNT
            | pe::IMAGE_FILE_MACHINE_THUMB
            | pe::IMAGE_FILE_MACHINE_RISCV32
    )
}

// Whether a dependency built for MACHINE can be loaded by an image built for
// IMAGE.  The loader skips a candidate of the wrong machine and keeps
// searching (it is what tells System32 and SysWOW64 apart).
pub fn compatible(image: pe::Machine, machine: pe::Machine) -> bool {
    if image == machine {
        return true;
    }
    // ARM64 images load ARM64EC and ARM64X modules, and an ARM64EC image
    // loads both the ARM64 and the x86_64 ones.
    matches!(
        (image, machine),
        (
            pe::IMAGE_FILE_MACHINE_ARM64 | pe::IMAGE_FILE_MACHINE_ARM64EC,
            pe::IMAGE_FILE_MACHINE_ARM64
                | pe::IMAGE_FILE_MACHINE_ARM64EC
                | pe::IMAGE_FILE_MACHINE_ARM64X
        ) | (pe::IMAGE_FILE_MACHINE_ARM64EC, pe::IMAGE_FILE_MACHINE_AMD64)
            | (
                pe::IMAGE_FILE_MACHINE_AMD64,
                pe::IMAGE_FILE_MACHINE_ARM64EC | pe::IMAGE_FILE_MACHINE_ARM64X
            )
    )
}

pub fn name(machine: pe::Machine) -> String {
    let name = match machine {
        pe::IMAGE_FILE_MACHINE_I386 => "i386",
        pe::IMAGE_FILE_MACHINE_AMD64 => "x86_64",
        pe::IMAGE_FILE_MACHINE_ARM64 => "arm64",
        pe::IMAGE_FILE_MACHINE_ARM64EC => "arm64ec",
        pe::IMAGE_FILE_MACHINE_ARM64X => "arm64x",
        pe::IMAGE_FILE_MACHINE_ARMNT => "armnt",
        pe::IMAGE_FILE_MACHINE_ARM => "arm",
        pe::IMAGE_FILE_MACHINE_THUMB => "thumb",
        pe::IMAGE_FILE_MACHINE_IA64 => "ia64",
        pe::IMAGE_FILE_MACHINE_RISCV32 => "riscv32",
        pe::IMAGE_FILE_MACHINE_RISCV64 => "riscv64",
        pe::IMAGE_FILE_MACHINE_EBC => "ebc",
        _ => return format!("{:#06x}", machine.0),
    };
    name.to_string()
}

pub fn subsystem_name(subsystem: pe::Subsystem) -> String {
    let name = match subsystem {
        pe::IMAGE_SUBSYSTEM_NATIVE => "native",
        pe::IMAGE_SUBSYSTEM_WINDOWS_GUI => "windows gui",
        pe::IMAGE_SUBSYSTEM_WINDOWS_CUI => "windows cui",
        pe::IMAGE_SUBSYSTEM_EFI_APPLICATION => "efi application",
        pe::IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => "efi boot service driver",
        pe::IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => "efi runtime driver",
        pe::IMAGE_SUBSYSTEM_EFI_ROM => "efi rom",
        pe::IMAGE_SUBSYSTEM_XBOX => "xbox",
        _ => return format!("{}", subsystem.0),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wow64_selection() {
        assert!(is_32bit(pe::IMAGE_FILE_MACHINE_I386));
        assert!(is_32bit(pe::IMAGE_FILE_MACHINE_ARMNT));
        assert!(!is_32bit(pe::IMAGE_FILE_MACHINE_AMD64));
        assert!(!is_32bit(pe::IMAGE_FILE_MACHINE_ARM64));
    }

    // A candidate of the wrong machine is skipped, which is what tells the
    // System32 and the SysWOW64 modules apart.
    #[test]
    fn machine_mismatch() {
        assert!(compatible(
            pe::IMAGE_FILE_MACHINE_AMD64,
            pe::IMAGE_FILE_MACHINE_AMD64
        ));
        assert!(!compatible(
            pe::IMAGE_FILE_MACHINE_AMD64,
            pe::IMAGE_FILE_MACHINE_I386
        ));
        assert!(!compatible(
            pe::IMAGE_FILE_MACHINE_I386,
            pe::IMAGE_FILE_MACHINE_AMD64
        ));
    }

    // An ARM64 image loads the emulation compatible modules.
    #[test]
    fn arm64_variants() {
        assert!(compatible(
            pe::IMAGE_FILE_MACHINE_ARM64,
            pe::IMAGE_FILE_MACHINE_ARM64X
        ));
        assert!(compatible(
            pe::IMAGE_FILE_MACHINE_ARM64EC,
            pe::IMAGE_FILE_MACHINE_AMD64
        ));
        assert!(!compatible(
            pe::IMAGE_FILE_MACHINE_ARM64,
            pe::IMAGE_FILE_MACHINE_I386
        ));
    }

    #[test]
    fn machine_names() {
        assert_eq!(name(pe::IMAGE_FILE_MACHINE_AMD64), "x86_64");
        assert_eq!(name(pe::Machine(0x1234)), "0x1234");
    }
}
