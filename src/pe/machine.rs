// The PE machine and subsystem types.

use object::pe;

// The system directory the WOW64 layer shows an image as System32: the
// native images see it as it is, the x86 ones get SysWOW64, and the 32 bit
// ARM ones SysArm32 (on an ARM64 host, up to Windows 11 23H2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Wow64 {
    Native,
    X86,
    Arm32,
}

impl Wow64 {
    pub fn of(machine: pe::Machine) -> Self {
        match machine {
            pe::IMAGE_FILE_MACHINE_I386 => Wow64::X86,
            pe::IMAGE_FILE_MACHINE_ARM
            | pe::IMAGE_FILE_MACHINE_ARMNT
            | pe::IMAGE_FILE_MACHINE_THUMB => Wow64::Arm32,
            _ => Wow64::Native,
        }
    }

    // The name of the directory standing for System32.
    pub fn system_dir(self) -> &'static str {
        match self {
            Wow64::Native => "System32",
            Wow64::X86 => "SysWOW64",
            Wow64::Arm32 => "SysArm32",
        }
    }
}

// Whether a dependency built for MACHINE can be loaded by an image built for
// IMAGE.  The loader skips a candidate of the wrong machine and keeps
// searching (it is what tells System32 and SysWOW64 apart).
pub fn compatible(image: pe::Machine, machine: pe::Machine) -> bool {
    if image == machine {
        return true;
    }
    // A native ARM64 process loads the ARM64 and the ARM64X modules, and an
    // emulated one (started from an x86_64 or an ARM64EC image) the x86_64,
    // the ARM64EC and the ARM64X ones: an ARM64X module holds both views,
    // while an ARM64EC one only loads on the emulated side and a plain ARM64
    // one only on the native side.  An ARM64X image given on the command
    // line stands for both processes.
    matches!(
        (image, machine),
        (
            pe::IMAGE_FILE_MACHINE_ARM64,
            pe::IMAGE_FILE_MACHINE_ARM64 | pe::IMAGE_FILE_MACHINE_ARM64X
        ) | (
            pe::IMAGE_FILE_MACHINE_AMD64 | pe::IMAGE_FILE_MACHINE_ARM64EC,
            pe::IMAGE_FILE_MACHINE_AMD64
                | pe::IMAGE_FILE_MACHINE_ARM64EC
                | pe::IMAGE_FILE_MACHINE_ARM64X
        ) | (
            pe::IMAGE_FILE_MACHINE_ARM64X,
            pe::IMAGE_FILE_MACHINE_ARM64
                | pe::IMAGE_FILE_MACHINE_ARM64EC
                | pe::IMAGE_FILE_MACHINE_AMD64
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
        let dir = |machine| Wow64::of(machine).system_dir();
        assert_eq!(dir(pe::IMAGE_FILE_MACHINE_I386), "SysWOW64");
        assert_eq!(dir(pe::IMAGE_FILE_MACHINE_ARMNT), "SysArm32");
        assert_eq!(dir(pe::IMAGE_FILE_MACHINE_AMD64), "System32");
        assert_eq!(dir(pe::IMAGE_FILE_MACHINE_ARM64), "System32");
        assert_eq!(dir(pe::IMAGE_FILE_MACHINE_ARM64X), "System32");
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
        // A pure ARM64EC module only loads on the emulated side, and a plain
        // ARM64 one only on the native side.
        assert!(!compatible(
            pe::IMAGE_FILE_MACHINE_ARM64,
            pe::IMAGE_FILE_MACHINE_ARM64EC
        ));
        assert!(!compatible(
            pe::IMAGE_FILE_MACHINE_ARM64EC,
            pe::IMAGE_FILE_MACHINE_ARM64
        ));
        assert!(compatible(
            pe::IMAGE_FILE_MACHINE_ARM64EC,
            pe::IMAGE_FILE_MACHINE_ARM64X
        ));
        assert!(compatible(
            pe::IMAGE_FILE_MACHINE_AMD64,
            pe::IMAGE_FILE_MACHINE_ARM64EC
        ));
    }

    // Windows on ARM builds the system modules as ARM64X.
    #[test]
    fn emulated_amd64_image() {
        assert!(compatible(
            pe::IMAGE_FILE_MACHINE_AMD64,
            pe::IMAGE_FILE_MACHINE_ARM64X
        ));
        assert!(!compatible(
            pe::IMAGE_FILE_MACHINE_AMD64,
            pe::IMAGE_FILE_MACHINE_ARM64
        ));
        // An ARM64X image is both views at once.
        assert!(compatible(
            pe::IMAGE_FILE_MACHINE_ARM64X,
            pe::IMAGE_FILE_MACHINE_ARM64
        ));
        assert!(compatible(
            pe::IMAGE_FILE_MACHINE_ARM64X,
            pe::IMAGE_FILE_MACHINE_AMD64
        ));
    }

    #[test]
    fn machine_names() {
        assert_eq!(name(pe::IMAGE_FILE_MACHINE_AMD64), "x86_64");
        assert_eq!(name(pe::Machine(0x1234)), "0x1234");
    }
}
