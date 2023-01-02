#[cfg(any(
    target_os = "linux",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "android"
))]
use object::elf::*;

#[cfg(target_os = "android")]
use crate::elf::android;
use crate::search_path;

// Return the default system directory for the architectures and class.  It is hard
// wired on glibc install for each triplet (the $slibdir).
#[cfg(target_os = "linux")]
pub fn get_slibdir(e_machine: u16, ei_class: u8) -> Option<&'static str> {
    // Not all machines are supported by object crate.
    const EM_ARCV2: u16 = 195;

    match e_machine {
        EM_AARCH64 | EM_ALPHA | EM_PPC64 | EM_LOONGARCH => Some("/lib64"),
        EM_ARCV2 | EM_ARM | EM_CSKY | EM_PARISC | EM_386 | EM_68K | EM_MICROBLAZE
        | EM_ALTERA_NIOS2 | EM_OPENRISC | EM_PPC | EM_SH => Some("/lib"),
        EM_S390 | EM_SPARC | EM_MIPS | EM_MIPS_RS3_LE => match ei_class {
            ELFCLASS32 => Some("/lib"),
            ELFCLASS64 => Some("/lib64"),
            _ => return None,
        },
        EM_RISCV => match ei_class {
            ELFCLASS32 => Some("/lib32/ilp32d"),
            ELFCLASS64 => Some("/lib64/lp64d"),
            _ => return None,
        },
        EM_X86_64 => match ei_class {
            ELFCLASS32 => Some("/libx32"),
            ELFCLASS64 => Some("/lib64"),
            _ => return None,
        },
        _ => return None,
    }
}

#[cfg(target_os = "linux")]
pub fn get_system_dirs(e_machine: u16, ei_class: u8) -> Option<search_path::SearchPathVec> {
    let path = get_slibdir(e_machine, ei_class)?;
    Some(vec![
        search_path::SearchPath {
            path: path.to_string(),
            dev: 0,
            ino: 0,
        },
        // The '/usr' part is configurable on glibc install, however there is no direct
        // way to obtain it on runtime.
        // TODO: Add an option to override it.
        search_path::SearchPath {
            path: format!("/usr/{}", path.to_string()),
            dev: 0,
            ino: 0,
        },
    ])
}

#[cfg(target_os = "android")]
pub fn get_system_dirs_xx(suffix: &str) -> Option<search_path::SearchPathVec> {
    let add_odm = match android::get_release().unwrap() {
        android::AndroidRelease::AndroidR28
        | android::AndroidRelease::AndroidR29
        | android::AndroidRelease::AndroidR30
        | android::AndroidRelease::AndroidR31
        | android::AndroidRelease::AndroidR32
        | android::AndroidRelease::AndroidR33 => true,
        _ => false,
    };

    let mut r = search_path::SearchPathVec::new();
    r.push(search_path::SearchPath {
        path: format!("/system/lib{}", suffix),
        dev: 0,
        ino: 0,
    });
    if add_odm {
        r.push(search_path::SearchPath {
            path: format!("/odm/lib{}", suffix),
            dev: 0,
            ino: 0,
        });
    }
    r.push(search_path::SearchPath {
        path: format!("/vendor/lib{}", suffix),
        dev: 0,
        ino: 0,
    });
    Some(r)
}
#[cfg(target_os = "android")]
pub fn get_system_dirs(e_machine: u16, ei_class: u8) -> Option<search_path::SearchPathVec> {
    match e_machine {
        EM_AARCH64 | EM_X86_64 => get_system_dirs_xx("64"),
        EM_ARM | EM_386 => get_system_dirs_xx(""),
        EM_MIPS => match ei_class {
            ELFCLASS64 => get_system_dirs_xx("64"),
            ELFCLASS32 => get_system_dirs_xx(""),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(target_os = "freebsd")]
pub fn get_system_dirs(_e_machine: u16, _ei_class: u8) -> Option<search_path::SearchPathVec> {
    Some(vec![search_path::SearchPath {
        path: "/lib".to_string(),
        dev: 0,
        ino: 0,
    }])
}

#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub fn get_system_dirs(_e_machine: u16, _ei_class: u8) -> Option<search_path::SearchPathVec> {
    Some(vec![search_path::SearchPath {
        path: "/usr/lib".to_string(),
        dev: 0,
        ino: 0,
    }])
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
pub fn get_system_dirs(e_machine: u16, _ei_class: u8) -> Option<search_path::SearchPathVec> {
    match e_machine {
        EM_386 => Some(vec![
            search_path::SearchPath {
                path: "/lib".to_string(),
                dev: 0,
                ino: 0,
            },
            search_path::SearchPath {
                path: "/usr/lib".to_string(),
                dev: 0,
                ino: 0,
            },
        ]),
        EM_X86_64 => Some(vec![
            search_path::SearchPath {
                path: "/lib64".to_string(),
                dev: 0,
                ino: 0,
            },
            search_path::SearchPath {
                path: "/usr/lib/64".to_string(),
                dev: 0,
                ino: 0,
            },
        ]),
        _ => None,
    }
}
