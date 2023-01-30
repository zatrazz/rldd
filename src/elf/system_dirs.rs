#[cfg(any(
    target_os = "linux",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "android"
))]
use object::elf::*;

use crate::search_path;

#[allow(dead_code)]
fn return_error<T>() -> Result<T, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "failed to get default system dir",
    ))
}

// Return the default system directory for the architectures and class.  It is hard
// wired on glibc install for each triplet (the $slibdir).
#[cfg(target_os = "linux")]
pub fn get_slibdir(e_machine: u16, ei_class: u8) -> Result<&'static str, std::io::Error> {
    // Not all machines are supported by object crate.
    const EM_ARCV2: u16 = 195;

    match e_machine {
        EM_AARCH64 | EM_ALPHA | EM_PPC64 | EM_LOONGARCH => Ok("/lib64"),
        EM_ARCV2 | EM_ARM | EM_CSKY | EM_PARISC | EM_386 | EM_68K | EM_MICROBLAZE
        | EM_ALTERA_NIOS2 | EM_OPENRISC | EM_PPC | EM_SH => Ok("/lib"),
        EM_S390 | EM_SPARC | EM_MIPS | EM_MIPS_RS3_LE => match ei_class {
            ELFCLASS32 => Ok("/lib"),
            ELFCLASS64 => Ok("/lib64"),
            _ => return_error(),
        },
        EM_RISCV => match ei_class {
            ELFCLASS32 => Ok("/lib32/ilp32d"),
            ELFCLASS64 => Ok("/lib64/lp64d"),
            _ => return_error(),
        },
        EM_X86_64 => match ei_class {
            ELFCLASS32 => Ok("/libx32"),
            ELFCLASS64 => Ok("/lib64"),
            _ => return_error(),
        },
        _ => return_error(),
    }
}

#[cfg(target_os = "linux")]
pub fn get_system_dirs(
    _interp: &Option<String>,
    e_machine: u16,
    ei_class: u8,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    let path = get_slibdir(e_machine, ei_class)?;
    Ok(vec![
        search_path::SearchPath {
            path: path.to_string(),
            dev: 0,
            ino: 0,
        },
        // The '/usr' part is configurable on glibc install, however there is no direct
        // way to obtain it on runtime.
        // TODO: Add an option to override it.
        search_path::SearchPath {
            path: format!("/usr/{path}"),
            dev: 0,
            ino: 0,
        },
    ])
}

#[cfg(target_os = "android")]
pub fn get_system_dirs(
    interp: &Option<String>,
    e_machine: u16,
    ei_class: u8,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    use crate::elf::android;

    pub fn get_system_dirs_xx(
        suffix: &str,
        is_asan: bool,
    ) -> Result<search_path::SearchPathVec, std::io::Error> {
        let release = android::get_release()?;

        let add_odm = match release {
            android::AndroidRelease::AndroidR28
            | android::AndroidRelease::AndroidR29
            | android::AndroidRelease::AndroidR30
            | android::AndroidRelease::AndroidR31
            | android::AndroidRelease::AndroidR32
            | android::AndroidRelease::AndroidR33 => true,
            _ => false,
        };

        let mut r = search_path::SearchPathVec::new();
        if is_asan {
            let path = match release {
                android::AndroidRelease::AndroidR24 | android::AndroidRelease::AndroidR25 => {
                    format!("/data/lib{}", suffix)
                }
                _ => format!("/data/asan/system/lib{}", suffix),
            };
            r.push(search_path::SearchPath {
                path: path,
                dev: 0,
                ino: 0,
            });
        }
        r.push(search_path::SearchPath {
            path: format!("/system/lib{}", suffix),
            dev: 0,
            ino: 0,
        });
        if is_asan && add_odm {
            r.push(search_path::SearchPath {
                path: format!("/data/asan/odm/lib{}", suffix),
                dev: 0,
                ino: 0,
            });
        }
        if add_odm {
            r.push(search_path::SearchPath {
                path: format!("/odm/lib{}", suffix),
                dev: 0,
                ino: 0,
            });
        }
        if is_asan {
            let path = match release {
                android::AndroidRelease::AndroidR24 | android::AndroidRelease::AndroidR25 => {
                    format!("/vendor/lib{}", suffix)
                }
                _ => format!("/data/asan/vendor/lib{}", suffix),
            };
            r.push(search_path::SearchPath {
                path: path,
                dev: 0,
                ino: 0,
            });
        }
        r.push(search_path::SearchPath {
            path: format!("/vendor/lib{}", suffix),
            dev: 0,
            ino: 0,
        });
        Ok(r)
    }

    if let Some(interp) = interp {
        let is_asan = android::is_asan(interp);

        return match e_machine {
            EM_AARCH64 | EM_X86_64 => get_system_dirs_xx("64", is_asan),
            EM_ARM | EM_386 => get_system_dirs_xx("", is_asan),
            EM_MIPS => match ei_class {
                ELFCLASS64 => get_system_dirs_xx("64", is_asan),
                ELFCLASS32 => get_system_dirs_xx("", is_asan),
                _ => return_error(),
            },
            _ => return_error(),
        };
    };
    return_error()
}

#[cfg(target_os = "freebsd")]
pub fn get_system_dirs(
    _interp: &Option<String>,
    _e_machine: u16,
    _ei_class: u8,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    Ok(vec![search_path::SearchPath {
        path: "/lib".to_string(),
        dev: 0,
        ino: 0,
    }])
}

#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub fn get_system_dirs(
    _interp: &Option<String>,
    _e_machine: u16,
    _ei_class: u8,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    Ok(vec![search_path::SearchPath {
        path: "/usr/lib".to_string(),
        dev: 0,
        ino: 0,
    }])
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
pub fn get_system_dirs(
    _interp: &Option<String>,
    e_machine: u16,
    _ei_class: u8,
) -> Result<search_path::SearchPathVec, std::io::Error> {
    match e_machine {
        EM_386 => Ok(vec![
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
        EM_X86_64 => Ok(vec![
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
        _ => return_error(),
    }
}
