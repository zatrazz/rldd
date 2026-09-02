use object::elf::*;
use std::ffi::CString;
use std::fmt;
use std::io::Error;

use crate::pathutils;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AndroidRelease(u32);

impl AndroidRelease {
    // Android 8.0, which added the ld.config.txt file on a hardcoded path.
    pub const R26: AndroidRelease = AndroidRelease(26);
    // Android 9, which added the abi and vndk specific configuration paths
    // along with the /odm partition.
    pub const R28: AndroidRelease = AndroidRelease(28);
    // Android 10, which added the per APEX configuration.
    pub const R29: AndroidRelease = AndroidRelease(29);
    // Android 11, which added the generated /linkerconfig files.
    pub const R30: AndroidRelease = AndroidRelease(30);
    // Android 13, the last release the /odm partition was handled for.
    pub const R33: AndroidRelease = AndroidRelease(33);
}

impl fmt::Display for AndroidRelease {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.0)
    }
}

const PROP_VALUE_MAX: usize = 92;

pub fn get_property<S1: AsRef<str>, S2: AsRef<str>>(
    property: S1,
    default: S2,
) -> Result<String, std::io::Error> {
    let name = CString::new(property.as_ref())?;

    let mut val: Vec<libc::c_uchar> = vec![0; PROP_VALUE_MAX];
    let ret = unsafe {
        libc::__system_property_get(name.as_ptr(), val.as_mut_ptr() as *mut libc::c_char)
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // The returned value is the length of the property value, zero meaning an
    // unset or empty property.
    match ret as usize {
        0 => Ok(default.as_ref().to_string()),
        l => std::str::from_utf8(&val[..l.min(PROP_VALUE_MAX)])
            .map_err(|_e| Error::other("Invalid UTF8 sequence"))
            .map(|s| s.trim_matches(char::from(0)).to_string()),
    }
}

pub fn get_release_str() -> Result<String, std::io::Error> {
    get_property("ro.build.version.sdk", "")
}

pub fn get_release() -> Result<AndroidRelease, std::io::Error> {
    get_release_str()?
        .trim()
        .parse::<u32>()
        .map(AndroidRelease)
        .map_err(|_| Error::other("Could not read the Android release"))
}

pub fn get_property_bool<S: AsRef<str>>(
    property: S,
    default: bool,
) -> Result<bool, std::io::Error> {
    match get_property(property, "")?.as_str() {
        "1" | "y" | "yes" | "on" | "true" => Ok(true),
        "0" | "n" | "no" | "off" | "false" => Ok(false),
        _ => Ok(default),
    }
}

pub fn get_vndk_version_string<S: AsRef<str>>(default: S) -> String {
    match get_property("ro.vndk.version", "") {
        Ok(value) => value,
        Err(_) => default.as_ref().to_string(),
    }
}

pub fn is_asan<S: AsRef<str>>(interp: S) -> bool {
    matches!(
        pathutils::get_name(&std::path::Path::new(interp.as_ref())).as_str(),
        "linker_asan" | "linker_asan64"
    )
}

pub fn libpath(e_machine: Machine, ei_class: FileClass) -> Option<&'static str> {
    match e_machine {
        EM_AARCH64 | EM_X86_64 => Some("lib64"),
        EM_ARM | EM_386 => Some("lib"),
        EM_MIPS => match ei_class {
            ELFCLASS64 => Some("lib64"),
            ELFCLASS32 => Some("lib"),
            _ => None,
        },
        _ => None,
    }
}

pub fn abi_string(e_machine: Machine, ei_class: FileClass) -> Option<&'static str> {
    match e_machine {
        EM_AARCH64 => Some("arm64"),
        EM_ARM => Some("arm"),
        EM_X86_64 => Some("x86_64"),
        EM_386 => Some("x86"),
        EM_RISCV => match ei_class {
            ELFCLASS64 => Some("riscv64"),
            _ => None,
        },
        _ => None,
    }
}
