use object::elf::*;
#[cfg(target_os = "android")]
use std::ffi::CString;
use std::fmt;
#[cfg(target_os = "android")]
use std::io::Error;

use crate::pathutils;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AndroidRelease(pub u32);

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
}

impl fmt::Display for AndroidRelease {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.0)
    }
}

// The system properties the loader configuration depends on.  They are read
// from the device, except on the host tests that set them directly.
#[derive(Clone, Debug)]
pub struct SystemProperties {
    // ro.build.version.sdk
    pub release: AndroidRelease,
    // ro.vndk.version, empty when unset.
    pub vndk_version: String,
    // ro.vndk.lite
    pub vndk_lite: bool,
}

impl SystemProperties {
    #[cfg(target_os = "android")]
    pub fn get() -> Result<SystemProperties, std::io::Error> {
        Ok(SystemProperties {
            release: get_release()?,
            vndk_version: get_property("ro.vndk.version", "").unwrap_or_default(),
            vndk_lite: get_property_bool("ro.vndk.lite", false).unwrap_or(false),
        })
    }

    // The bionic Config::get_vndk_version_string: the VNDK version preceded
    // by DELIMITER, or nothing when it is unset or 'current'.
    pub fn vndk_version_string(&self, delimiter: char) -> String {
        if self.vndk_version.is_empty() || self.vndk_version == "current" {
            return String::new();
        }
        format!("{delimiter}{}", self.vndk_version)
    }
}

#[cfg(target_os = "android")]
const PROP_VALUE_MAX: usize = 92;

#[cfg(target_os = "android")]
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

#[cfg(target_os = "android")]
pub fn get_release_str() -> Result<String, std::io::Error> {
    get_property("ro.build.version.sdk", "")
}

#[cfg(target_os = "android")]
pub fn get_release() -> Result<AndroidRelease, std::io::Error> {
    get_release_str()?
        .trim()
        .parse::<u32>()
        .map(AndroidRelease)
        .map_err(|_| Error::other("Could not read the Android release"))
}

#[cfg(target_os = "android")]
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

// The sanitizer in use is derived from the loader name, the way bionic builds
// a separate linker for each one.  A shared library has no PT_INTERP segment.
fn interp_name(interp: Option<&str>) -> String {
    match interp {
        Some(interp) => pathutils::get_name(&std::path::Path::new(interp)),
        None => String::new(),
    }
}

pub fn is_asan(interp: Option<&str>) -> bool {
    matches!(
        interp_name(interp).as_str(),
        "linker_asan" | "linker_asan64"
    )
}

pub fn is_hwasan(interp: Option<&str>) -> bool {
    matches!(
        interp_name(interp).as_str(),
        "linker_hwasan" | "linker_hwasan64"
    )
}

// The ${LIB} substitution and the system directories suffix, which the bionic
// loader hardwires as 'lib64' for the LP64 ABIs and 'lib' for the ILP32 ones.
pub fn libpath(ei_class: FileClass) -> &'static str {
    match ei_class {
        ELFCLASS64 => "lib64",
        _ => "lib",
    }
}

// The bionic ABI_STRING, used on the architecture specific configuration file
// name.
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
