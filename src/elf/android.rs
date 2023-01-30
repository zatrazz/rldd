use object::elf::*;
use std::ffi::CString;
use std::fmt;
use std::io::{Error, ErrorKind};

use crate::pathutils;

pub enum AndroidRelease {
    AndroidR24 = 24, // 7.0
    AndroidR25 = 25, // 7.1
    AndroidR26 = 26, // 8.0
    AndroidR27 = 27, // 8.1
    AndroidR28 = 28, // 9.0
    AndroidR29 = 29, // 10
    AndroidR30 = 30, // 11
    AndroidR31 = 31, // 12
    AndroidR32 = 32, // 12.1
    AndroidR33 = 33, // 13
    AndroidR34 = 34, // 14
}

impl fmt::Display for AndroidRelease {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            AndroidRelease::AndroidR24 => fmt.write_str("24")?,
            AndroidRelease::AndroidR25 => fmt.write_str("25")?,
            AndroidRelease::AndroidR26 => fmt.write_str("26")?,
            AndroidRelease::AndroidR27 => fmt.write_str("27")?,
            AndroidRelease::AndroidR28 => fmt.write_str("28")?,
            AndroidRelease::AndroidR29 => fmt.write_str("29")?,
            AndroidRelease::AndroidR30 => fmt.write_str("30")?,
            AndroidRelease::AndroidR31 => fmt.write_str("31")?,
            AndroidRelease::AndroidR32 => fmt.write_str("32")?,
            AndroidRelease::AndroidR33 => fmt.write_str("33")?,
            AndroidRelease::AndroidR34 => fmt.write_str("34")?,
        };
        Ok(())
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

    match val.len() {
        0 => Ok(default.as_ref().to_string()),
        l => std::str::from_utf8(&val[..l - 1])
            .map_err(|_e| Error::new(ErrorKind::Other, "Invalid UTF8 sequence"))
            .map(|s| s.trim_matches(char::from(0)).to_string()),
    }
}

pub fn get_release_str() -> Result<String, std::io::Error> {
    get_property("ro.build.version.sdk", "")
}

pub fn get_release() -> Result<AndroidRelease, std::io::Error> {
    match get_release_str()?.as_str() {
        "24" => Ok(AndroidRelease::AndroidR24),
        "25" => Ok(AndroidRelease::AndroidR25),
        "26" => Ok(AndroidRelease::AndroidR26),
        "27" => Ok(AndroidRelease::AndroidR27),
        "28" => Ok(AndroidRelease::AndroidR28),
        "29" => Ok(AndroidRelease::AndroidR29),
        "30" => Ok(AndroidRelease::AndroidR30),
        "31" => Ok(AndroidRelease::AndroidR31),
        "32" => Ok(AndroidRelease::AndroidR32),
        "33" => Ok(AndroidRelease::AndroidR33),
        "34" => Ok(AndroidRelease::AndroidR34),
        _ => Err(Error::new(ErrorKind::Other, "Unsupported Android release")),
    }
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

pub fn libpath(e_machine: u16, ei_class: u8) -> Option<&'static str> {
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

pub fn abi_string(e_machine: u16, ei_class: u8) -> Option<&'static str> {
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
