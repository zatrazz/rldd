use std::ffi::CString;
use std::io::{Error, ErrorKind};

pub enum AndroidRelease {
    AndroidR26 = 26,
    AndroidR27 = 27,
    AndroidR28 = 28,
    AndroidR29 = 29,
    AndroidR30 = 30,
    AndroidR31 = 31,
    AndroidR32 = 32,
    AndroidR33 = 33,
    AndroidR34 = 34,
}

const PROP_VALUE_MAX: usize = 92;

pub fn get_release() -> Result<AndroidRelease, std::io::Error> {
    let name = CString::new("ro.build.version.sdk")?;

    let mut val: Vec<libc::c_uchar> = vec![0; PROP_VALUE_MAX];
    let ret = unsafe {
        libc::__system_property_get(name.as_ptr(), val.as_mut_ptr() as *mut libc::c_char)
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let androidrelease = match val.len() {
        0 => Err(Error::new(ErrorKind::Other, "Invalid Android release")),
        l => std::str::from_utf8(&val[..l - 1])
            .map_err(|_e| Error::new(ErrorKind::Other, "Invalid UTF8 sequence"))
            .and_then(|s| Ok(s.trim_matches(char::from(0)))),
    }?;

    match androidrelease {
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
