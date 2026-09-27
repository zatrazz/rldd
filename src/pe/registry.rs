// The registry values the loader consults.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    REG_ROUTINE_FLAGS, RRF_RT_REG_DWORD, RRF_RT_REG_MULTI_SZ, RRF_RT_REG_SZ,
};

// S as a NUL terminated wide string.
pub fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// The REG_DWORD VALUE of the KEY subkey of HKEY_LOCAL_MACHINE, when it is set.
pub fn dword(key: &str, value: &str) -> Option<u32> {
    let key = wide(key);
    let value = wide(value);
    let mut data = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: both names are NUL terminated, and the buffer and its size in
    // bytes describe DATA, which the type restriction makes large enough.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            &mut data as *mut u32 as *mut std::ffi::c_void,
            &mut size,
        )
    };
    (rc == ERROR_SUCCESS).then_some(data)
}

// The wide characters of the string VALUE of the KEY subkey of
// HKEY_LOCAL_MACHINE, of one of the TYPES, NUL terminators included.
fn wide_value(key: &str, value: &str, types: REG_ROUTINE_FLAGS) -> Option<Vec<u16>> {
    let key = wide(key);
    let value = wide(value);
    // The value may grow between the size query and the read, so the read
    // is retried a few times.
    for _ in 0..4 {
        let mut size = 0u32;
        // SAFETY: both names are NUL terminated, and a null buffer only asks
        // for the size in bytes.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                types,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let mut data = vec![0u16; (size as usize).div_ceil(2)];
        let mut size = (data.len() * 2) as u32;
        // SAFETY: the buffer and its size in bytes describe DATA.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                types,
                std::ptr::null_mut(),
                data.as_mut_ptr() as *mut std::ffi::c_void,
                &mut size,
            )
        };
        if rc == ERROR_SUCCESS {
            data.truncate(size as usize / 2);
            return Some(data);
        }
    }
    None
}

// The REG_SZ VALUE of the KEY subkey of HKEY_LOCAL_MACHINE, when it is set.
pub fn string(key: &str, value: &str) -> Option<String> {
    let data = wide_value(key, value, RRF_RT_REG_SZ)?;
    let end = data.iter().position(|c| *c == 0).unwrap_or(data.len());
    Some(String::from_utf16_lossy(&data[..end]))
}

// The strings of the REG_MULTI_SZ VALUE of the KEY subkey of
// HKEY_LOCAL_MACHINE, empty when it is not set.
pub fn multi_string(key: &str, value: &str) -> Vec<String> {
    let Some(data) = wide_value(key, value, RRF_RT_REG_MULTI_SZ) else {
        return Vec::new();
    };
    data.split(|c| *c == 0)
        .filter(|string| !string.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

// The names of the subkeys of the KEY subkey of HKEY_LOCAL_MACHINE.
pub fn subkeys(key: &str) -> Vec<String> {
    let mut names = Vec::new();
    let subkey = wide(key);
    let mut handle: HKEY = std::ptr::null_mut();
    // SAFETY: the subkey is NUL terminated and the handle is only used when
    // the call succeeds.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut handle,
        )
    };
    if rc != ERROR_SUCCESS {
        return names;
    }
    for index in 0.. {
        // A key name is at most 255 characters.
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: the name length is in characters and describes the buffer,
        // and the class and the time are not asked for.
        let rc = unsafe {
            RegEnumKeyExW(
                handle,
                index,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc == ERROR_SUCCESS {
            names.push(String::from_utf16_lossy(&name[..len as usize]));
        }
    }
    // SAFETY: the handle comes from the RegOpenKeyExW above and is not used
    // after this point.
    unsafe { RegCloseKey(handle) };
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    #[test]
    fn dword_values() {
        // A value every installation sets.
        assert!(dword(KEY, "InstallDate").is_some());
        assert!(dword(KEY, "rldd-not-a-value").is_none());
        assert!(dword(r"SOFTWARE\rldd-not-a-key", "x").is_none());
        // A string value is not read as a number.
        assert!(dword(KEY, "ProductName").is_none());
    }

    #[test]
    fn string_values() {
        assert!(string(KEY, "ProductName").is_some_and(|name| name.contains("Windows")));
        assert!(string(KEY, "InstallDate").is_none());
        assert!(string(KEY, "rldd-not-a-value").is_none());
        // A multi string every installation sets.
        let session = r"SYSTEM\CurrentControlSet\Control\Session Manager";
        assert!(multi_string(session, "BootExecute")
            .iter()
            .any(|entry| entry.contains("autocheck")));
        assert!(multi_string(session, "rldd-not-a-value").is_empty());
        assert!(multi_string(KEY, "ProductName").is_empty());
    }

    #[test]
    fn registry_subkeys() {
        let keys = subkeys(r"SYSTEM\CurrentControlSet\Control");
        assert!(keys
            .iter()
            .any(|key| key.eq_ignore_ascii_case("Session Manager")));
        assert!(subkeys(r"SOFTWARE\rldd-not-a-key").is_empty());
    }

    #[test]
    fn wide_strings() {
        assert_eq!(wide("ab"), [b'a' as u16, b'b' as u16, 0]);
    }
}
