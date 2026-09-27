// The registry values the loader consults.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dword_values() {
        const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        // A value every installation sets.
        assert!(dword(KEY, "InstallDate").is_some());
        assert!(dword(KEY, "rldd-not-a-value").is_none());
        assert!(dword(r"SOFTWARE\rldd-not-a-key", "x").is_none());
        // A string value is not read as a number.
        assert!(dword(KEY, "ProductName").is_none());
    }

    #[test]
    fn wide_strings() {
        assert_eq!(wide("ab"), [b'a' as u16, b'b' as u16, 0]);
    }
}
