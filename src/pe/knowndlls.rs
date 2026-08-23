// The KnownDLLs registry key.  The modules the loader always resolves from the
// known DLLs directory, whatever the search order says.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ,
    REG_SZ,
};

const KNOWNDLLS_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs";

#[derive(Default, Debug)]
pub struct KnownDlls {
    // The module names, lowercased.
    names: HashSet<String>,
    dir: Option<String>,
    dir32: Option<String>,
}

impl KnownDlls {
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(&name.to_lowercase())
    }

    // The 32 bit known DLLs live on the DllDirectory32 directory.
    pub fn directory(&self, is_32bit: bool) -> Option<&str> {
        if is_32bit {
            self.dir32.as_deref()
        } else {
            self.dir.as_deref()
        }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn from_wide(buffer: &[u16], bytes: u32) -> String {
    let len = (bytes as usize / 2).min(buffer.len());
    let units = &buffer[..len];
    let units = match units.iter().position(|&c| c == 0) {
        Some(nul) => &units[..nul],
        None => units,
    };
    String::from_utf16_lossy(units)
}

pub fn load() -> KnownDlls {
    let mut known = KnownDlls::default();
    let subkey = wide(KNOWNDLLS_KEY);
    let mut key: HKEY = std::ptr::null_mut();

    // The subkey is NUL terminated and the handle is only used when the call
    // succeeds.
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut key) };
    if rc != ERROR_SUCCESS {
        return known;
    }

    let mut index = 0u32;
    loop {
        // The registry allows far longer values, but this key only holds
        // module names and the two DllDirectory paths, so the buffers are
        // sized for a module name and for a path above MAX_PATH.  Anything
        // larger is reported as ERROR_MORE_DATA and skipped below.
        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut kind = 0u32;
        let mut data = [0u16; 512];
        let mut data_len = (data.len() * 2) as u32;

        // The name length is in characters and the data one in bytes, as the
        // API documents, and both describe the buffers passed along.
        let rc = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr() as *mut u8,
                &mut data_len,
            )
        };
        if rc != ERROR_SUCCESS {
            // Skip the values that do not fit the buffers.
            if rc != ERROR_MORE_DATA {
                break;
            }
            index += 1;
            continue;
        }
        index += 1;

        if kind != REG_SZ && kind != REG_EXPAND_SZ {
            continue;
        }
        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        let value = from_wide(&data, data_len);
        if name.eq_ignore_ascii_case("DllDirectory") {
            known.dir = Some(value);
        } else if name.eq_ignore_ascii_case("DllDirectory32") {
            known.dir32 = Some(value);
        } else if !value.is_empty() {
            known.names.insert(value.to_lowercase());
        }
    }

    // The key comes from the RegOpenKeyExW above and is not used after this
    // point.
    unsafe { RegCloseKey(key) };

    known
}
