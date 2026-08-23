// The directories the loader searches for a dependency, in order, following
// the documented search order for unpackaged applications.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::MAIN_SEPARATOR;

use windows_sys::Win32::Foundation::MAX_PATH;
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

use crate::deptree::DepMode;
use crate::search_path::{SearchPath, SearchPathVec, SearchPathVecExt, LIST_SEPARATOR};

pub type SearchDirs = Vec<(SearchPath, DepMode)>;

pub fn windows_dir() -> String {
    // The Windows directory is set at installation and bound to MAX_PATH, so
    // the buffer always holds it.
    let mut buffer = [0u16; MAX_PATH as usize];
    // SAFETY: the length is passed in wide characters, as documented.
    let len = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 || len > buffer.len() {
        return std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    }
    OsString::from_wide(&buffer[..len])
        .to_string_lossy()
        .into_owned()
}

// The system directory, which is SysWOW64 for 32 bit images.
pub fn system_dir(windows: &str, is_32bit: bool) -> String {
    let name = if is_32bit { "SysWOW64" } else { "System32" };
    format!("{windows}{MAIN_SEPARATOR}{name}")
}

fn push(dirs: &mut SearchDirs, entry: &str, mode: DepMode) {
    let mut probe = SearchPathVec::new();
    probe.add_path(entry);
    if let Some(path) = probe.pop() {
        if !dirs.iter().any(|(existent, _)| *existent == path) {
            dirs.push((path, mode));
        }
    }
}

// The search order as described in https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#search-order-for-unpackaged-apps
// 1. the application directory.
// 2. the directories set with SetDllDirectory.
// 3. the system directory.
// 4. the 16 bit system directory.
// 5. the Windows directory.
// 6. the current directory.
// 7. the PATH directories.
// With the safe search mode disabled the current directory comes right after the
// application one.
pub fn build(
    application: Option<&str>,
    user: &SearchPathVec,
    windows: &str,
    is_32bit: bool,
    safe_search: bool,
) -> SearchDirs {
    let mut dirs = SearchDirs::new();

    if let Some(application) = application {
        push(&mut dirs, application, DepMode::Application);
    }
    for path in user {
        push(&mut dirs, &path.path, DepMode::LdLibraryPath);
    }

    let current = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    if !safe_search {
        if let Some(current) = &current {
            push(&mut dirs, current, DepMode::CurrentDir);
        }
    }

    push(
        &mut dirs,
        &system_dir(windows, is_32bit),
        DepMode::SystemDirs,
    );
    push(
        &mut dirs,
        &format!("{windows}{MAIN_SEPARATOR}System"),
        DepMode::SystemDirs,
    );
    push(&mut dirs, windows, DepMode::WindowsDir);

    if safe_search {
        if let Some(current) = &current {
            push(&mut dirs, current, DepMode::CurrentDir);
        }
    }

    if let Ok(path) = std::env::var("PATH") {
        for entry in path.split(LIST_SEPARATOR) {
            if !entry.is_empty() {
                push(&mut dirs, entry, DepMode::EnvPath);
            }
        }
    }

    dirs
}
