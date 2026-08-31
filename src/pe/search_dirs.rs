// The directories the loader searches for a dependency, in order, following
// the documented search order for unpackaged applications.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, MAIN_SEPARATOR};

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

// A Windows on ARM host holds SyChpe32, the CHPE (hybrid x86) build of the
// core modules, which the x86 emulation loads in place of the plain x86 ones
// on SysWOW64.  It is taken wherever thesearch order reaches it, so an object
// that lives there resolves the CHPE modules too, while a copy on another
// directory still wins.
fn chpe_dir(windows: &str, is_32bit: bool) -> Option<String> {
    if !is_32bit {
        return None;
    }
    let chpe = format!("{windows}{MAIN_SEPARATOR}SyChpe32");
    Path::new(&chpe).is_dir().then_some(chpe)
}

fn same_dir(one: &str, other: &str) -> bool {
    match (std::fs::canonicalize(one), std::fs::canonicalize(other)) {
        (Ok(one), Ok(other)) => one == other,
        _ => false,
    }
}

// The system directories, in the order the loader takes them.
pub fn system_dirs(windows: &str, is_32bit: bool) -> Vec<String> {
    let mut dirs = Vec::new();
    if let Some(chpe) = chpe_dir(windows, is_32bit) {
        dirs.push(chpe);
    }
    dirs.push(system_dir(windows, is_32bit));
    dirs
}

pub fn add(dirs: &mut SearchDirs, entry: &str, mode: DepMode) {
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
    let wow64 = system_dir(windows, true);
    let shadow = chpe_dir(windows, is_32bit);

    // SyChpe32 shadows SysWOW64 wherever the order reaches it, the
    // application directory of an object living there included.
    let add_dir = |dirs: &mut SearchDirs, entry: &str, mode: DepMode| {
        if let Some(chpe) = &shadow {
            if same_dir(entry, &wow64) {
                add(dirs, chpe, mode);
            }
        }
        add(dirs, entry, mode);
    };

    if let Some(application) = application {
        add_dir(&mut dirs, application, DepMode::Application);
    }
    for path in user {
        add_dir(&mut dirs, &path.path, DepMode::LdLibraryPath);
    }

    let current = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    if !safe_search {
        if let Some(current) = &current {
            add_dir(&mut dirs, current, DepMode::CurrentDir);
        }
    }

    add_dir(
        &mut dirs,
        &system_dir(windows, is_32bit),
        DepMode::SystemDirs,
    );
    add(
        &mut dirs,
        &format!("{windows}{MAIN_SEPARATOR}System"),
        DepMode::SystemDirs,
    );
    add(&mut dirs, windows, DepMode::WindowsDir);

    if safe_search {
        if let Some(current) = &current {
            add_dir(&mut dirs, current, DepMode::CurrentDir);
        }
    }

    if let Ok(path) = std::env::var("PATH") {
        for entry in path.split(LIST_SEPARATOR) {
            if !entry.is_empty() {
                add_dir(&mut dirs, entry, DepMode::EnvPath);
            }
        }
    }

    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(dirs: &SearchDirs, mode: DepMode) -> usize {
        dirs.iter()
            .position(|(_, found)| *found == mode)
            .unwrap_or_else(|| panic!("no {mode} directory on the search order"))
    }

    #[test]
    fn wow64_system_directory() {
        assert!(system_dir(r"C:\Windows", false).ends_with(r"\System32"));
        assert!(system_dir(r"C:\Windows", true).ends_with(r"\SysWOW64"));
    }

    #[test]
    fn chpe_system_directory() {
        let windows = windows_dir();

        // A 64 bit image only has the system directory.
        assert_eq!(system_dirs(&windows, false), [system_dir(&windows, false)]);

        let dirs = system_dirs(&windows, true);
        assert_eq!(*dirs.last().unwrap(), system_dir(&windows, true));
        let chpe = format!("{windows}{MAIN_SEPARATOR}SyChpe32");
        match Path::new(&chpe).is_dir() {
            true => assert_eq!(dirs, [chpe, system_dir(&windows, true)]),
            false => assert_eq!(dirs.len(), 1),
        }
    }

    // The CHPE directory shadows SysWOW64 wherever the order reaches it, so
    // an object that lives there resolves the CHPE modules as well, while an
    // object elsewhere keeps its own directory first.
    #[test]
    fn chpe_shadows_the_application_directory() {
        let windows = windows_dir();
        let wow64 = system_dir(&windows, true);
        let Some(chpe) = chpe_dir(&windows, true) else {
            return;
        };

        let dirs = build(Some(&wow64), &SearchPathVec::new(), &windows, true, true);
        assert_eq!(dirs[0].1, DepMode::Application);
        assert!(same_dir(&dirs[0].0.path, &chpe), "{}", dirs[0].0.path);
        assert!(same_dir(&dirs[1].0.path, &wow64), "{}", dirs[1].0.path);

        // A 64 bit object never takes it.
        let dirs = build(Some(&wow64), &SearchPathVec::new(), &windows, false, true);
        assert!(!dirs.iter().any(|(dir, _)| same_dir(&dir.path, &chpe)));
    }

    // The application directory is searched first, then the ones set with
    // SetDllDirectory, and the Windows directory after the system one.
    #[test]
    fn search_order() {
        let windows = windows_dir();
        let current = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut user = SearchPathVec::new();
        user.add_path(&current);

        let dirs = build(
            Some(&system_dir(&windows, false)),
            &user,
            &windows,
            false,
            true,
        );

        assert_eq!(dirs[0].1, DepMode::Application);
        assert!(position(&dirs, DepMode::LdLibraryPath) < position(&dirs, DepMode::WindowsDir));
        assert!(position(&dirs, DepMode::WindowsDir) < position(&dirs, DepMode::EnvPath));
    }

    // The safe mode moves the current directory after the system ones.
    #[test]
    fn safe_search_mode() {
        let windows = windows_dir();
        let safe = build(None, &SearchPathVec::new(), &windows, false, true);
        assert!(position(&safe, DepMode::SystemDirs) < position(&safe, DepMode::CurrentDir));

        let unsafe_search = build(None, &SearchPathVec::new(), &windows, false, false);
        assert!(
            position(&unsafe_search, DepMode::CurrentDir)
                < position(&unsafe_search, DepMode::SystemDirs)
        );
    }

    // A directory reached twice keeps the mode it was first added with.
    #[test]
    fn duplicated_directories() {
        let windows = windows_dir();
        let dirs = build(Some(&windows), &SearchPathVec::new(), &windows, false, true);
        assert_eq!(dirs[0].1, DepMode::Application);
        assert!(!dirs.iter().any(|(_, mode)| *mode == DepMode::WindowsDir));
    }

    // A directory that does not exist is not searched.
    #[test]
    fn missing_directories() {
        let dirs = build(
            Some(r"C:\rldd-does-not-exist"),
            &SearchPathVec::new(),
            &windows_dir(),
            false,
            true,
        );
        assert!(!dirs.iter().any(|(_, mode)| *mode == DepMode::Application));
    }
}
