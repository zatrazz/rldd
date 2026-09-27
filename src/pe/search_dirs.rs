// The directories the loader searches for a dependency, in order, following
// the documented search order for unpackaged applications.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;

use windows_sys::Win32::Foundation::MAX_PATH;
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

use super::machine::Wow64;
use crate::deptree::DepMode;
use crate::pathutils;
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

// The system directory, which is SysWOW64 or SysArm32 for the 32 bit images.
pub fn system_dir(windows: &str, wow64: Wow64) -> String {
    pathutils::join(windows, wow64.system_dir())
}

// A Windows on ARM host holds SyChpe32, the CHPE (hybrid x86) build of the
// core modules, which the x86 emulation loads in place of the plain x86 ones
// on SysWOW64.  It is taken wherever thesearch order reaches it, so an object
// that lives there resolves the CHPE modules too, while a copy on another
// directory still wins.
fn chpe_dir(windows: &str, wow64: Wow64) -> Option<String> {
    if wow64 != Wow64::X86 {
        return None;
    }
    let chpe = pathutils::join(windows, "SyChpe32");
    Path::new(&chpe).is_dir().then_some(chpe)
}

fn same_dir(one: &str, other: &str) -> bool {
    match (std::fs::canonicalize(one), std::fs::canonicalize(other)) {
        (Ok(one), Ok(other)) => one == other,
        _ => false,
    }
}

// The system directories, in the order the loader takes them.
pub fn system_dirs(windows: &str, wow64: Wow64) -> Vec<String> {
    let mut dirs = Vec::new();
    if let Some(chpe) = chpe_dir(windows, wow64) {
        dirs.push(chpe);
    }
    dirs.push(system_dir(windows, wow64));
    dirs
}

// The directories below System32 the WOW64 file system redirector leaves
// alone.
const REDIRECTION_EXEMPT: [&str; 6] = [
    "catroot",
    "catroot2",
    "driverstore",
    r"drivers\etc",
    "logfiles",
    "spool",
];

// The rest of PATH after the DIR prefix, when PATH is DIR or a path below it.
// The names are compared without regard to ASCII case, and either separator
// matches the one DIR has.
fn below<'a>(path: &'a str, dir: &str) -> Option<&'a str> {
    let head = path.as_bytes().get(..dir.len())?;
    let same = head.iter().zip(dir.as_bytes()).all(|(a, b)| {
        a.eq_ignore_ascii_case(b) || (matches!(a, b'/' | b'\\') && matches!(b, b'/' | b'\\'))
    });
    let rest = path.get(dir.len()..)?;
    (same && (rest.is_empty() || rest.starts_with(['\\', '/']))).then_some(rest)
}

// The directory a 32 bit image reaches for ENTRY through the WOW64 file system
// redirector: System32 and everything below it stand for the WOW64 system
// directory, except the few exempt directories, and Sysnative names the real
// System32, as
// https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
// documents.  A 32 bit image importing wmiutils.dll finds it through the
// 'C:\Windows\System32\wbem' PATH entry, which is SysWOW64\wbem for it.
pub fn redirect(entry: &str, windows: &str, wow64: Wow64) -> String {
    if wow64 == Wow64::Native {
        return entry.to_string();
    }
    let system32 = pathutils::join(windows, "System32");
    if let Some(rest) = below(entry, &system32) {
        let inner = rest.trim_start_matches(['\\', '/']);
        if REDIRECTION_EXEMPT
            .iter()
            .any(|exempt| below(inner, exempt).is_some())
        {
            return entry.to_string();
        }
        return format!("{}{rest}", system_dir(windows, wow64));
    }
    if let Some(rest) = below(entry, &pathutils::join(windows, "Sysnative")) {
        return format!("{system32}{rest}");
    }
    entry.to_string()
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
// application one.  SetDllDirectory removes the current directory from the
// order altogether, as its documentation describes (and LoadLibrary no longer
// finds a module only the current directory holds after the call).
pub fn build(
    application: Option<&str>,
    user: &SearchPathVec,
    windows: &str,
    wow64: Wow64,
    safe_search: bool,
) -> SearchDirs {
    let mut dirs = SearchDirs::new();
    let syswow64 = system_dir(windows, Wow64::X86);
    let shadow = chpe_dir(windows, wow64);

    // Every directory goes through the WOW64 redirection, and SyChpe32
    // shadows SysWOW64 wherever the order reaches it, the application
    // directory of an object living there included.
    let add_dir = |dirs: &mut SearchDirs, entry: &str, mode: DepMode| {
        let entry = redirect(entry, windows, wow64);
        if let Some(chpe) = &shadow {
            if same_dir(&entry, &syswow64) {
                add(dirs, chpe, mode);
            }
        }
        add(dirs, &entry, mode);
    };

    if let Some(application) = application {
        add_dir(&mut dirs, application, DepMode::Application);
    }
    for path in user {
        add_dir(&mut dirs, &path.path, DepMode::LdLibraryPath);
    }

    let current = std::env::current_dir()
        .ok()
        .filter(|_| user.is_empty())
        .map(|path| path.to_string_lossy().into_owned());
    if !safe_search {
        if let Some(current) = &current {
            add_dir(&mut dirs, current, DepMode::CurrentDir);
        }
    }

    add_dir(&mut dirs, &system_dir(windows, wow64), DepMode::SystemDirs);
    add(
        &mut dirs,
        &pathutils::join(windows, "System"),
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
        assert!(system_dir(r"C:\Windows", Wow64::Native).ends_with(r"\System32"));
        assert!(system_dir(r"C:\Windows", Wow64::X86).ends_with(r"\SysWOW64"));
    }

    #[test]
    fn chpe_system_directory() {
        let windows = windows_dir();

        // A 64 bit image only has the system directory.
        assert_eq!(
            system_dirs(&windows, Wow64::Native),
            [system_dir(&windows, Wow64::Native)]
        );

        let dirs = system_dirs(&windows, Wow64::X86);
        assert_eq!(*dirs.last().unwrap(), system_dir(&windows, Wow64::X86));
        let chpe = pathutils::join(&windows, "SyChpe32");
        match Path::new(&chpe).is_dir() {
            true => assert_eq!(dirs, [chpe, system_dir(&windows, Wow64::X86)]),
            false => assert_eq!(dirs.len(), 1),
        }
    }

    // The CHPE directory shadows SysWOW64 wherever the order reaches it, so
    // an object that lives there resolves the CHPE modules as well, while an
    // object elsewhere keeps its own directory first.
    #[test]
    fn chpe_shadows_the_application_directory() {
        let windows = windows_dir();
        let wow64 = system_dir(&windows, Wow64::X86);
        let Some(chpe) = chpe_dir(&windows, Wow64::X86) else {
            return;
        };

        let dirs = build(
            Some(&wow64),
            &SearchPathVec::new(),
            &windows,
            Wow64::X86,
            true,
        );
        assert_eq!(dirs[0].1, DepMode::Application);
        assert!(same_dir(&dirs[0].0.path, &chpe), "{}", dirs[0].0.path);
        assert!(same_dir(&dirs[1].0.path, &wow64), "{}", dirs[1].0.path);

        // A 64 bit object never takes it.
        let dirs = build(
            Some(&wow64),
            &SearchPathVec::new(),
            &windows,
            Wow64::Native,
            true,
        );
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
            Some(&system_dir(&windows, Wow64::Native)),
            &user,
            &windows,
            Wow64::Native,
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
        let safe = build(None, &SearchPathVec::new(), &windows, Wow64::Native, true);
        assert!(position(&safe, DepMode::SystemDirs) < position(&safe, DepMode::CurrentDir));

        let unsafe_search = build(None, &SearchPathVec::new(), &windows, Wow64::Native, false);
        assert!(
            position(&unsafe_search, DepMode::CurrentDir)
                < position(&unsafe_search, DepMode::SystemDirs)
        );
    }

    // SetDllDirectory removes the current directory, whatever the safe
    // search mode.
    #[test]
    fn dll_directory_drops_the_current_directory() {
        let windows = windows_dir();
        let mut user = SearchPathVec::new();
        user.add_path(&windows);
        for safe_search in [true, false] {
            let dirs = build(None, &user, &windows, Wow64::Native, safe_search);
            assert!(!dirs.iter().any(|(_, mode)| *mode == DepMode::CurrentDir));
            assert_eq!(dirs[0].1, DepMode::LdLibraryPath);
        }
    }

    // A directory reached twice keeps the mode it was first added with.
    #[test]
    fn duplicated_directories() {
        let windows = windows_dir();
        let dirs = build(
            Some(&windows),
            &SearchPathVec::new(),
            &windows,
            Wow64::Native,
            true,
        );
        assert_eq!(dirs[0].1, DepMode::Application);
        assert!(!dirs.iter().any(|(_, mode)| *mode == DepMode::WindowsDir));
    }

    // A 32 bit image sees System32 and what is below it as the WOW64 system
    // directory, except for the exempt directories, and Sysnative as the
    // real System32.  A 64 bit one sees every path as it is.
    #[test]
    fn wow64_redirection() {
        let w = r"C:\Windows";
        let x86 = |entry| redirect(entry, w, Wow64::X86);
        assert_eq!(x86(r"C:\Windows\System32"), r"C:\Windows\SysWOW64");
        assert_eq!(
            x86(r"c:\windows\system32\wbem"),
            r"C:\Windows\SysWOW64\wbem"
        );
        assert_eq!(x86(r"C:/Windows/System32/"), r"C:\Windows\SysWOW64/");
        assert_eq!(
            x86(r"C:\Windows\System32\drivers"),
            r"C:\Windows\SysWOW64\drivers"
        );
        assert_eq!(
            x86(r"C:\Windows\System32\spool"),
            r"C:\Windows\System32\spool"
        );
        assert_eq!(
            x86(r"C:\Windows\System32\catroot2\x"),
            r"C:\Windows\System32\catroot2\x"
        );
        assert_eq!(
            x86(r"C:\Windows\System32\drivers\etc"),
            r"C:\Windows\System32\drivers\etc"
        );
        assert_eq!(
            x86(r"C:\Windows\System32\DriverStore\FileRepository"),
            r"C:\Windows\System32\DriverStore\FileRepository"
        );
        assert_eq!(
            x86(r"C:\Windows\System32\catrootx"),
            r"C:\Windows\SysWOW64\catrootx"
        );
        assert_eq!(
            x86(r"C:\Windows\Sysnative\wbem"),
            r"C:\Windows\System32\wbem"
        );
        assert_eq!(x86(r"C:\Windows\System32x"), r"C:\Windows\System32x");
        assert_eq!(x86(r"C:\Windows"), r"C:\Windows");
        assert_eq!(x86("C:\\Windows\\Systém"), "C:\\Windows\\Systém");
        assert_eq!(
            redirect(r"C:\Windows\System32", w, Wow64::Arm32),
            r"C:\Windows\SysArm32"
        );
        assert_eq!(
            redirect(r"C:\Windows\System32\wbem", w, Wow64::Native),
            r"C:\Windows\System32\wbem"
        );
        assert_eq!(
            redirect(r"C:\Windows\Sysnative", w, Wow64::Native),
            r"C:\Windows\Sysnative"
        );
    }

    // The redirection applies to every directory of the order, so the
    // application directory of a 32 bit image under System32 is SysWOW64.
    #[test]
    fn wow64_redirected_order() {
        let windows = windows_dir();
        let system32 = system_dir(&windows, Wow64::Native);
        let syswow64 = system_dir(&windows, Wow64::X86);
        if !Path::new(&syswow64).is_dir() {
            return;
        }
        let dirs = build(
            Some(&system32),
            &SearchPathVec::new(),
            &windows,
            Wow64::X86,
            true,
        );
        let application = dirs
            .iter()
            .find(|(_, mode)| *mode == DepMode::Application)
            .unwrap();
        assert!(
            same_dir(&application.0.path, &syswow64),
            "{}",
            application.0.path
        );
        assert!(!dirs.iter().any(|(dir, _)| same_dir(&dir.path, &system32)));
    }

    // A directory that does not exist is not searched.
    #[test]
    fn missing_directories() {
        let dirs = build(
            Some(r"C:\rldd-does-not-exist"),
            &SearchPathVec::new(),
            &windows_dir(),
            Wow64::Native,
            true,
        );
        assert!(!dirs.iter().any(|(_, mode)| *mode == DepMode::Application));
    }
}
