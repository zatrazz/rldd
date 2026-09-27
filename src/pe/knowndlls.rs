// The known DLLs: the modules the loader maps from the \KnownDlls object
// directory (\KnownDlls32 for the 32 bit images), whatever the search order
// says.  At boot, smss creates a section there for each module of the
// KnownDLLs registry key and for every module their imports pull in, with the
// API sets resolved, so the directory is the registry list along with its
// static import closure (on Windows 11 24H2, the 38 registry values give 42
// sections, ntdll, kernelbase and ucrtbase among the extra ones).  The modules
// the ExcludeFromKnownDlls value of the Session Manager lists are left out.

use std::collections::{HashSet, VecDeque};

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ,
    REG_SZ,
};

const SESSION_MANAGER_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager";
const KNOWNDLLS_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs";

// A module of the known DLLs list, with the name its registry value has and
// the file it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownDll {
    pub name: String,
    pub file: String,
}

impl KnownDll {
    // A module an import pulls in, which smss names by the file name up to
    // its first dot.
    fn imported(file: String) -> Self {
        let name = file.split('.').next().unwrap_or_default().to_string();
        KnownDll { name, file }
    }
}

#[derive(Default, Debug)]
pub struct KnownDlls {
    // The registry list, as recorded.
    entries: Vec<KnownDll>,
    // The ExcludeFromKnownDlls list.
    excluded: Vec<String>,
    dir: Option<String>,
    dir32: Option<String>,
}

impl KnownDlls {
    pub fn entries(&self) -> &[KnownDll] {
        &self.entries
    }

    pub fn excluded(&self) -> &[String] {
        &self.excluded
    }

    // The 32 bit known DLLs live on the DllDirectory32 directory.
    pub fn directory(&self, is_32bit: bool) -> Option<&str> {
        if is_32bit {
            self.dir32.as_deref()
        } else {
            self.dir.as_deref()
        }
    }
}

// The known DLL sections smss creates for the ENTRIES registry list: each
// module that exists, then the modules its IMPORTS (the static ones, with the
// API sets already resolved) name, until no new one shows up.  IMPORTS returns
// None for a module that could not be opened, which gets no section.  A module
// whose name or file the EXCLUDED list names gets no section either, and its
// imports are not followed: smss appends the imports of each module to the
// list it walks, and checks every entry against the exclusion list, comparing
// both the value name and the file name without regard to case (the ReactOS
// smss, SmpInitializeKnownDllsInternal and SmpProcessModuleImports, does the
// same).  The names are lowercased.
pub fn sections<F>(entries: &[KnownDll], excluded: &[String], mut imports: F) -> HashSet<String>
where
    F: FnMut(&str) -> Option<Vec<String>>,
{
    let is_excluded = |entry: &KnownDll| {
        excluded.iter().any(|excluded| {
            excluded.eq_ignore_ascii_case(&entry.name) || excluded.eq_ignore_ascii_case(&entry.file)
        })
    };
    let mut sections = HashSet::new();
    let mut seen = HashSet::new();
    let mut queue: VecDeque<KnownDll> = entries.iter().cloned().collect();
    while let Some(entry) = queue.pop_front() {
        if is_excluded(&entry) || !seen.insert(entry.file.to_lowercase()) {
            continue;
        }
        let Some(deps) = imports(&entry.file) else {
            continue;
        };
        sections.insert(entry.file.to_lowercase());
        queue.extend(
            deps.into_iter()
                .filter(|dep| !seen.contains(&dep.to_lowercase()))
                .map(KnownDll::imported),
        );
    }
    sections
}

// Expand the '%NAME%' environment references of a REG_EXPAND_SZ value, the
// way ExpandEnvironmentStrings does: a reference to an unset variable is left
// as it is.
fn expand(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            rest = &rest[start..];
            break;
        };
        match std::env::var(&after[..end]) {
            Ok(expanded) if end > 0 => out.push_str(&expanded),
            _ => out.push_str(&rest[start..start + end + 2]),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
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
    let mut known = KnownDlls {
        excluded: super::registry::multi_string(SESSION_MANAGER_KEY, "ExcludeFromKnownDlls"),
        ..Default::default()
    };
    let subkey = super::registry::wide(KNOWNDLLS_KEY);
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
        // The directories are REG_EXPAND_SZ values, usually holding
        // '%SystemRoot%', which the registry does not expand.
        let value = match kind {
            REG_EXPAND_SZ => expand(&value),
            _ => value,
        };
        if name.eq_ignore_ascii_case("DllDirectory") {
            known.dir = Some(value);
        } else if name.eq_ignore_ascii_case("DllDirectory32") {
            known.dir32 = Some(value);
        } else if !value.is_empty() {
            known.entries.push(KnownDll { name, file: value });
        }
    }

    // The key comes from the RegOpenKeyExW above and is not used after this
    // point.
    unsafe { RegCloseKey(key) };

    known
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, file: &str) -> KnownDll {
        KnownDll {
            name: name.to_string(),
            file: file.to_string(),
        }
    }

    // The sections of the ENTRIES without the EXCLUDED ones, for a.dll
    // importing b.dll and itself, b.dll importing c.dll, and c.dll importing
    // a.dll, d.dll and a module that does not exist.
    fn closure(entries: &[KnownDll], excluded: &[&str]) -> Vec<String> {
        let excluded: Vec<String> = excluded.iter().map(|name| name.to_string()).collect();
        let sections = sections(entries, &excluded, |name| {
            match name.to_lowercase().as_str() {
                "a.dll" => Some(vec!["b.dll".to_string(), "A.DLL".to_string()]),
                "b.dll" => Some(vec!["C.dll".to_string()]),
                "c.dll" => Some(vec![
                    "a.dll".to_string(),
                    "d.dll".to_string(),
                    "gone.dll".to_string(),
                ]),
                "d.dll" => Some(Vec::new()),
                _ => None,
            }
        });
        let mut sections: Vec<_> = sections.into_iter().collect();
        sections.sort();
        sections
    }

    // The registry list along with the modules their imports pull in, which
    // is not every module the program uses: a module that does not exist
    // gets no section, and neither do its imports.
    #[test]
    fn import_closure() {
        let entries = [entry("A", "A.dll"), entry("missing", "missing.dll")];
        assert_eq!(closure(&entries, &[]), ["a.dll", "b.dll", "c.dll", "d.dll"]);
    }

    // An excluded module gets no section, whether the registry lists it or an
    // import pulls it in, and its imports are not followed; the exclusion
    // names the registry value, or the file, or an import up to its first
    // dot.
    #[test]
    fn excluded_modules() {
        let entries = [entry("A", "A.dll"), entry("SHELL", "d.dll")];
        assert_eq!(closure(&entries, &["a.DLL"]), ["d.dll"]);
        assert_eq!(closure(&entries, &["a"]), ["d.dll"]);
        assert_eq!(
            closure(&entries, &["SHELL"]),
            ["a.dll", "b.dll", "c.dll", "d.dll"]
        );
        assert_eq!(
            closure(&entries, &["shell", "d"]),
            ["a.dll", "b.dll", "c.dll"]
        );
        assert_eq!(closure(&entries, &["B.dll"]), ["a.dll", "d.dll"]);
        assert_eq!(closure(&entries, &["c"]), ["a.dll", "b.dll", "d.dll"]);
        assert_eq!(
            closure(&entries, &["gone"]),
            ["a.dll", "b.dll", "c.dll", "d.dll"]
        );
    }

    #[test]
    fn expand_references() {
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(
            expand(r"%SystemRoot%\system32"),
            format!(r"{root}\system32")
        );
        assert_eq!(expand(r"%systemroot%\x"), format!(r"{root}\x"));
        assert_eq!(
            expand("%rldd-not-a-variable%\\x"),
            "%rldd-not-a-variable%\\x"
        );
        assert_eq!(expand("100%"), "100%");
        assert_eq!(expand("%%"), "%%");
        assert_eq!(expand("plain"), "plain");
    }

    #[test]
    fn registry_list() {
        let known = load();
        assert!(known
            .entries()
            .iter()
            .any(|entry| entry.file.eq_ignore_ascii_case("kernel32.dll")));
        // The directories, when set, are expanded.
        for dir in [known.directory(false), known.directory(true)]
            .into_iter()
            .flatten()
        {
            assert!(!dir.contains('%'), "{dir}");
        }
    }
}
