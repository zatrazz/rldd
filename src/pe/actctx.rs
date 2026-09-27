// The system default activation context: the Microsoft.Windows.SystemCompatible
// assembly and the ones it depends on (the common controls version 5.82 and
// GDI+ 1.1 among them), which the loader searches for a module name after the
// activation contexts of the importing module and of the process.  Its
// manifests are compressed on the WinSxS store, so the OS is asked for it.
//
// The OS builds the context for the architecture of each process, which is
// not the one of rldd for an image of another machine.  The context an x86
// process gets is the one created from the same root assembly with the x86
// architecture, which a process of any architecture may create (checked on
// Windows 11 24H2: the same six assemblies, at the same builds, as a 32 bit
// process queries, which differ from the 64 bit ones).

use std::cell::RefCell;
use std::collections::HashMap;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    ActivateActCtx, CreateActCtxW, DeactivateActCtx, FindActCtxSectionStringW, QueryActCtxW,
    ReleaseActCtx, ACTCTXW, ACTCTX_SECTION_KEYED_DATA,
    ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION,
};
use windows_sys::Win32::System::WindowsProgramming::{
    ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF, FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX,
};

use super::registry::wide;

// From winbase.h and winnt.h.
const ACTCTX_SYSTEM_DEFAULT: HANDLE = -4isize as HANDLE;
const ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION: u32 = 2;
const ASSEMBLY_DETAILED_INFORMATION_IN_ACTIVATION_CONTEXT: u32 = 3;

// The roster index of the root assembly of a context.
const ROOT_ASSEMBLY: u32 = 1;

pub struct SystemContext {
    handle: HANDLE,
    // The WinSxS directory each module name is redirected to, None when the
    // context holds no such module.
    redirected: RefCell<HashMap<String, Option<String>>>,
}

impl SystemContext {
    // The system default context of the processes of the store ARCH
    // ('x86', 'amd64', 'arm64'...).
    pub fn new(arch: &str) -> Option<Self> {
        let root = assembly_information(ACTCTX_SYSTEM_DEFAULT, ROOT_ASSEMBLY)?.identity;
        let identity = with_architecture(&root, arch)?;
        let source = wide(&identity);
        let request = ACTCTXW {
            cbSize: std::mem::size_of::<ACTCTXW>() as u32,
            dwFlags: ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF,
            lpSource: source.as_ptr(),
            ..Default::default()
        };
        // SAFETY: the request describes itself, and its source is a NUL
        // terminated string that outlives the call.
        let handle = unsafe { CreateActCtxW(&request) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return None;
        }
        Some(SystemContext {
            handle,
            redirected: RefCell::new(HashMap::new()),
        })
    }

    // The WinSxS directory the context redirects the module NAME to.
    pub fn redirect(&self, name: &str) -> Option<String> {
        let key = name.to_lowercase();
        if let Some(found) = self.redirected.borrow().get(&key) {
            return found.clone();
        }
        let found = self.find(name);
        self.redirected.borrow_mut().insert(key, found.clone());
        found
    }

    fn find(&self, name: &str) -> Option<String> {
        let name = wide(name);
        let mut cookie = 0usize;
        // SAFETY: the handle is a context of ours, activated on this thread
        // and deactivated below with its cookie.
        if unsafe { ActivateActCtx(self.handle, &mut cookie) } == 0 {
            return None;
        }
        let mut data = ACTCTX_SECTION_KEYED_DATA {
            cbSize: std::mem::size_of::<ACTCTX_SECTION_KEYED_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: the name is NUL terminated and the data describes itself;
        // the context found is returned with a reference, released below.
        let found = unsafe {
            FindActCtxSectionStringW(
                FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX,
                std::ptr::null(),
                ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION,
                name.as_ptr(),
                &mut data,
            )
        } != 0;
        // SAFETY: the cookie comes from the activation above.
        unsafe { DeactivateActCtx(0, cookie) };
        if !found || data.hActCtx.is_null() {
            return None;
        }
        // The search falls back to the contexts of rldd itself, which are
        // not the ones of the image.
        let ours = data.hActCtx == self.handle;
        // SAFETY: the handle was returned with a reference.
        unsafe { ReleaseActCtx(data.hActCtx) };
        if !ours {
            return None;
        }
        assembly_information(self.handle, data.ulAssemblyRosterIndex)?.directory
    }
}

impl Drop for SystemContext {
    fn drop(&mut self) {
        // SAFETY: the handle comes from CreateActCtxW and is not used after
        // this point.
        unsafe { ReleaseActCtx(self.handle) };
    }
}

struct AssemblyInformation {
    identity: String,
    directory: Option<String>,
}

// The identity and the WinSxS directory of the assembly at INDEX on the roster
// of the CONTEXT.
fn assembly_information(context: HANDLE, index: u32) -> Option<AssemblyInformation> {
    let mut needed = 0usize;
    // SAFETY: the index is the sub instance this class expects, and an empty
    // buffer only asks for the size.
    unsafe {
        QueryActCtxW(
            0,
            context,
            &index as *const u32 as *const std::ffi::c_void,
            ASSEMBLY_DETAILED_INFORMATION_IN_ACTIVATION_CONTEXT,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed < std::mem::size_of::<ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION>() {
        return None;
    }
    // A buffer of u64 is aligned for the structure, which the strings follow.
    let mut buffer = vec![0u64; needed.div_ceil(8)];
    // SAFETY: the buffer and its size in bytes describe BUFFER.
    let ok = unsafe {
        QueryActCtxW(
            0,
            context,
            &index as *const u32 as *const std::ffi::c_void,
            ASSEMBLY_DETAILED_INFORMATION_IN_ACTIVATION_CONTEXT,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len() * 8,
            &mut needed,
        )
    } != 0;
    if !ok {
        return None;
    }
    // SAFETY: the call filled the structure at the start of the buffer, whose
    // string pointers point inside it at strings of the recorded lengths in
    // bytes.
    let (identity, directory) = unsafe {
        let info = &*(buffer.as_ptr() as *const ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION);
        (
            string(
                info.lpAssemblyEncodedAssemblyIdentity,
                info.ulEncodedAssemblyIdentityLength,
            ),
            string(
                info.lpAssemblyDirectoryName,
                info.ulAssemblyDirectoryNameLength,
            ),
        )
    };
    Some(AssemblyInformation {
        identity: identity?,
        directory,
    })
}

// SAFETY: POINTER is null or points at BYTES bytes of UTF-16.
unsafe fn string(pointer: *const u16, bytes: u32) -> Option<String> {
    if pointer.is_null() || bytes == 0 {
        return None;
    }
    let units = std::slice::from_raw_parts(pointer, bytes as usize / 2);
    Some(String::from_utf16_lossy(units))
}

// The assembly IDENTITY with its processorArchitecture attribute set to ARCH.
fn with_architecture(identity: &str, arch: &str) -> Option<String> {
    const ATTRIBUTE: &str = "processorArchitecture=\"";
    let start = identity.find(ATTRIBUTE)? + ATTRIBUTE.len();
    let end = start + identity[start..].find('"')?;
    Some(format!("{}{arch}{}", &identity[..start], &identity[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_attribute() {
        let identity = r#"Microsoft.Windows.SystemCompatible,processorArchitecture="amd64",publicKeyToken="6595b64144ccf1df",type="win32",version="6.0.26100.1""#;
        assert_eq!(
            with_architecture(identity, "x86").unwrap(),
            identity.replace("amd64", "x86")
        );
        assert!(with_architecture("Name,version=\"1.0\"", "x86").is_none());
    }

    // The system default context of the native processes redirects comctl32
    // to the common controls version 5.82 and gdiplus to GDI+ 1.1, and so
    // does the one of the x86 processes, to its own assemblies.
    #[test]
    fn system_default_context() {
        let native = match cfg!(target_arch = "aarch64") {
            true => "arm64",
            false => "amd64",
        };
        let context = SystemContext::new(native).expect("no system default context");
        let comctl32 = context.redirect("COMCTL32.dll").unwrap();
        assert!(comctl32.starts_with(&format!("{native}_microsoft.windows.common-controls_")));
        assert!(comctl32.contains("_5.82."), "{comctl32}");
        let gdiplus = context.redirect("gdiplus.dll").unwrap();
        assert!(gdiplus.contains("_1.1."), "{gdiplus}");
        assert!(context.redirect("kernel32.dll").is_none());
        // Cached, and still the same.
        assert_eq!(context.redirect("comctl32.dll"), Some(comctl32));

        if let Some(x86) = SystemContext::new("x86") {
            let comctl32 = x86.redirect("comctl32.dll").unwrap();
            assert!(comctl32.starts_with("x86_microsoft.windows.common-controls_"));
        }
    }
}
