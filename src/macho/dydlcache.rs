use std::ffi::CString;
use std::io::{Error, ErrorKind};

static MACOS_BIG_SUR_CACHE_PATH_ARM64: &str =
    "/System/Library/dyld/dyld_shared_cache_arm64e";
static MACOS_BIG_SUR_CACHE_PATH_X86_64: &str =
    "/System/Library/dyld/dyld_shared_cache_x86_64";
static MACOS_VENTURA_CACHE_PATH_ARM64: &str =
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e";
static MACOS_VENTURA_CACHE_PATH_X86_64: &str =
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64";

#[derive(Debug)]
enum MacOsRelease
{
  VENTURA,
  MONTEREY,
  BIGSUR,
}

fn osrelease() -> Result<MacOsRelease, std::io::Error> {
   let name = CString::new("kern.osrelease")?;

   // First get the size in bytes.
   let mut len = 0;
   let ret = unsafe {
      libc::sysctlbyname(
         name.as_ptr(),
         std::ptr::null_mut(),
         &mut len,
         std::ptr::null_mut(),
         0,
      )
   };
   if ret < 0 {
      return Err(std::io::Error::last_os_error());
   }

   // And then get the value.
   let mut val: Vec<libc::c_uchar> = vec![0; len];
   let mut newlen = len;
   let ret = unsafe {
      libc::sysctlbyname(
         name.as_ptr(),
         val.as_mut_ptr() as *mut libc::c_void,
         &mut newlen,
         std::ptr::null_mut(),
         0,
      )
   };
   if ret < 0 {
      return Err(std::io::Error::last_os_error());
   }

   assert!(newlen <= len);
   // The call can return bytes that are less than initially indicated, so it should
   // be safe to truncate it.
   if newlen < len {
      val.truncate(newlen);
   }

   let osrelease = match val.len() {
      0 => Ok("".to_string()),
      l => std::str::from_utf8(&val[..l - 1])
	   .map_err(|_e| Error::new(ErrorKind::Other, "Invalid UTF8 sequence"))
	   .and_then(|s| Ok(s.to_string())),
    }?;

    match osrelease.split('.').nth(0) {
         Some("22") => return Ok(MacOsRelease::VENTURA),
         Some("21") => return Ok(MacOsRelease::MONTEREY),
         Some("20") => return Ok(MacOsRelease::BIGSUR),
         _ => return Err(Error::new(ErrorKind::Other, "Invalid MacOS release")),
   }
}

pub fn path() -> Option<&'static str> {
  match osrelease() {
    Ok(MacOsRelease::VENTURA) =>
       match std::env::consts::ARCH {
          "aarch64" => Some(MACOS_VENTURA_CACHE_PATH_ARM64),
          "x86_64" => Some(MACOS_VENTURA_CACHE_PATH_X86_64),
          _ => None
       },
    Ok(MacOsRelease::MONTEREY) | Ok(MacOsRelease::BIGSUR) =>
       match std::env::consts::ARCH {
          "aarch64" => Some(MACOS_BIG_SUR_CACHE_PATH_ARM64),
          "x86_64" => Some(MACOS_BIG_SUR_CACHE_PATH_X86_64),
          _ => None
       },
    _ => None
  }
}
