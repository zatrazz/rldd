use std::path::Path;

// Known locations of the dyld shared cache for the supported architectures.
// The filesystem probing is more robust than checking the system release
// version, since it might keep working on newer macOS version (the cache
// location has been stable since Ventura).
#[cfg(target_arch = "aarch64")]
static CACHE_PATHS: &[&str] = &[
    // macOS 13 (Ventura) and later.
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
    // macOS 11 (Big Sur) and macOS 12 (Monterey).
    "/System/Library/dyld/dyld_shared_cache_arm64e",
];

#[cfg(target_arch = "x86_64")]
static CACHE_PATHS: &[&str] = &[
    // macOS 13 (Ventura) and later.
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64",
    // macOS 11 (Big Sur) and macOS 12 (Monterey).
    "/System/Library/dyld/dyld_shared_cache_x86_64",
    // macOS 10.15 (Catalina), where dyld prefers the haswell variant when
    // available.
    "/var/db/dyld/dyld_shared_cache_x86_64h",
    "/var/db/dyld/dyld_shared_cache_x86_64",
];

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
static CACHE_PATHS: &[&str] = &[];

pub fn path() -> Option<&'static str> {
    CACHE_PATHS.iter().find(|p| Path::new(p).exists()).copied()
}
