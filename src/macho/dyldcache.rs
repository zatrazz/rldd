use std::collections::HashMap;
use std::fs;
use std::path::Path;
use memmap2::Mmap;
use object::Endianness;

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

fn path() -> Option<&'static str> {
    CACHE_PATHS.iter().find(|p| Path::new(p).exists()).copied()
}

// The mmapped dyld cache files along with a map of the image install names to the
// file and offset of their Mach-O headers.
#[derive(Default)]
pub struct DyldCache {
    files: Vec<Mmap>,
    images: HashMap<String, Option<(usize, u64)>>,
}

impl DyldCache {
    // Return the data and the offset of the image Mach-O header, or None if
    // NAME is not present in the cache.  The inner Option is None for images
    // whose address is not covered by any cache mapping.
    pub fn image(&self, name: &str) -> Option<Option<(&[u8], u64)>> {
        self.images
            .get(name)
            .map(|entry| entry.map(|(idx, offset)| (&self.files[idx][..], offset)))
    }

    pub fn len(&self) -> usize {
        self.images.len()
    }

    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }
}

// macOS starting with 11 (BigSur) only provides a generated cache of all built in
// dynamic libraries, so if a file does not exist in the filesystem it is then
// checked against the cache.  Starting with macOS 12 the cache is split over
// the main file and multiple subcache files, where the image list resides in
// the main file but the image contents may live in any of them.
pub fn load() -> DyldCache {
    try_load().unwrap_or_default()
}

fn try_load() -> Option<DyldCache> {
    type ObjDyldCache<'data> = object::read::macho::DyldCache<'data, Endianness>;

    let path = path()?;
    let mut files = vec![mmap_file(path)?];
    for suffix in ObjDyldCache::subcache_suffixes(&files[0][..]).ok()? {
        files.push(mmap_file(&format!("{path}{suffix}"))?);
    }

    let datas: Vec<&[u8]> = files.iter().map(|mmap| &mmap[..]).collect();
    let cache = ObjDyldCache::parse(datas[0], &datas[1..]).ok()?;

    let mut images = HashMap::new();
    for image in cache.images() {
        let Ok(name) = image.path() else {
            continue;
        };
        // Map the image address back to the cache file that contains it.
        let entry = image.image_data_and_offset().ok().and_then(|(data, offset)| {
            datas
                .iter()
                .position(|d| d.as_ptr() == data.as_ptr())
                .map(|idx| (idx, offset))
        });
        // The cache records framework images under the versioned path
        // (Foo.framework/Versions/A/Foo), while install names may reference
        // the unversioned convention (Foo.framework/Foo) whose symlink
        // target only exists inside the cache.  Register the unversioned
        // alias so both forms resolve, like dyld does.
        if let Some(alias) = unversioned_framework_alias(name) {
            images.entry(alias).or_insert(entry);
        }
        images.insert(name.to_string(), entry);
    }

    Some(DyldCache { files, images })
}

// Return the unversioned framework path (Foo.framework/Foo) for a versioned
// framework image path (Foo.framework/Versions/A/Foo).
fn unversioned_framework_alias(name: &str) -> Option<String> {
    let (dir, leaf) = name.rsplit_once('/')?;
    let (fwdir, version) = dir.rsplit_once("/Versions/")?;
    if version.contains('/') || !fwdir.ends_with(".framework") {
        return None;
    }
    let fwname = fwdir.rsplit('/').next()?.strip_suffix(".framework")?;
    if fwname == leaf {
        Some(format!("{fwdir}/{leaf}"))
    } else {
        None
    }
}

fn mmap_file(path: &str) -> Option<Mmap> {
    let file = fs::File::open(path).ok()?;
    unsafe { Mmap::map(&file) }.ok()
}
