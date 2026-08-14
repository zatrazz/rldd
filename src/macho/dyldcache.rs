use memmap2::Mmap;
use object::Endianness;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// Known locations of the dyld shared cache.  The filesystem probing is more
// robust than checking the system release version, since it might keep
// working on newer macOS version (the cache location has been stable since
// Ventura).
static CACHE_DIRS: &[&str] = &[
    // macOS 13 (Ventura) and later.
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
    // macOS 11 (Big Sur) and macOS 12 (Monterey).
    "/System/Library/dyld",
    // macOS 10.15 (Catalina), where dyld prefers the haswell variant when
    // available.
    "/var/db/dyld",
];

// Find the cache file for the architecture names, in preference order.
fn path(names: &[&str]) -> Option<String> {
    for dir in CACHE_DIRS {
        for name in names {
            let path = format!("{dir}/dyld_shared_cache_{name}");
            if Path::new(&path).exists() {
                return Some(path);
            }
        }
    }
    None
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
pub fn load(names: &[&str]) -> DyldCache {
    try_load(names).unwrap_or_default()
}

fn try_load(names: &[&str]) -> Option<DyldCache> {
    type ObjDyldCache<'data> = object::read::macho::DyldCache<'data, Endianness>;

    let path = path(names)?;
    let mut files = vec![mmap_file(&path)?];
    for suffix in ObjDyldCache::subcache_suffixes(&files[0][..]).ok()? {
        files.push(mmap_file(&format!("{path}{suffix}"))?);
    }

    let datas: Vec<&[u8]> = files.iter().map(|mmap| &mmap[..]).collect();
    let cache = ObjDyldCache::parse(datas[0], &datas[1..]).ok()?;

    let mut images = HashMap::new();
    // The image entries in array order, used to resolve the dylibs trie
    // indexes below.
    let mut entries = Vec::new();
    for image in cache.images() {
        // Map the image address back to the cache file that contains it.
        let entry = image
            .image_data_and_offset()
            .ok()
            .and_then(|(data, offset)| {
                datas
                    .iter()
                    .position(|d| d.as_ptr() == data.as_ptr())
                    .map(|idx| (idx, offset))
            });
        entries.push(entry);
        let Ok(name) = image.path() else {
            continue;
        };
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

    // The dylibs trie also records the alias paths whose symlink target only
    // exists inside the cache (e.g. /usr/lib/swift/libswiftWebKit.dylib
    // pointing to WebKit), which dyld resolves but are absent from the image
    // array.
    for (path, index) in dylibs_trie(&cache, datas[0]) {
        if let Some(entry) = entries.get(index as usize) {
            images.entry(path).or_insert(*entry);
        }
    }

    Some(DyldCache { files, images })
}

// The dylib paths recorded on the cache dylibs trie along with their image
// array index, including the alias paths.
fn dylibs_trie(
    cache: &object::read::macho::DyldCache<'_, Endianness>,
    data: &[u8],
) -> Vec<(String, u64)> {
    let mut dylibs = Vec::new();
    let trie = (|| {
        let header = object::macho::DyldCacheHeader::<Endianness>::parse(data).ok()?;
        let endian = cache.endianness();
        // Older caches predate the dylibs trie header fields, whose presence
        // is signaled by the header size recorded on mapping_offset.
        let trie_fields_end =
            std::mem::offset_of!(object::macho::DyldCacheHeader<Endianness>, dylibs_trie_size) + 8;
        if (header.mapping_offset.get(endian) as usize) < trie_fields_end {
            return None;
        }
        let addr = header.dylibs_trie_addr.get(endian);
        let size = header.dylibs_trie_size.get(endian);
        if addr == 0 || size == 0 {
            return None;
        }
        let (tdata, offset) = cache.data_and_offset_for_address(addr)?;
        tdata.get(offset as usize..(offset as usize).checked_add(size as usize)?)
    })();
    if let Some(trie) = trie {
        walk_trie(trie, 0, &mut Vec::new(), &mut dylibs, 0);
    }
    dylibs
}

fn read_uleb(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

// Walk the dylibs trie (the export trie format), collecting the terminal
// paths along with their payload (the image array index).
fn walk_trie(
    data: &[u8],
    offset: usize,
    prefix: &mut Vec<u8>,
    dylibs: &mut Vec<(String, u64)>,
    depth: usize,
) -> Option<()> {
    // Guard against malformed input, the paths are bounded in practice.
    if depth > 128 {
        return None;
    }
    let mut pos = offset;
    let terminal_size = read_uleb(data, &mut pos)?;
    if terminal_size != 0 {
        let mut tpos = pos;
        let index = read_uleb(data, &mut tpos)?;
        if let Ok(path) = String::from_utf8(prefix.clone()) {
            dylibs.push((path, index));
        }
    }
    pos = pos.checked_add(terminal_size as usize)?;
    let children = *data.get(pos)?;
    pos += 1;
    for _ in 0..children {
        let start = pos;
        while *data.get(pos)? != 0 {
            pos += 1;
        }
        let edge = data[start..pos].to_vec();
        pos += 1;
        let child = read_uleb(data, &mut pos)?;
        let len = prefix.len();
        prefix.extend_from_slice(&edge);
        walk_trie(data, child as usize, prefix, dylibs, depth + 1);
        prefix.truncate(len);
    }
    Some(())
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
