use std::collections::HashMap;
use std::io::{Error, Result};
use std::mem::{align_of, size_of};
use std::path::Path;
use std::{fs, str};

use crate::pathutils;
use object::elf::*;
use object::Pod;

mod hwcap;

const CACHEMAGIC: &str = "ld.so-1.7.0";
const CACHEMAGIC_NEW: &str = "glibc-ld.so.cache";
const CACHE_VERSION: &str = "1.1";

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct cache_file {
    magic: [u8; CACHEMAGIC.len()],
    // The alignment padding before nlibs, explicit so the struct has none.
    _padding: [u8; 1],
    nlibs: u32,
}
// SAFETY: repr(C) integers and byte arrays, without padding (the size is the
// sum of the fields).
unsafe impl Pod for cache_file {}
const _: () = assert!(std::mem::size_of::<cache_file>() == CACHEMAGIC.len() + 1 + 4);
const CACHE_FILE_LEN: usize = size_of::<cache_file>();

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct file_entry {
    flags: i32,
    key: u32,
    value: u32,
}
// SAFETY: repr(C) integers and byte arrays, without padding (the size is the
// sum of the fields).
unsafe impl Pod for file_entry {}
const _: () = assert!(std::mem::size_of::<file_entry>() == 3 * 4);
const FILE_ENTRY_LEN: usize = size_of::<file_entry>();

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct cache_file_new {
    magic: [u8; CACHEMAGIC_NEW.len()],
    version: [u8; CACHE_VERSION.len()],
    nlibs: u32,
    len_strings: u32,
    flags: u8,
    padding_unsed: [u8; 3],
    extension_offset: u32,
    unused: [u32; 3],
}
// SAFETY: repr(C) integers and byte arrays, without padding (the size is the
// sum of the fields).
unsafe impl Pod for cache_file_new {}
const _: () = assert!(
    std::mem::size_of::<cache_file_new>()
        == CACHEMAGIC_NEW.len() + CACHE_VERSION.len() + 4 + 4 + 1 + 3 + 4 + 3 * 4
);
const CACHE_FILE_NEW_LEN: usize = size_of::<cache_file_new>();

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct file_entry_new {
    flags: i32,
    key: u32,
    value: u32,
    osversion_unused: u32,
    hwcap: u64,
}
// SAFETY: repr(C) integers and byte arrays, without padding (the size is the
// sum of the fields).
unsafe impl Pod for file_entry_new {}
const _: () = assert!(std::mem::size_of::<file_entry_new>() == 4 * 4 + 8);
const FILE_ENTRY_NEW_LEN: usize = size_of::<file_entry_new>();

// The cache_file_new extension header, pointer by extension_offset field.  The MAGIC should be
// 'cache_extension_magic' and COUNT indicates ow many cache_extension_section can be read
// (on glibc definition the cache_extension_section is defined as a flexible array meant to be
// accessed through mmap).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct cache_extension {
    magic: u32,
    count: u32,
}
// SAFETY: repr(C) integers and byte arrays, without padding (the size is the
// sum of the fields).
unsafe impl Pod for cache_extension {}
const _: () = assert!(std::mem::size_of::<cache_extension>() == 2 * 4);
const CACHE_EXTENSION_LEN: usize = size_of::<cache_extension>();

#[allow(non_upper_case_globals)]
const cache_extension_magic: u32 = 0xeaa42174;

const CACHE_EXTENSION_TAG_GLIBC_HWCAPS: u32 = 1;

// Element in the array following struct cache_extension.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct cache_extension_section {
    tag: u32,    // Type of the extension section (CACHE_EXTENSION_TAG_*).
    flags: u32,  // Extension-specific flags.  Currently generated as zero.
    offset: u32, // Offset from the start of the file for the data in this extension section.
    size: u32,   // Length in bytes of the extension data.
}
// SAFETY: repr(C) integers and byte arrays, without padding (the size is the
// sum of the fields).
unsafe impl Pod for cache_extension_section {}
const _: () = assert!(std::mem::size_of::<cache_extension_section>() == 4 * 4);
const CACHE_EXTENSION_SECTION_LEN: usize = size_of::<cache_extension_section>();

// Check the ld.so.cache file_entry_new flags against a pre-defined value from glibc
// dl-cache.h.
const FLAG_ELF_LIBC6: i32 = 0x0003;
const FLAG_SPARC_LIB64: i32 = 0x0100;
const FLAG_IA64_LIB64: i32 = 0x0200;
const FLAG_X8664_LIB64: i32 = 0x0300;
const FLAG_S390_LIB64: i32 = 0x0400;
const FLAG_POWERPC_LIB64: i32 = 0x0500;
const FLAG_MIPS64_LIBN32: i32 = 0x0600;
const FLAG_MIPS64_LIBN64: i32 = 0x0700;
const FLAG_X8664_LIBX32: i32 = 0x0800;
const FLAG_ARM_LIBHF: i32 = 0x0900;
const FLAG_AARCH64_LIB64: i32 = 0x0a00;
const FLAG_ARM_LIBSF: i32 = 0x0b00;
const FLAG_MIPS_LIB32_NAN2008: i32 = 0x0c00;
const FLAG_MIPS64_LIBN32_NAN2008: i32 = 0x0d00;
const FLAG_MIPS64_LIBN64_NAN2008: i32 = 0x0e00;
const FLAG_RISCV_FLOAT_ABI_SOFT: i32 = 0x0f00;
const FLAG_RISCV_FLOAT_ABI_DOUBLE: i32 = 0x1000;
const FLAG_LARCH_FLOAT_ABI_SOFT: i32 = 0x1100;
const FLAG_LARCH_FLOAT_ABI_DOUBLE: i32 = 0x1200;

fn check_file_entry_flags(
    flags: i32,
    ei_class: FileClass,
    e_machine: Machine,
    e_flags: FileFlags,
) -> bool {
    match e_machine {
        EM_AARCH64 => match ei_class {
            ELFCLASS64 => flags == FLAG_ELF_LIBC6 | FLAG_AARCH64_LIB64,
            _ => false,
        },
        EM_ARM => {
            if e_flags.contains(EF_ARM_VFP_FLOAT) {
                (flags == FLAG_ARM_LIBHF | FLAG_ELF_LIBC6) || (flags == FLAG_ELF_LIBC6)
            } else {
                // Either EF_ARM_SOFT_FLOAT or no float ABI flag at all.
                (flags == FLAG_ARM_LIBSF | FLAG_ELF_LIBC6) || (flags == FLAG_ELF_LIBC6)
            }
        }
        EM_IA_64 => match ei_class {
            ELFCLASS64 => flags == FLAG_ELF_LIBC6 | FLAG_IA64_LIB64,
            _ => false,
        },
        EM_MIPS => match ei_class {
            ELFCLASS32 => {
                if e_flags & (EF_MIPS_NAN2008 | EF_MIPS_ABI2) == EF_MIPS_NAN2008 | EF_MIPS_ABI2 {
                    flags == FLAG_MIPS64_LIBN32_NAN2008 | FLAG_ELF_LIBC6
                } else if e_flags & EF_MIPS_NAN2008 == EF_MIPS_NAN2008 {
                    flags == FLAG_MIPS_LIB32_NAN2008 | FLAG_ELF_LIBC6
                } else if e_flags & EF_MIPS_ABI2 == EF_MIPS_ABI2 {
                    flags == FLAG_MIPS64_LIBN32 | FLAG_ELF_LIBC6
                } else {
                    flags == FLAG_ELF_LIBC6
                }
            }
            ELFCLASS64 => {
                if e_flags & EF_MIPS_NAN2008 == EF_MIPS_NAN2008 {
                    flags == FLAG_MIPS64_LIBN64_NAN2008 | FLAG_ELF_LIBC6
                } else {
                    flags == FLAG_MIPS64_LIBN64 | FLAG_ELF_LIBC6
                }
            }
            _ => false,
        },
        EM_LOONGARCH => match e_flags & FileFlags(EF_LARCH_ABI_MODIFIER_MASK) {
            EF_LARCH_ABI_DOUBLE_FLOAT => flags == FLAG_ELF_LIBC6 | FLAG_LARCH_FLOAT_ABI_DOUBLE,
            EF_LARCH_ABI_SOFT_FLOAT => flags == FLAG_ELF_LIBC6 | FLAG_LARCH_FLOAT_ABI_SOFT,
            _ => flags == FLAG_ELF_LIBC6,
        },
        EM_PPC64 => flags == FLAG_ELF_LIBC6 | FLAG_POWERPC_LIB64,
        EM_RISCV => match e_flags & FileFlags(EF_RISCV_FLOAT_ABI) {
            EF_RISCV_FLOAT_ABI_DOUBLE => flags == FLAG_ELF_LIBC6 | FLAG_RISCV_FLOAT_ABI_DOUBLE,
            EF_RISCV_FLOAT_ABI_SOFT => flags == FLAG_ELF_LIBC6 | FLAG_RISCV_FLOAT_ABI_SOFT,
            _ => flags == FLAG_ELF_LIBC6,
        },
        EM_S390 => match ei_class {
            ELFCLASS32 => flags == FLAG_ELF_LIBC6,
            ELFCLASS64 => flags == FLAG_ELF_LIBC6 | FLAG_S390_LIB64,
            _ => false,
        },
        // The 64-bit objects use EM_SPARCV9, while the 32-bit ones might use
        // either EM_SPARC or EM_SPARC32PLUS (v8+).
        EM_SPARC | EM_SPARC32PLUS | EM_SPARCV9 => match ei_class {
            ELFCLASS32 => flags == FLAG_ELF_LIBC6,
            ELFCLASS64 => flags == FLAG_ELF_LIBC6 | FLAG_SPARC_LIB64,
            _ => false,
        },
        EM_X86_64 => match ei_class {
            ELFCLASS32 => flags == FLAG_ELF_LIBC6 | FLAG_X8664_LIBX32,
            ELFCLASS64 => flags == FLAG_ELF_LIBC6 | FLAG_X8664_LIB64,
            _ => false,
        },
        _ => flags == FLAG_ELF_LIBC6,
    }
}

// To mimic glibc internal definitions
#[allow(non_upper_case_globals, dead_code)]
const cache_file_new_flags_endian_big: u8 = 3u8;
#[allow(non_upper_case_globals, dead_code)]
const cache_file_new_flags_endian_little: u8 = 2u8;
#[cfg(target_endian = "big")]
#[allow(non_upper_case_globals)]
const cache_file_new_flags_endian_current: u8 = cache_file_new_flags_endian_big;
#[cfg(target_endian = "little")]
#[allow(non_upper_case_globals)]
const cache_file_new_flags_endian_current: u8 = cache_file_new_flags_endian_little;

fn check_cache_new_endian(flags: u8) -> bool {
    // A zero value for cache->flags means that no endianness.
    flags == 0 || (flags & cache_file_new_flags_endian_big) == cache_file_new_flags_endian_current
}

// Read a T at OFFSET of the cache DATA, None if it does not fit in the file.
fn read_at<T: Pod + Default>(data: &[u8], offset: usize) -> Option<T> {
    pathutils::read_struct(&mut data.get(offset..)?).ok()
}

// The NUL terminated string at OFFSET of the string table starting at TABLE,
// which must end within the file.
fn read_string(data: &[u8], table: usize, offset: u32) -> Result<String> {
    let value = table
        .checked_add(offset as usize)
        .and_then(|start| data.get(start..))
        .and_then(|s| s.split(|&c| c == 0).next().filter(|v| v.len() < s.len()))
        .ok_or(Error::other("Invalid cache string"))?;
    str::from_utf8(value)
        .map(str::to_string)
        .map_err(|_| Error::other("Invalid UTF8 value"))
}

fn align_cache(value: usize) -> usize {
    (value + (align_of::<cache_file_new>() - 1)) & !(align_of::<cache_file_new>() - 1)
}

// The directory of the library path for each name the loader resolves through
// the cache.
pub type LdCache = HashMap<String, String>;

// A cache entry.
#[derive(Debug)]
struct CacheEntry {
    flags: i32,
    name: String,
    path: String,
    // The file_entry_new hwcap field, zero on the old format.
    hwcap: u64,
}

// The cache file contents: the entries in the file order (sorted by name, the
// glibc-hwcaps ones first) and the glibc-hwcaps subdirectory names the
// extension entries index.
#[derive(Debug, Default)]
struct CacheFile {
    entries: Vec<CacheEntry>,
    hwcaps: Vec<String>,
}

fn parse_ld_so_cache_old(data: &[u8]) -> Result<CacheFile> {
    let hdr: cache_file = read_at(data, 0).ok_or(Error::other("Invalid cache file"))?;

    // Check for corruption, avoiding overflow (glibc _dl_load_cache_lookup).
    let nlibs = hdr.nlibs as usize;
    if (data.len() - CACHE_FILE_LEN) / FILE_ENTRY_LEN < nlibs {
        return Err(Error::other("Invalid cache file"));
    }

    // The string table follows the entries, and the new format header (if
    // any) is at its start after the alignment.
    let strings = CACHE_FILE_LEN + nlibs * FILE_ENTRY_LEN;
    let offset = align_cache(strings);
    if data.len() > (offset + CACHE_FILE_NEW_LEN) {
        return parse_ld_so_cache_new(data, offset);
    }

    if hdr.magic != CACHEMAGIC.as_bytes() {
        return Err(Error::other("Invalid magic"));
    }

    let mut entries = Vec::new();
    for i in 0..nlibs {
        let entry: file_entry = read_at(data, CACHE_FILE_LEN + i * FILE_ENTRY_LEN)
            .ok_or(Error::other("Invalid cache entry"))?;
        entries.push(CacheEntry {
            flags: entry.flags,
            name: read_string(data, strings, entry.key)?,
            path: read_string(data, strings, entry.value)?,
            hwcap: 0,
        });
    }
    Ok(CacheFile {
        entries,
        hwcaps: Vec::new(),
    })
}

fn parse_ld_so_cache_new(data: &[u8], initial: usize) -> Result<CacheFile> {
    let hdr: cache_file_new =
        read_at(data, initial).ok_or(Error::other("Invalid new cache header"))?;

    if hdr.magic != CACHEMAGIC_NEW.as_bytes() {
        return Err(Error::other("Invalid new cache magic"));
    }
    if hdr.version != CACHE_VERSION.as_bytes() {
        return Err(Error::other("Invalid new cache version"));
    }
    if !check_cache_new_endian(hdr.flags) {
        return Err(Error::other("Invalid new cache endianness"));
    }

    // Check for corruption, avoiding overflow (glibc _dl_load_cache_lookup).
    let nlibs = hdr.nlibs as usize;
    let first = initial + CACHE_FILE_NEW_LEN;
    if (data.len() - first) / FILE_ENTRY_NEW_LEN < nlibs {
        return Err(Error::other("Invalid new cache file"));
    }

    let mut entries = Vec::new();
    for i in 0..nlibs {
        let entry: file_entry_new = read_at(data, first + i * FILE_ENTRY_NEW_LEN)
            .ok_or(Error::other("Invalid new cache entry"))?;
        // The strings are relative to the new format header.
        entries.push(CacheEntry {
            flags: entry.flags,
            name: read_string(data, initial, entry.key)?,
            path: read_string(data, initial, entry.value)?,
            hwcap: entry.hwcap,
        });
    }

    Ok(CacheFile {
        entries,
        hwcaps: parse_ld_so_cache_glibc_hwcap(data, initial, hdr.extension_offset)?,
    })
}

const DL_CACHE_HWCAP_ISA_LEVEL_COUNT: u64 = 10;
const DL_CACHE_HWCAP_EXTENSION: u64 = 1u64 << 62;
const DL_CACHE_HWCAP_ISA_LEVEL_MASK: u64 = (1 << DL_CACHE_HWCAP_ISA_LEVEL_COUNT) - 1;

// Whether the hwcap field names a glibc-hwcaps subdirectory, whose index on
// the extension section is on the lower 32 bits (glibc dl_cache_hwcap_extension).
fn check_cache_hwcap_extension(hwcap: u64) -> bool {
    // The hwcap extension is enabled iff the DL_CACHE_HWCAP_EXTENSION bit is set, ignoring the
    // lower 32 bits as well as the ISA level bits in the upper 32 bits.
    (hwcap >> 32) & !DL_CACHE_HWCAP_ISA_LEVEL_MASK == (DL_CACHE_HWCAP_EXTENSION >> 32)
}

// Return the possible glibc-hwcap subfolders used in optimized library selection.  The
// array is indexed by the 32-bit lower bit from file_entry_new hwcap field.  The whole
// section directory is read first, and each section should be within the file (glibc
// cache_extension_load).
fn parse_ld_so_cache_glibc_hwcap(
    data: &[u8],
    initial: usize,
    extension_offset: u32,
) -> Result<Vec<String>> {
    if extension_offset == 0 {
        return Ok(Vec::<String>::new());
    }
    let invalid = || Error::other("Invalid cache extension");

    let offset = initial
        .checked_add(extension_offset as usize)
        .ok_or_else(invalid)?;
    let ext: cache_extension = read_at(data, offset).ok_or_else(invalid)?;
    if ext.magic != cache_extension_magic {
        return Err(Error::other("Invalid cache_extension magic"));
    }

    // Stop at the first section out of the file, so a bogus count does not
    // allocate more than the file size.
    let directory = offset + CACHE_EXTENSION_LEN;
    let sections = (0..ext.count as usize)
        .map(|i| {
            i.checked_mul(CACHE_EXTENSION_SECTION_LEN)
                .and_then(|len| len.checked_add(directory))
                .and_then(|offset| read_at::<cache_extension_section>(data, offset))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(invalid)?;

    // Return an empty set if the cache does not have any glibc-hwcap extension.
    let mut r = Vec::<String>::new();
    for ext_sec in sections {
        let section = initial
            .checked_add(ext_sec.offset as usize)
            .and_then(|start| Some(start..start.checked_add(ext_sec.size as usize)?))
            .and_then(|range| data.get(range))
            .ok_or_else(invalid)?;

        if ext_sec.tag == CACHE_EXTENSION_TAG_GLIBC_HWCAPS {
            for idx in section.as_chunks().0 {
                r.push(read_string(data, initial, u32::from_ne_bytes(*idx))?);
            }
        }
    }
    Ok(r)
}

fn parse_cache(data: &[u8]) -> Result<CacheFile> {
    if data.starts_with(CACHEMAGIC.as_bytes()) {
        parse_ld_so_cache_old(data)
    } else {
        parse_ld_so_cache_new(data, 0)
    }
}

// The priority of each glibc-hwcaps subdirectory of the cache for a loader
// searching SUPPORTED (best first): its position on the list starting at one
// (lower is better), or zero for one it does not search.  Both lists are
// merged sorted by name, as glibc glibc_hwcaps_priorities_init does (the
// cache lists them sorted).
fn hwcaps_priorities(hwcaps: &[String], supported: &[&str]) -> Vec<u32> {
    let mut active: Vec<(&str, u32)> = supported.iter().copied().zip(1..).collect();
    active.sort_by(|a, b| a.0.cmp(b.0));
    let mut active = active.into_iter().peekable();

    hwcaps
        .iter()
        .map(|name| loop {
            let Some((subdir, priority)) = active.peek() else {
                break 0;
            };
            match name.as_str().cmp(subdir) {
                std::cmp::Ordering::Equal => {
                    let priority = *priority;
                    active.next();
                    break priority;
                }
                std::cmp::Ordering::Less => break 0,
                std::cmp::Ordering::Greater => {
                    active.next();
                }
            }
        })
        .collect()
}

// The search state of a name (glibc search_cache).
#[derive(Default)]
struct Search<'a> {
    best: Option<&'a str>,
    // The priority of the glibc-hwcaps entry selected, if any.
    priority: u32,
    done: bool,
}

// Select the entries the loader takes for the object ABI, with SUPPORTED the
// glibc-hwcaps subdirectories it searches (best first), following glibc
// search_cache.  The glibc-hwcaps entries of a name come first and the one
// with the best priority wins, skipping the ones for a subdirectory the loader
// does not search (for instance one the CPU does not support).  Otherwise the
// first regular entry is taken.
fn select_entries(
    file: &CacheFile,
    ei_class: FileClass,
    e_machine: Machine,
    e_flags: FileFlags,
    supported: &[&str],
) -> LdCache {
    let priorities = hwcaps_priorities(&file.hwcaps, supported);

    let mut searches = HashMap::<&str, Search>::new();
    for entry in &file.entries {
        let search = searches.entry(&entry.name).or_default();
        // Skip not supported entries for the binary architecture, for instance
        // x86_64/i686 with multilib support.
        if search.done || !check_file_entry_flags(entry.flags, ei_class, e_machine, e_flags) {
            continue;
        }

        let named_hwcap = check_cache_hwcap_extension(entry.hwcap);
        // The glibc-hwcaps entries are exhausted, so the best one found so
        // far wins.
        if !named_hwcap && search.best.is_some() {
            search.done = true;
            continue;
        }
        if named_hwcap {
            let priority = priorities
                .get(entry.hwcap as u32 as usize)
                .copied()
                .unwrap_or(0);
            // Either not usable at all, or not a better match than the one
            // already found.
            if priority == 0 || (search.best.is_some() && priority >= search.priority) {
                continue;
            }
            search.priority = priority;
        }

        search.best = Some(&entry.path);
        search.done = !named_hwcap;
    }

    searches
        .into_iter()
        .filter_map(|(name, search)| Some((name.to_string(), pathutils::get_path(&search.best?)?)))
        .collect()
}

pub fn parse_ld_so_cache<P: AsRef<Path>>(
    filename: &P,
    ei_class: FileClass,
    e_machine: Machine,
    e_flags: FileFlags,
) -> Result<LdCache> {
    // The file is small, and the loader maps it whole as well.
    let file = parse_cache(&fs::read(filename)?)?;
    // And obtain the current machine supported glibc-hwcap subfolder.
    let supported = hwcap::hwcap_supported()?;
    Ok(select_entries(
        &file, ei_class, e_machine, e_flags, &supported,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86_64: i32 = FLAG_ELF_LIBC6 | FLAG_X8664_LIB64;

    // The hwcap field of an entry on the INDEX glibc-hwcaps subdirectory.
    fn named(index: u32) -> u64 {
        DL_CACHE_HWCAP_EXTENSION | index as u64
    }

    // A new format cache holding the given (flags, name, path, hwcap) entries
    // in that order, with an extension listing the HWCAPS subdirectories (if
    // any).
    fn build_cache(entries: &[(i32, &str, &str, u64)], hwcaps: &[&str]) -> Vec<u8> {
        let mut strings = Vec::<u8>::new();
        let base = CACHE_FILE_NEW_LEN + entries.len() * FILE_ENTRY_NEW_LEN;
        let mut add = |s: &str| {
            let offset = base + strings.len();
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            offset as u32
        };
        let offsets: Vec<(u32, u32)> = entries
            .iter()
            .map(|(_, name, path, _)| (add(name), add(path)))
            .collect();
        let hwcaps: Vec<u32> = hwcaps.iter().map(|s| add(s)).collect();

        // No endianness.
        let mut header = cache_file_new {
            magic: CACHEMAGIC_NEW.as_bytes().try_into().unwrap(),
            version: CACHE_VERSION.as_bytes().try_into().unwrap(),
            nlibs: entries.len() as u32,
            len_strings: strings.len() as u32,
            ..Default::default()
        };
        if !hwcaps.is_empty() {
            header.extension_offset = (base + strings.len()).next_multiple_of(4) as u32;
        }
        let mut cache = object::pod::bytes_of(&header).to_vec();
        for ((flags, _, _, hwcap), (key, value)) in entries.iter().zip(offsets) {
            let entry = file_entry_new {
                flags: *flags,
                key,
                value,
                hwcap: *hwcap,
                ..Default::default()
            };
            cache.extend_from_slice(object::pod::bytes_of(&entry));
        }
        cache.extend_from_slice(&strings);

        if !hwcaps.is_empty() {
            cache.resize(header.extension_offset as usize, 0);
            let ext = cache_extension {
                magic: cache_extension_magic,
                count: 1,
            };
            let section = cache_extension_section {
                tag: CACHE_EXTENSION_TAG_GLIBC_HWCAPS,
                flags: 0,
                offset: header.extension_offset
                    + (CACHE_EXTENSION_LEN + CACHE_EXTENSION_SECTION_LEN) as u32,
                size: (hwcaps.len() * size_of::<u32>()) as u32,
            };
            cache.extend_from_slice(object::pod::bytes_of(&ext));
            cache.extend_from_slice(object::pod::bytes_of(&section));
            for offset in hwcaps {
                cache.extend_from_slice(&offset.to_ne_bytes());
            }
        }
        cache
    }

    fn select(cache: &[u8], supported: &[&str]) -> LdCache {
        let file = parse_cache(cache).unwrap();
        select_entries(&file, ELFCLASS64, EM_X86_64, FileFlags(0), supported)
    }

    #[test]
    fn first_of_the_duplicate_entries_wins() {
        let cache = select(
            &build_cache(
                &[
                    (
                        FLAG_ELF_LIBC6,
                        "libc.so.6",
                        "/usr/lib/i386-linux-gnu/libc.so.6",
                        0,
                    ),
                    (
                        X86_64,
                        "libc.so.6",
                        "/usr/lib/x86_64-linux-gnu/libc.so.6",
                        0,
                    ),
                    (X86_64, "libc.so.6", "/usr/lib64/libc.so.6", 0),
                    (
                        X86_64,
                        "libm.so.6",
                        "/usr/lib/x86_64-linux-gnu/libm.so.6",
                        0,
                    ),
                ],
                &[],
            ),
            &[],
        );
        assert_eq!(cache.len(), 2);
        assert_eq!(cache["libc.so.6"], "/usr/lib/x86_64-linux-gnu");
        assert_eq!(cache["libm.so.6"], "/usr/lib/x86_64-linux-gnu");
    }

    #[test]
    fn entry_count_beyond_the_file() {
        // The header claims more entries than the file holds, which must not
        // be trusted for any allocation.
        let mut cache = build_cache(&[(X86_64, "libc.so.6", "/lib/libc.so.6", 0)], &[]);
        cache[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(parse_cache(&cache).is_err());

        let mut old = object::pod::bytes_of(&cache_file {
            magic: CACHEMAGIC.as_bytes().try_into().unwrap(),
            nlibs: u32::MAX,
            ..Default::default()
        })
        .to_vec();
        old.resize(76, 0);
        assert!(parse_cache(&old).is_err());
    }

    #[test]
    fn glibc_hwcaps_index_out_of_the_extension() {
        // The loader takes an index without a subdirectory as priority zero,
        // so the entry is not usable.
        let entries = [
            (X86_64, "libz.so.1", "/usr/lib/v3/libz.so.1", named(7)),
            (X86_64, "libz.so.1", "/usr/lib/libz.so.1", 0),
        ];
        let supported = ["x86-64-v3", "x86-64-v2"];
        for hwcaps in [&[][..], &["x86-64-v3"]] {
            let cache = select(&build_cache(&entries, hwcaps), &supported);
            assert_eq!(cache["libz.so.1"], "/usr/lib");
        }
    }

    #[test]
    fn unsupported_glibc_hwcaps_entry_sorting_first() {
        // Only a x86-64-v4 variant besides the regular one, on a x86-64-v3
        // machine (or one without glibc-hwcaps subdirectories).
        let cache = build_cache(
            &[
                (
                    X86_64,
                    "libzstd.so.1",
                    "/opt/glibc-hwcaps/x86-64-v4/libzstd.so.1",
                    named(0),
                ),
                (X86_64, "libzstd.so.1", "/usr/lib/libzstd.so.1", 0),
            ],
            &["x86-64-v4"],
        );
        for supported in [&["x86-64-v3", "x86-64-v2"][..], &[]] {
            assert_eq!(select(&cache, supported)["libzstd.so.1"], "/usr/lib");
        }
        assert_eq!(
            select(&cache, &["x86-64-v4", "x86-64-v3", "x86-64-v2"])["libzstd.so.1"],
            "/opt/glibc-hwcaps/x86-64-v4"
        );
    }

    #[test]
    fn best_glibc_hwcaps_entry() {
        // The glibc-hwcaps entries are sorted by subdirectory name, and the
        // best-fit one the machine supports wins.
        let cache = build_cache(
            &[
                (
                    X86_64,
                    "liblzma.so.5",
                    "/opt/x86-64-v2/liblzma.so.5",
                    named(0),
                ),
                (
                    X86_64,
                    "liblzma.so.5",
                    "/opt/x86-64-v3/liblzma.so.5",
                    named(1),
                ),
                (
                    X86_64,
                    "liblzma.so.5",
                    "/opt/x86-64-v4/liblzma.so.5",
                    named(2),
                ),
                (X86_64, "liblzma.so.5", "/opt/liblzma.so.5", 0),
                (X86_64, "liblzma.so.5", "/usr/lib/liblzma.so.5", 0),
            ],
            &["x86-64-v2", "x86-64-v3", "x86-64-v4"],
        );
        for (supported, dir) in [
            (
                &["x86-64-v4", "x86-64-v3", "x86-64-v2"][..],
                "/opt/x86-64-v4",
            ),
            (&["x86-64-v3", "x86-64-v2"], "/opt/x86-64-v3"),
            (&["x86-64-v2"], "/opt/x86-64-v2"),
            (&[], "/opt"),
        ] {
            assert_eq!(select(&cache, supported)["liblzma.so.5"], dir);
        }
    }
}
