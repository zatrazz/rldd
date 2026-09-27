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

pub type LdCache = HashMap<String, String>;

fn parse_ld_so_cache_old(
    data: &[u8],
    ei_class: FileClass,
    e_machine: Machine,
    e_flags: FileFlags,
) -> Result<LdCache> {
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
        return parse_ld_so_cache_new(data, offset, ei_class, e_machine, e_flags);
    }

    if hdr.magic != CACHEMAGIC.as_bytes() {
        return Err(Error::other("Invalid magic"));
    }

    let mut ldsocache = LdCache::new();
    for i in 0..nlibs {
        let entry: file_entry = read_at(data, CACHE_FILE_LEN + i * FILE_ENTRY_LEN)
            .ok_or(Error::other("Invalid cache entry"))?;
        if !check_file_entry_flags(entry.flags, ei_class, e_machine, e_flags) {
            continue;
        }
        let key = read_string(data, strings, entry.key)?;
        let value = read_string(data, strings, entry.value)?;

        ldsocache.insert(key, value);
    }
    Ok(ldsocache)
}

fn parse_ld_so_cache_new(
    data: &[u8],
    initial: usize,
    ei_class: FileClass,
    e_machine: Machine,
    e_flags: FileFlags,
) -> Result<LdCache> {
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
    let entries = initial + CACHE_FILE_NEW_LEN;
    if (data.len() - entries) / FILE_ENTRY_NEW_LEN < nlibs {
        return Err(Error::other("Invalid new cache file"));
    }

    // Return vector of defined glibc-hwcap subfolder defined in the extension headers.  For
    // instance on x86_64 it mught return [x86-64-v2, x86-64-v3].
    let hwcap_idxs = parse_ld_so_cache_glibc_hwcap(data, initial, hdr.extension_offset)?;

    // And obtain the current machine supported glibc-hwcap subfolder.
    let hwcap_supported = hwcap::hwcap_supported()?;

    let mut ldsocache = LdCache::new();
    // Keep track of the last glibc-hwcap value for the entry to allow check if the new entry is
    // new best-fit value.  Using an extra map avoid the need to add an extra field on the
    // returned ldsocache map.
    let mut hwcapseen = HashMap::<String, usize>::new();

    for i in 0..nlibs {
        let entry: file_entry_new = read_at(data, entries + i * FILE_ENTRY_NEW_LEN)
            .ok_or(Error::other("Invalid new cache entry"))?;
        // Skip not supported entries for the binary architecture, for instance x86_64/i686
        // with multilib support.
        if !check_file_entry_flags(entry.flags, ei_class, e_machine, e_flags) {
            continue;
        }
        let hwcapidx = check_cache_hwcap_extension(entry.hwcap);

        // The strings are relative to the new format header.
        let key = read_string(data, initial, entry.key)?;
        let value = read_string(data, initial, entry.value)?;

        // First check if there is an already found glibc-hwcap option for the entry.  In this case,
        // also check if the newer entry has a glibc-hwcap index associated and if it is also the case
        // check if the new glibc-hwcap is a better fit than the existent one.  This is done by
        // comparing the index value, since the supported hwcasp are sorted in priority order (with
        // the first entry being the better fit).
        if let Some(seen_idx) = hwcapseen.get(&key) {
            // It only makes sense to possible update a new entry if there is also a glibc-hwcap
            // entry associated.
            if let Some(new_idx) = check_hwcap_index(&hwcapidx, &hwcap_idxs, &hwcap_supported) {
                if new_idx < *seen_idx {
                    // If the entry is a newer best fit, update both the cache and the seen map.
                    hwcapseen.insert(key.to_string(), new_idx);
                    ldsocache.insert(
                        key,
                        pathutils::get_path(&value)
                            .ok_or(Error::other("Invalid ld.so.cache entry"))?,
                    );
                }
            }
        } else {
            let idx = check_hwcap_index(&hwcapidx, &hwcap_idxs, &hwcap_supported);
            // The loader takes the first of the entries with the same name and
            // flags.
            if idx.is_none() && ldsocache.contains_key(&key) {
                continue;
            }
            if let Some(idx) = idx {
                hwcapseen.insert(key.to_string(), idx);
            }
            ldsocache.insert(
                key,
                pathutils::get_path(&value).ok_or(Error::other("Invalid ld.so.cache entry"))?,
            );
        }
    }

    Ok(ldsocache)
}

// Return a new best-fit index for HWCAP_SUPPORTED if the HWCAPIDX contains a valid value.
fn check_hwcap_index(
    hwcapidx: &Option<u32>,
    hwcap_idxs: &[String],
    hwcap_supported: &[&'static str],
) -> Option<usize> {
    let hwcap_value = hwcap_idxs.get((*hwcapidx)? as usize)?;
    hwcap_supported.iter().position(|&r| r == hwcap_value)
}

const DL_CACHE_HWCAP_ISA_LEVEL_COUNT: u64 = 10;
const DL_CACHE_HWCAP_EXTENSION: u64 = 1u64 << 62;
const DL_CACHE_HWCAP_ISA_LEVEL_MASK: u64 = (1 << DL_CACHE_HWCAP_ISA_LEVEL_COUNT) - 1;

// The hwcap is an index on a string list, so return remove the unused high bits.
fn check_cache_hwcap_extension(hwcap: u64) -> Option<u32> {
    // The hwcap extension is enabled iff the DL_CACHE_HWCAP_EXTENSION bit is set, ignoring the
    // lower 32 bits as well as the ISA level bits in the upper 32 bits.
    let active: bool =
        (hwcap >> 32) & !DL_CACHE_HWCAP_ISA_LEVEL_MASK == (DL_CACHE_HWCAP_EXTENSION >> 32);
    match active {
        true => Some(hwcap as u32),
        false => None,
    }
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

pub fn parse_ld_so_cache<P: AsRef<Path>>(
    filename: &P,
    ei_class: FileClass,
    e_machine: Machine,
    e_flags: FileFlags,
) -> Result<LdCache> {
    // The file is small, and the loader maps it whole as well.
    let data = fs::read(filename)?;

    if data.starts_with(CACHEMAGIC.as_bytes()) {
        parse_ld_so_cache_old(&data, ei_class, e_machine, e_flags)
    } else {
        parse_ld_so_cache_new(&data, 0, ei_class, e_machine, e_flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A new format cache holding the given (flags, name, path) entries in
    // that order, without any extension.
    fn build_cache(entries: &[(i32, &str, &str)]) -> Vec<u8> {
        let mut strings = Vec::<u8>::new();
        let mut offsets = Vec::new();
        let base = CACHE_FILE_NEW_LEN + entries.len() * FILE_ENTRY_NEW_LEN;
        for (_, name, path) in entries {
            let key = base + strings.len();
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            let value = base + strings.len();
            strings.extend_from_slice(path.as_bytes());
            strings.push(0);
            offsets.push((key as u32, value as u32));
        }

        // No endianness, no extension.
        let header = cache_file_new {
            magic: CACHEMAGIC_NEW.as_bytes().try_into().unwrap(),
            version: CACHE_VERSION.as_bytes().try_into().unwrap(),
            nlibs: entries.len() as u32,
            len_strings: strings.len() as u32,
            ..Default::default()
        };
        let mut cache = object::pod::bytes_of(&header).to_vec();
        for ((flags, _, _), (key, value)) in entries.iter().zip(offsets) {
            let entry = file_entry_new {
                flags: *flags,
                key,
                value,
                ..Default::default()
            };
            cache.extend_from_slice(object::pod::bytes_of(&entry));
        }
        cache.extend_from_slice(&strings);
        cache
    }

    fn parse(cache: Vec<u8>) -> LdCache {
        parse_ld_so_cache_new(&cache, 0, ELFCLASS64, EM_X86_64, FileFlags(0)).unwrap()
    }

    // Set the hwcap field of the INDEX entry of a new format CACHE.
    fn set_hwcap(cache: &mut [u8], index: usize, hwcap: u64) {
        let offset = CACHE_FILE_NEW_LEN + index * FILE_ENTRY_NEW_LEN + 16;
        cache[offset..offset + 8].copy_from_slice(&hwcap.to_ne_bytes());
    }

    #[test]
    fn entry_count_beyond_the_file() {
        // The header claims more entries than the file holds, which must not
        // be trusted for any allocation.
        let mut cache = build_cache(&[(FLAG_ELF_LIBC6, "libc.so.6", "/lib/libc.so.6")]);
        cache[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(parse_ld_so_cache_new(&cache, 0, ELFCLASS64, EM_X86_64, FileFlags(0)).is_err());

        let mut old = object::pod::bytes_of(&cache_file {
            magic: CACHEMAGIC.as_bytes().try_into().unwrap(),
            nlibs: u32::MAX,
            ..Default::default()
        })
        .to_vec();
        old.resize(76, 0);
        assert!(parse_ld_so_cache_old(&old, ELFCLASS64, EM_X86_64, FileFlags(0)).is_err());
    }

    #[test]
    fn hwcap_index_without_extension() {
        let x86_64 = FLAG_ELF_LIBC6 | FLAG_X8664_LIB64;
        let mut cache = build_cache(&[
            (
                x86_64,
                "libz.so.1",
                "/usr/lib/glibc-hwcaps/x86-64-v3/libz.so.1",
            ),
            (x86_64, "libz.so.1", "/usr/lib/libz.so.1"),
        ]);
        set_hwcap(&mut cache, 0, DL_CACHE_HWCAP_EXTENSION | 7);
        parse(cache);
    }

    #[test]
    fn first_of_the_duplicate_entries_wins() {
        let x86_64 = FLAG_ELF_LIBC6 | FLAG_X8664_LIB64;
        let cache = parse(build_cache(&[
            (
                FLAG_ELF_LIBC6,
                "libc.so.6",
                "/usr/lib/i386-linux-gnu/libc.so.6",
            ),
            (x86_64, "libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
            (x86_64, "libc.so.6", "/usr/lib64/libc.so.6"),
            (x86_64, "libm.so.6", "/usr/lib/x86_64-linux-gnu/libm.so.6"),
        ]));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache["libc.so.6"], "/usr/lib/x86_64-linux-gnu");
        assert_eq!(cache["libm.so.6"], "/usr/lib/x86_64-linux-gnu");
    }
}
