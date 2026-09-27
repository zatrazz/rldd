use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::io::{Error, Result};
use std::mem::{align_of, size_of};
use std::path::Path;
use std::{fs, str};

use crate::pathutils;
use object::elf::*;
use object::Pod;

pub mod hwcap;

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

// The ld.so.cache entry flags, from glibc ldconfig.h.
const FLAG_ELF: i32 = 0x0001;
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

// The entry flags the loader built for an object ABI takes (the dl-cache.h
// _dl_cache_check_flags of each ABI): its _DL_CACHE_DEFAULT_ID, whose entry
// ends the search, and another value it takes as well, if any.
#[derive(Clone, Copy, Debug)]
struct CacheFlags {
    default_id: i32,
    other: Option<i32>,
}

impl CacheFlags {
    // The flags for the object ABI, None for an ABI without a glibc loader.
    fn new(ei_class: FileClass, e_machine: Machine, e_flags: FileFlags) -> Option<Self> {
        let only = |default_id| CacheFlags {
            default_id,
            other: None,
        };
        // The generic check also takes FLAG_ELF, which ldconfig before glibc
        // 2.37 wrote for the libraries without a libc dependency.
        let generic = CacheFlags {
            default_id: FLAG_ELF_LIBC6,
            other: Some(FLAG_ELF),
        };
        Some(match e_machine {
            EM_AARCH64 => match ei_class {
                ELFCLASS64 => only(FLAG_ELF_LIBC6 | FLAG_AARCH64_LIB64),
                _ => return None,
            },
            // The unmarked objects are compatible with either float ABI.
            EM_ARM => CacheFlags {
                default_id: FLAG_ELF_LIBC6,
                other: Some(if e_flags.contains(EF_ARM_VFP_FLOAT) {
                    FLAG_ARM_LIBHF | FLAG_ELF_LIBC6
                } else {
                    // Either EF_ARM_SOFT_FLOAT or no float ABI flag at all.
                    FLAG_ARM_LIBSF | FLAG_ELF_LIBC6
                }),
            },
            EM_IA_64 => match ei_class {
                ELFCLASS64 => only(FLAG_ELF_LIBC6 | FLAG_IA64_LIB64),
                _ => return None,
            },
            // The legacy o32 ABI uses the generic check.
            EM_MIPS => match ei_class {
                ELFCLASS32 => {
                    if e_flags & (EF_MIPS_NAN2008 | EF_MIPS_ABI2) == EF_MIPS_NAN2008 | EF_MIPS_ABI2
                    {
                        only(FLAG_MIPS64_LIBN32_NAN2008 | FLAG_ELF_LIBC6)
                    } else if e_flags & EF_MIPS_NAN2008 == EF_MIPS_NAN2008 {
                        only(FLAG_MIPS_LIB32_NAN2008 | FLAG_ELF_LIBC6)
                    } else if e_flags & EF_MIPS_ABI2 == EF_MIPS_ABI2 {
                        only(FLAG_MIPS64_LIBN32 | FLAG_ELF_LIBC6)
                    } else {
                        generic
                    }
                }
                ELFCLASS64 => {
                    if e_flags & EF_MIPS_NAN2008 == EF_MIPS_NAN2008 {
                        only(FLAG_MIPS64_LIBN64_NAN2008 | FLAG_ELF_LIBC6)
                    } else {
                        only(FLAG_MIPS64_LIBN64 | FLAG_ELF_LIBC6)
                    }
                }
                _ => return None,
            },
            EM_LOONGARCH => match e_flags & FileFlags(EF_LARCH_ABI_MODIFIER_MASK) {
                EF_LARCH_ABI_DOUBLE_FLOAT => only(FLAG_ELF_LIBC6 | FLAG_LARCH_FLOAT_ABI_DOUBLE),
                EF_LARCH_ABI_SOFT_FLOAT => only(FLAG_ELF_LIBC6 | FLAG_LARCH_FLOAT_ABI_SOFT),
                _ => only(FLAG_ELF_LIBC6),
            },
            EM_PPC64 => only(FLAG_ELF_LIBC6 | FLAG_POWERPC_LIB64),
            EM_RISCV => match e_flags & FileFlags(EF_RISCV_FLOAT_ABI) {
                EF_RISCV_FLOAT_ABI_DOUBLE => only(FLAG_ELF_LIBC6 | FLAG_RISCV_FLOAT_ABI_DOUBLE),
                EF_RISCV_FLOAT_ABI_SOFT => only(FLAG_ELF_LIBC6 | FLAG_RISCV_FLOAT_ABI_SOFT),
                _ => only(FLAG_ELF_LIBC6),
            },
            EM_S390 => match ei_class {
                ELFCLASS32 => generic,
                ELFCLASS64 => only(FLAG_ELF_LIBC6 | FLAG_S390_LIB64),
                _ => return None,
            },
            // The 64-bit objects use EM_SPARCV9, while the 32-bit ones might use
            // either EM_SPARC or EM_SPARC32PLUS (v8+).
            EM_SPARC | EM_SPARC32PLUS | EM_SPARCV9 => match ei_class {
                ELFCLASS32 => generic,
                ELFCLASS64 => only(FLAG_ELF_LIBC6 | FLAG_SPARC_LIB64),
                _ => return None,
            },
            EM_X86_64 => match ei_class {
                ELFCLASS32 => only(FLAG_ELF_LIBC6 | FLAG_X8664_LIBX32),
                ELFCLASS64 => only(FLAG_ELF_LIBC6 | FLAG_X8664_LIB64),
                _ => return None,
            },
            _ => generic,
        })
    }

    fn check(&self, flags: i32) -> bool {
        flags == self.default_id || Some(flags) == self.other
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
// None if it does not end within the file.
fn read_bytes(data: &[u8], table: usize, offset: u32) -> Option<&[u8]> {
    let s = data.get(table.checked_add(offset as usize)?..)?;
    let end = s.iter().position(|&c| c == 0)?;
    Some(&s[..end])
}

fn align_cache(value: usize) -> usize {
    (value + (align_of::<cache_file_new>() - 1)) & !(align_of::<cache_file_new>() - 1)
}

// A cache entry.
#[derive(Debug)]
struct CacheEntry {
    flags: i32,
    name: String,
    // The library path, None if it is not valid UTF-8 (the loader would try
    // it, but it can not be represented).
    path: Option<String>,
    // The file_entry_new hwcap field, zero on the old format.
    hwcap: u64,
}

impl CacheEntry {
    // The entry with the KEY and VALUE strings of the string table at TABLE.
    // An entry with a string out of the file is not usable (the loader
    // _dl_cache_verify_ptr), nor is one whose name is not valid UTF-8, since
    // no dependency names it.
    fn new(
        data: &[u8],
        table: usize,
        flags: i32,
        key: u32,
        value: u32,
        hwcap: u64,
    ) -> Option<Self> {
        let name = str::from_utf8(read_bytes(data, table, key)?).ok()?;
        let path = read_bytes(data, table, value)?;
        Some(CacheEntry {
            flags,
            name: name.to_string(),
            path: str::from_utf8(path).ok().map(str::to_string),
            hwcap,
        })
    }
}

// The cache file contents: the entries in the file order (sorted by name, the
// glibc-hwcaps ones first) and the glibc-hwcaps subdirectory names the
// extension entries index (None for one out of the file).
#[derive(Debug, Default)]
struct CacheFile {
    entries: Vec<CacheEntry>,
    hwcaps: Vec<Option<Vec<u8>>>,
    // Whether the entries are the new format ones, with the hwcap field.
    new_format: bool,
}

// Whether DATA at OFFSET starts a new format header (glibc
// CACHEMAGIC_VERSION_NEW).
fn is_cache_new(data: &[u8], offset: usize) -> bool {
    data.get(offset..).is_some_and(|data| {
        data.len() >= CACHE_FILE_NEW_LEN
            && data.starts_with(CACHEMAGIC_NEW.as_bytes())
            && data[CACHEMAGIC_NEW.len()..].starts_with(CACHE_VERSION.as_bytes())
    })
}

fn parse_ld_so_cache_old(data: &[u8]) -> Result<CacheFile> {
    let hdr: cache_file = read_at(data, 0).ok_or(Error::other("Invalid cache file"))?;

    // Check for corruption, avoiding overflow (glibc _dl_load_cache_lookup).
    let nlibs = hdr.nlibs as usize;
    if (data.len() - CACHE_FILE_LEN) / FILE_ENTRY_LEN < nlibs {
        return Err(Error::other("Invalid cache file"));
    }

    // The string table follows the entries, and the compat format has the new
    // format header at its start after the alignment (ldconfig makes the
    // entry count even so there is no padding).  Without it, the old format
    // entries are used.
    let strings = CACHE_FILE_LEN + nlibs * FILE_ENTRY_LEN;
    let offset = align_cache(strings);
    if is_cache_new(data, offset) {
        return parse_ld_so_cache_new(data, offset);
    }

    let mut entries = Vec::new();
    for i in 0..nlibs {
        let entry: file_entry = read_at(data, CACHE_FILE_LEN + i * FILE_ENTRY_LEN)
            .ok_or(Error::other("Invalid cache entry"))?;
        entries.extend(CacheEntry::new(
            data,
            strings,
            entry.flags,
            entry.key,
            entry.value,
            0,
        ));
    }
    Ok(CacheFile {
        entries,
        hwcaps: Vec::new(),
        new_format: false,
    })
}

fn parse_ld_so_cache_new(data: &[u8], initial: usize) -> Result<CacheFile> {
    let hdr: cache_file_new =
        read_at(data, initial).ok_or(Error::other("Invalid new cache header"))?;

    // The old format part of a compat cache is not used either with the wrong
    // endianness.
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
        entries.extend(CacheEntry::new(
            data,
            initial,
            entry.flags,
            entry.key,
            entry.value,
            entry.hwcap,
        ));
    }

    Ok(CacheFile {
        entries,
        hwcaps: parse_ld_so_cache_glibc_hwcap(data, hdr.extension_offset),
        new_format: true,
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

// The glibc-hwcaps section of the extension directory at EXTENSION_OFFSET: the
// whole directory must be within the file, and so must every section, and the
// section must be a non empty and aligned array of 32-bit string offsets
// (glibc cache_extension_load and cache_extension_verify).  The offsets are
// relative to the start of the file, which is not the new format header on a
// compat cache.
fn glibc_hwcaps_section(data: &[u8], extension_offset: u32) -> Option<&[u8]> {
    // Either no extension, or a misaligned one.
    if extension_offset == 0 || !extension_offset.is_multiple_of(4) {
        return None;
    }
    let offset = extension_offset as usize;
    let ext: cache_extension = read_at(data, offset)?;
    if ext.magic != cache_extension_magic {
        return None;
    }

    // A bogus section count stops at the end of the file.
    let directory = offset + CACHE_EXTENSION_LEN;
    let mut hwcaps = None;
    for i in 0..ext.count as usize {
        let section: cache_extension_section = i
            .checked_mul(CACHE_EXTENSION_SECTION_LEN)
            .and_then(|len| len.checked_add(directory))
            .and_then(|offset| read_at(data, offset))?;
        let start = section.offset as usize;
        let contents = data.get(start..start.checked_add(section.size as usize)?)?;
        // The last one wins, as for any other tag.
        if section.tag == CACHE_EXTENSION_TAG_GLIBC_HWCAPS {
            hwcaps = Some((start, contents));
        }
    }

    let (start, contents) = hwcaps?;
    (!contents.is_empty() && start.is_multiple_of(4) && contents.len().is_multiple_of(4))
        .then_some(contents)
}

// Return the possible glibc-hwcap subfolders used in optimized library selection.  The
// array is indexed by the 32-bit lower bit from file_entry_new hwcap field.  A malformed
// extension leaves no subdirectory, so no glibc-hwcaps entry is usable while the regular
// ones still are (the loader glibc_hwcaps_priorities_init).
//
// The loader reads the names relative to the start of the file (glibc_hwcaps_compare),
// while ldconfig writes them relative to the new format header, as the entry strings.
// So on a compat cache the names do not match any subdirectory and the loader uses no
// glibc-hwcaps entry, which is mimicked by reading them the same way.
fn parse_ld_so_cache_glibc_hwcap(data: &[u8], extension_offset: u32) -> Vec<Option<Vec<u8>>> {
    let Some(section) = glibc_hwcaps_section(data, extension_offset) else {
        return Vec::new();
    };
    section
        .as_chunks()
        .0
        .iter()
        .map(|idx| read_bytes(data, 0, u32::from_ne_bytes(*idx)).map(<[u8]>::to_vec))
        .collect()
}

// Parse the cache formats the loader handles (glibc _dl_load_cache_lookup): the
// new format alone, the old format alone, and the compat one (the old format
// with the new one at its string table).
fn parse_cache(data: &[u8]) -> Result<CacheFile> {
    if data.len() > CACHE_FILE_NEW_LEN && is_cache_new(data, 0) {
        parse_ld_so_cache_new(data, 0)
    } else if data.len() > CACHE_FILE_LEN && data.starts_with(CACHEMAGIC.as_bytes()) {
        parse_ld_so_cache_old(data)
    } else {
        Err(Error::other("Invalid cache file"))
    }
}

// The priority of each glibc-hwcaps subdirectory of the cache for a loader
// searching SUPPORTED (best first): its position on the list starting at one
// (lower is better), or zero for one it does not search.  Both lists are
// merged sorted by name, as glibc glibc_hwcaps_priorities_init does (the
// cache lists them sorted).
fn hwcaps_priorities(hwcaps: &[Option<Vec<u8>>], supported: &[&str]) -> Vec<u32> {
    let mut active: Vec<(&str, u32)> = supported.iter().copied().zip(1..).collect();
    active.sort_by(|a, b| a.0.cmp(b.0));
    let mut active = active.into_iter().peekable();

    hwcaps
        .iter()
        .map(|name| loop {
            // A name out of the file has no priority.
            let (Some(name), Some((subdir, priority))) = (name, active.peek()) else {
                break 0;
            };
            match name.as_slice().cmp(subdir.as_bytes()) {
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
    best: Option<&'a CacheEntry>,
    // The priority of the glibc-hwcaps entry selected, if any.
    priority: u32,
    done: bool,
}

// Whether the ISA level a glibc-hwcaps entry HWCAP requires is one of the
// ISA_LEVELS the CPU supports (glibc dl_cache_hwcap_isa_level_compatible on
// x86, while the other loaders take any).
fn check_isa_level(hwcap: u64, isa_levels: Option<u32>) -> bool {
    let Some(isa_levels) = isa_levels else {
        return true;
    };
    // ldconfig writes the index of the highest GNU_PROPERTY_X86_ISA_1_NEEDED
    // bit of the library.
    let level = 1u32
        .checked_shl(((hwcap >> 32) & DL_CACHE_HWCAP_ISA_LEVEL_MASK) as u32)
        .unwrap_or(0);
    level != 0 && isa_levels & level == level
}

// Select the entries the loader takes for the object ABI, with HWCAPS the
// capabilities it uses, following glibc search_cache.  The glibc-hwcaps
// entries of a name come first and the one with the best priority wins,
// skipping the ones for a subdirectory the loader does not search (for
// instance one the CPU does not support) or requiring an ISA level the CPU
// does not support.  Otherwise the first regular entry is taken on the new
// format, skipping the ones with legacy hwcap bits the loader does not take
// (any of them when LEGACY is false, since glibc 2.40), while the old format
// one keeps searching for an entry with the loader default flags (the
// generic FLAG_ELF_LIBC6 over FLAG_ELF, or the ARM unmarked entries over the
// float ABI ones).  The result is the directory of the library path for each
// name.
fn select_entries(
    file: &CacheFile,
    ei_class: FileClass,
    e_machine: Machine,
    e_flags: FileFlags,
    hwcaps: &hwcap::LoaderHwcaps,
    legacy: bool,
) -> HashMap<String, String> {
    let Some(flags) = CacheFlags::new(ei_class, e_machine, e_flags) else {
        return HashMap::new();
    };
    let priorities = hwcaps_priorities(&file.hwcaps, &hwcaps.subdirs);

    let mut searches = HashMap::<&str, Search>::new();
    for entry in &file.entries {
        let search = searches.entry(&entry.name).or_default();
        // Skip not supported entries for the binary architecture, for instance
        // x86_64/i686 with multilib support.
        if search.done || !flags.check(entry.flags) {
            continue;
        }

        let mut named_hwcap = false;
        if file.new_format {
            named_hwcap = check_cache_hwcap_extension(entry.hwcap);
            if named_hwcap && !check_isa_level(entry.hwcap, hwcaps.isa_levels) {
                continue;
            }
            // The glibc-hwcaps entries are exhausted, so the best one found so
            // far wins.
            if !named_hwcap && search.best.is_some() {
                search.done = true;
                continue;
            }
            if !named_hwcap && entry.hwcap != 0 && !(legacy && hwcaps.legacy.check(entry.hwcap)) {
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
        }

        search.best = Some(entry);
        search.done = !named_hwcap && entry.flags == flags.default_id;
    }

    // A path that is not valid UTF-8 resolves nothing, as if the loader failed
    // to open it.
    searches
        .into_iter()
        .filter_map(|(name, search)| {
            let path = search.best?.path.as_ref()?;
            Some((name.to_string(), pathutils::get_path(path)?))
        })
        .collect()
}

// The glibc release of the LOADER, from the version banner ld.so has since
// glibc 2.33 ("ld.so (GNU libc) stable release version 2.39."), None for an
// older or an unreadable one.
fn glibc_release<P: AsRef<Path>>(loader: &P) -> Option<(u32, u32)> {
    glibc_release_in(&pathutils::map_file(loader).ok()?)
}

fn glibc_release_in(data: &[u8]) -> Option<(u32, u32)> {
    const BANNER: &[u8] = b" release version ";
    let start = data.windows(BANNER.len()).position(|w| w == BANNER)? + BANNER.len();
    let version = data[start..]
        .split(|c| !c.is_ascii_digit() && *c != b'.')
        .next()?;
    let mut numbers = str::from_utf8(version).ok()?.split('.').map(str::parse);
    Some((numbers.next()?.ok()?, numbers.next()?.ok()?))
}

// The object ABI the entries are selected for, and whether its loader takes
// the legacy hwcap bits.
type Abi = (FileClass, DataEncoding, Machine, FileFlags, bool);

// The loader cache, read once and shared by all objects, with the entries
// selected for the ABI of the last object given to select.
#[derive(Debug, Default)]
pub struct LdCache {
    file: CacheFile,
    abi: Option<Abi>,
    entries: HashMap<String, String>,
}

impl LdCache {
    fn parse(data: &[u8]) -> Result<Self> {
        Ok(LdCache {
            file: parse_cache(data)?,
            ..Default::default()
        })
    }

    // Select the entries for the object ABI: each object runs with the
    // loader built for its ABI, which takes only the entries of that ABI and
    // has its own glibc-hwcaps subdirectories.  The LOADER path (the object
    // PT_INTERP) tells its glibc release, since the ones before 2.40 take
    // the entries with the legacy hwcap bits of the machine.  An unknown
    // release is taken as an older one, since only ldconfig up to 2.36
    // writes such entries.
    pub fn select(
        &mut self,
        ei_class: FileClass,
        ei_data: DataEncoding,
        e_machine: Machine,
        e_flags: FileFlags,
        loader: Option<&str>,
    ) {
        let legacy = !loader
            .and_then(|loader| glibc_release(&loader))
            .is_some_and(|release| release >= (2, 40));
        let abi = Some((ei_class, ei_data, e_machine, e_flags, legacy));
        if self.abi == abi {
            return;
        }
        // And obtain the capabilities the loader uses on the current machine.
        // A machine whose capabilities can not be read has no glibc-hwcaps
        // subdirectory, which still leaves the regular entries.
        let hwcaps = hwcap::loader_hwcaps(e_machine, ei_class, ei_data);
        self.entries = select_entries(&self.file, ei_class, e_machine, e_flags, &hwcaps, legacy);
        self.abi = abi;
    }

    // The directory the selected entry for NAME is in.
    pub fn get<Q: Hash + Eq + ?Sized>(&self, name: &Q) -> Option<&String>
    where
        String: Borrow<Q>,
    {
        self.entries.get(name)
    }

    // The number of names with a selected entry.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

pub fn parse_ld_so_cache<P: AsRef<Path>>(filename: &P) -> Result<LdCache> {
    // The file is small, and the loader maps it whole as well.
    LdCache::parse(&fs::read(filename)?)
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

    // An old format cache holding the given (flags, name, path) entries in
    // that order.
    fn build_old(entries: &[(i32, &str, &str)]) -> Vec<u8> {
        let header = cache_file {
            magic: CACHEMAGIC.as_bytes().try_into().unwrap(),
            nlibs: entries.len() as u32,
            ..Default::default()
        };
        let mut cache = object::pod::bytes_of(&header).to_vec();
        let mut strings = Vec::<u8>::new();
        let mut add = |s: &str| {
            let offset = strings.len();
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            offset as u32
        };
        for (flags, name, path) in entries {
            let entry = file_entry {
                flags: *flags,
                key: add(name),
                value: add(path),
            };
            cache.extend_from_slice(object::pod::bytes_of(&entry));
        }
        cache.extend_from_slice(&strings);
        cache
    }

    // A compat format cache, as ldconfig -c compat writes it: an old format
    // part with the same entries (the count made even by repeating the last
    // one, so the new format header needs no padding), the new format part at
    // its string table (the string offsets of both relative to it), and the
    // extension offsets relative to the file start.
    fn build_compat(entries: &[(i32, &str, &str, u64)], hwcaps: &[&str]) -> Vec<u8> {
        let mut new = build_cache(entries, hwcaps);
        let nlibs = entries.len().next_multiple_of(2);
        let header = cache_file {
            magic: CACHEMAGIC.as_bytes().try_into().unwrap(),
            nlibs: nlibs as u32,
            ..Default::default()
        };
        let mut cache = object::pod::bytes_of(&header).to_vec();
        for i in 0..nlibs {
            let index = i.min(entries.len() - 1);
            let entry: file_entry_new =
                read_at(&new, CACHE_FILE_NEW_LEN + index * FILE_ENTRY_NEW_LEN).unwrap();
            let entry = file_entry {
                flags: entry.flags,
                key: entry.key,
                value: entry.value,
            };
            cache.extend_from_slice(object::pod::bytes_of(&entry));
        }
        assert_eq!(cache.len(), align_cache(cache.len()));

        if !hwcaps.is_empty() {
            let old = cache.len() as u32;
            let extension = u32::from_ne_bytes(new[EXTENSION_OFFSET..][..4].try_into().unwrap());
            let section = extension as usize + CACHE_EXTENSION_LEN + 8;
            set_u32(&mut new, EXTENSION_OFFSET, extension + old);
            let offset = u32::from_ne_bytes(new[section..][..4].try_into().unwrap());
            set_u32(&mut new, section, offset + old);
        }
        cache.extend_from_slice(&new);
        cache
    }

    // Replace the first FROM bytes of CACHE with TO.
    fn patch(cache: &mut [u8], from: &[u8], to: &[u8]) {
        let at = cache.windows(from.len()).position(|w| w == from).unwrap();
        cache[at..at + to.len()].copy_from_slice(to);
    }

    // Set the u32 at OFFSET of CACHE.
    fn set_u32(cache: &mut [u8], offset: usize, value: u32) {
        cache[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    // The offset of the value field of the INDEX entry of a new format cache,
    // and of the extension_offset header field.
    fn entry_value(index: usize) -> usize {
        CACHE_FILE_NEW_LEN + index * FILE_ENTRY_NEW_LEN + 8
    }
    const EXTENSION_OFFSET: usize = 32;

    // The x86-64 selection for a loader searching the SUPPORTED glibc-hwcaps
    // subdirectories, which does not check the ISA levels.
    fn select(cache: &[u8], supported: &[&'static str]) -> HashMap<String, String> {
        select_hwcaps(
            cache,
            &hwcap::LoaderHwcaps {
                subdirs: supported.to_vec(),
                ..Default::default()
            },
            true,
        )
    }

    fn select_hwcaps(
        cache: &[u8],
        hwcaps: &hwcap::LoaderHwcaps,
        legacy: bool,
    ) -> HashMap<String, String> {
        let file = parse_cache(cache).unwrap();
        select_entries(&file, ELFCLASS64, EM_X86_64, FileFlags(0), hwcaps, legacy)
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

    #[test]
    fn glibc_hwcaps_priorities_merge() {
        // The loader merges both lists sorted by name, so a name out of the
        // file has no priority, and neither has one out of order.
        let name = |s: &str| Some(s.as_bytes().to_vec());
        let hwcaps = [
            name("x86-64-v2"),
            None,
            name("x86-64-v3"),
            name("x86-64-v5"),
            name("x86-64-v4"),
        ];
        let supported = ["x86-64-v4", "x86-64-v3", "x86-64-v2"];
        assert_eq!(hwcaps_priorities(&hwcaps, &supported), [3, 0, 2, 0, 0]);
        assert_eq!(hwcaps_priorities(&hwcaps, &[]), [0; 5]);
    }

    #[test]
    fn glibc_hwcaps_entry_isa_level() {
        // ldconfig records the x86 ISA level a glibc-hwcaps library requires
        // (the index of the highest GNU_PROPERTY_X86_ISA_1_NEEDED bit), which
        // the CPU must support.
        let isa_level = |level: u64| level << 32;
        let cache = build_cache(
            &[
                (
                    X86_64,
                    "liblzma.so.5",
                    "/opt/x86-64-v2/liblzma.so.5",
                    named(0) | isa_level(1),
                ),
                (
                    X86_64,
                    "liblzma.so.5",
                    "/opt/x86-64-v3/liblzma.so.5",
                    named(1) | isa_level(3),
                ),
                (X86_64, "liblzma.so.5", "/usr/lib/liblzma.so.5", 0),
            ],
            &["x86-64-v2", "x86-64-v3"],
        );
        let v3 =
            GNU_PROPERTY_X86_ISA_1_BASELINE | GNU_PROPERTY_X86_ISA_1_V2 | GNU_PROPERTY_X86_ISA_1_V3;
        for (isa_levels, dir) in [
            // The loaders that do not check it.
            (None, "/opt/x86-64-v3"),
            (Some(v3), "/opt/x86-64-v2"),
            (Some(v3 | GNU_PROPERTY_X86_ISA_1_V4), "/opt/x86-64-v3"),
            (Some(GNU_PROPERTY_X86_ISA_1_BASELINE), "/usr/lib"),
        ] {
            let hwcaps = hwcap::LoaderHwcaps {
                subdirs: vec!["x86-64-v3", "x86-64-v2"],
                isa_levels,
                ..Default::default()
            };
            assert_eq!(select_hwcaps(&cache, &hwcaps, true)["liblzma.so.5"], dir);
        }
        // A level out of the 32-bit ISA bits.
        assert!(!check_isa_level(named(0) | isa_level(40), Some(u32::MAX)));
    }

    #[test]
    fn legacy_hwcap_entries() {
        // A regular entry with legacy hwcap bits (ldconfig up to 2.36, for a
        // library of a tls, x86_64 or haswell subdirectory) sorts before the
        // one without them.
        const TLS: u64 = 1 << 63;
        const X86_64_BIT: u64 = 1 << 1;
        const SSE2_BIT: u64 = 1 << 0;
        const HASWELL: u64 = 1 << 50;
        let x86_64 = hwcap::LoaderHwcaps {
            legacy: hwcap::LegacyHwcaps::new(X86_64_BIT, X86_64_BIT | 1 << 2, 0xf << 48, None),
            ..Default::default()
        };
        let haswell = hwcap::LoaderHwcaps {
            legacy: hwcap::LegacyHwcaps::new(
                X86_64_BIT,
                X86_64_BIT | 1 << 2,
                0xf << 48,
                Some(HASWELL),
            ),
            ..Default::default()
        };
        let unknown = hwcap::LoaderHwcaps::default();
        for (hwcap, legacy, taken) in [
            (TLS, &unknown, true),
            (X86_64_BIT, &unknown, false),
            (X86_64_BIT | TLS, &x86_64, true),
            (SSE2_BIT, &x86_64, false),
            (HASWELL, &x86_64, false),
            (HASWELL | X86_64_BIT, &haswell, true),
            (1 << 51, &haswell, false),
        ] {
            let cache = build_cache(
                &[
                    (X86_64, "libfoo.so.1", "/opt/legacy/libfoo.so.1", hwcap),
                    (X86_64, "libfoo.so.1", "/usr/lib/libfoo.so.1", 0),
                ],
                &[],
            );
            let dir = if taken { "/opt/legacy" } else { "/usr/lib" };
            assert_eq!(select_hwcaps(&cache, legacy, true)["libfoo.so.1"], dir);
            // The loaders since 2.40 skip any of them.
            assert_eq!(
                select_hwcaps(&cache, legacy, false)["libfoo.so.1"],
                "/usr/lib"
            );
        }
    }

    #[test]
    fn loader_release() {
        // The banner of a loader since 2.33, and none before.
        let banner =
            b"\x7fELF\0ld.so (Ubuntu GLIBC 2.39-0ubuntu8.9) stable release version 2.39.\n";
        assert_eq!(glibc_release_in(banner), Some((2, 39)));
        let banner = b"\0ld.so (GNU libc) development release version 2.43.9000.\n";
        assert_eq!(glibc_release_in(banner), Some((2, 43)));
        assert_eq!(glibc_release_in(b"\x7fELF\0ld-linux-x86-64.so.2\0"), None);
        assert_eq!(glibc_release(&"/nonexistent/ld.so"), None);
    }

    #[test]
    fn old_format() {
        // More strings than a new format header, which does not make it a
        // compat cache.
        let cache = select(
            &build_old(&[
                (
                    FLAG_ELF_LIBC6,
                    "libc.so.6",
                    "/usr/lib/i386-linux-gnu/libc.so.6",
                ),
                (X86_64, "libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
                (X86_64, "libm.so.6", "/usr/lib/x86_64-linux-gnu/libm.so.6"),
            ]),
            &[],
        );
        assert_eq!(cache.len(), 2);
        assert_eq!(cache["libc.so.6"], "/usr/lib/x86_64-linux-gnu");
        assert_eq!(cache["libm.so.6"], "/usr/lib/x86_64-linux-gnu");
    }

    #[test]
    fn compat_format() {
        let cache = build_compat(
            &[
                (
                    X86_64,
                    "liblzma.so.5",
                    "/opt/x86-64-v3/liblzma.so.5",
                    named(0),
                ),
                (X86_64, "liblzma.so.5", "/opt/liblzma.so.5", 0),
                (X86_64, "libm.so.6", "/usr/lib/libm.so.6", 0),
            ],
            &["x86-64-v3"],
        );
        // The extension is found at its file offset, but the loader reads the
        // subdirectory name from the file start instead of the new format
        // header ldconfig writes it relative to, so it does not match.
        let file = parse_cache(&cache).unwrap();
        assert_eq!(file.hwcaps.len(), 1);
        assert_ne!(file.hwcaps[0].as_deref(), Some(&b"x86-64-v3"[..]));

        let cache = select(&cache, &["x86-64-v3", "x86-64-v2"]);
        assert_eq!(cache["liblzma.so.5"], "/opt");
        assert_eq!(cache["libm.so.6"], "/usr/lib");
    }

    fn select_abi(
        cache: &[u8],
        ei_class: FileClass,
        e_machine: Machine,
        e_flags: FileFlags,
    ) -> HashMap<String, String> {
        let file = parse_cache(cache).unwrap();
        select_entries(
            &file,
            ei_class,
            e_machine,
            e_flags,
            &Default::default(),
            true,
        )
    }

    #[test]
    fn entries_selected_per_abi() {
        // The same cache used for objects of different ABIs, in any order.
        let mut cache = LdCache::parse(&build_cache(
            &[
                (FLAG_ELF_LIBC6, "libc.so.6", "/usr/lib32/libc.so.6", 0),
                (X86_64, "libc.so.6", "/usr/lib64/libc.so.6", 0),
                (
                    FLAG_ELF_LIBC6,
                    "libnoneed.so.1",
                    "/usr/lib32/libnoneed.so.1",
                    0,
                ),
                (X86_64, "libz.so.1", "/usr/lib64/libz.so.1", 0),
            ],
            &[],
        ))
        .unwrap();
        for _ in 0..2 {
            cache.select(ELFCLASS64, ELFDATA2LSB, EM_X86_64, FileFlags(0), None);
            assert_eq!(cache.len(), 2);
            assert_eq!(cache.get("libc.so.6").unwrap(), "/usr/lib64");
            assert_eq!(cache.get("libnoneed.so.1"), None);

            cache.select(ELFCLASS32, ELFDATA2LSB, EM_386, FileFlags(0), None);
            assert_eq!(cache.len(), 2);
            assert_eq!(cache.get("libc.so.6").unwrap(), "/usr/lib32");
            assert_eq!(cache.get("libnoneed.so.1").unwrap(), "/usr/lib32");
            assert_eq!(cache.get("libz.so.1"), None);
        }
    }

    #[test]
    fn flag_elf_entries() {
        // ldconfig before 2.37 marks a library without a libc dependency as
        // FLAG_ELF, which the loaders with the generic check take (i386) and
        // the others do not (x86-64).
        let entries = [
            (FLAG_ELF, "libnoneed.so.1", "/opt/libnoneed.so.1"),
            (X86_64, "libnoneed.so.1", "/usr/lib64/libnoneed.so.1"),
        ];
        let new = build_cache(&entries.map(|(f, n, p)| (f, n, p, 0)), &[]);
        for cache in [build_old(&entries), new] {
            let i386 = select_abi(&cache, ELFCLASS32, EM_386, FileFlags(0));
            assert_eq!(i386["libnoneed.so.1"], "/opt");
            let x86_64 = select_abi(&cache, ELFCLASS64, EM_X86_64, FileFlags(0));
            assert_eq!(x86_64["libnoneed.so.1"], "/usr/lib64");
        }
    }

    #[test]
    fn default_flags_on_the_old_format() {
        // The new format takes the first entry the loader accepts, while the
        // old one keeps searching for one with the loader default flags, and
        // otherwise takes the last one.
        let i386 = |cache: &[u8]| select_abi(cache, ELFCLASS32, EM_386, FileFlags(0));
        let entries = [
            (FLAG_ELF, "libfoo.so.1", "/opt/elf/libfoo.so.1"),
            (FLAG_ELF, "libfoo.so.1", "/usr/elf/libfoo.so.1"),
            (FLAG_ELF_LIBC6, "libfoo.so.1", "/usr/lib/libfoo.so.1"),
            (FLAG_ELF, "libbar.so.1", "/opt/elf/libbar.so.1"),
            (FLAG_ELF, "libbar.so.1", "/usr/elf/libbar.so.1"),
        ];
        let old = i386(&build_old(&entries));
        assert_eq!(old["libfoo.so.1"], "/usr/lib");
        assert_eq!(old["libbar.so.1"], "/usr/elf");
        let new = i386(&build_cache(&entries.map(|(f, n, p)| (f, n, p, 0)), &[]));
        assert_eq!(new["libfoo.so.1"], "/opt/elf");
        assert_eq!(new["libbar.so.1"], "/opt/elf");

        // The ARM loaders take the unmarked entries along with the ones of
        // their float ABI, but only the former are the default ones.
        let armhf = |cache: &[u8]| select_abi(cache, ELFCLASS32, EM_ARM, EF_ARM_VFP_FLOAT);
        let entries = [
            (
                FLAG_ARM_LIBHF | FLAG_ELF_LIBC6,
                "libm.so.6",
                "/usr/lib/arm-linux-gnueabihf/libm.so.6",
            ),
            (
                FLAG_ARM_LIBSF | FLAG_ELF_LIBC6,
                "libm.so.6",
                "/usr/lib/arm-linux-gnueabi/libm.so.6",
            ),
            (FLAG_ELF_LIBC6, "libm.so.6", "/usr/lib/libm.so.6"),
        ];
        assert_eq!(armhf(&build_old(&entries))["libm.so.6"], "/usr/lib");
        let new = build_cache(&entries.map(|(f, n, p)| (f, n, p, 0)), &[]);
        assert_eq!(armhf(&new)["libm.so.6"], "/usr/lib/arm-linux-gnueabihf");
    }

    #[test]
    fn invalid_strings_affect_their_entry_only() {
        let mut cache = build_cache(
            &[
                (X86_64, "libbar.so.1", "/opt/libbar.so.1", 0),
                (X86_64, "libbar.so.1", "/usr/lib/libbar.so.1", 0),
                (X86_64, "libbad.so.1", "/usr/lib/libbad.so.1", 0),
                (X86_64, "libc.so.6", "/usr/lib/libc.so.6", 0),
                (X86_64, "libfoo.so.1", "/usr/xib/libfoo.so.1", 0),
                (X86_64, "libfoo.so.1", "/usr/lib/libfoo.so.1", 0),
            ],
            &[],
        );
        // A path out of the file makes the loader skip the entry.
        set_u32(&mut cache, entry_value(0), u32::MAX);
        // No dependency names an entry that is not valid UTF-8.
        patch(&mut cache, b"libbad", b"lib\xffad");
        // The loader would try a path that is not valid UTF-8, which rldd can
        // not, so the name resolves nothing through the cache.
        patch(&mut cache, b"/usr/xib", b"/usr/\xffib");

        let cache = select(&cache, &[]);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache["libbar.so.1"], "/usr/lib");
        assert_eq!(cache["libc.so.6"], "/usr/lib");
    }

    #[test]
    fn malformed_extension_keeps_the_regular_entries() {
        let good = build_cache(
            &[
                (
                    X86_64,
                    "liblzma.so.5",
                    "/opt/x86-64-v3/liblzma.so.5",
                    named(0),
                ),
                (X86_64, "liblzma.so.5", "/usr/lib/liblzma.so.5", 0),
            ],
            &["x86-64-v3"],
        );
        let supported = ["x86-64-v3", "x86-64-v2"];
        assert_eq!(select(&good, &supported)["liblzma.so.5"], "/opt/x86-64-v3");

        let extension = u32::from_ne_bytes(good[EXTENSION_OFFSET..][..4].try_into().unwrap());
        let (ext, section) = (extension as usize, extension as usize + CACHE_EXTENSION_LEN);
        let corruptions: [(usize, u32); 7] = [
            // The magic.
            (ext, 0),
            // The extension offset, past the file and misaligned.
            (EXTENSION_OFFSET, good.len() as u32),
            (EXTENSION_OFFSET, extension + 2),
            // The section count, past the file.
            (ext + 4, u32::MAX),
            // The section size, past the file, empty, and not a multiple of 4.
            (section + 12, u32::MAX),
            (section + 12, 0),
            (section + 12, 3),
        ];
        for (offset, value) in corruptions {
            let mut cache = good.clone();
            set_u32(&mut cache, offset, value);
            assert_eq!(select(&cache, &supported)["liblzma.so.5"], "/usr/lib");
        }
    }
}
