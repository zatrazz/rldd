use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Result, Seek, SeekFrom};
use std::mem::{align_of, size_of};
use std::path::Path;
use std::str;

use object::elf::*;

mod hwcap;

const CACHEMAGIC: &str = "ld.so-1.7.0";
const CACHEMAGIC_NEW: &str = "glibc-ld.so.cache";
const CACHE_VERSION: &str = "1.1";

fn read_u8(reader: &mut dyn Read) -> std::io::Result<u8> {
    let mut buffer = [0; 1];
    reader.read(&mut buffer)?;
    Ok(buffer[0])
}

// Read a i32 value in native endianess format.
fn read_i32(reader: &mut dyn Read) -> std::io::Result<i32> {
    let mut buffer = [0; 4];
    reader.read(&mut buffer[..])?;
    Ok(i32::from_ne_bytes(buffer) as i32)
}

// Read a u32 value in native endianess format.
fn read_u32(reader: &mut dyn Read) -> std::io::Result<u32> {
    let mut buffer = [0; 4];
    reader.read(&mut buffer[..])?;
    Ok(u32::from_ne_bytes(buffer) as u32)
}

// Read a u64 value in native endianess format.
fn read_u64(reader: &mut dyn Read) -> std::io::Result<u64> {
    let mut buffer = [0; 8];
    reader.read(&mut buffer[..])?;
    Ok(u64::from_ne_bytes(buffer) as u64)
}

#[derive(Debug)]
struct CacheFile {
    magic: [u8; CACHEMAGIC.len()],
    nlibs: u32,
}
const CACHE_FILE_LEN: usize = size_of::<CacheFile>();

impl CacheFile {
    fn from_reader<R: Read>(rdr: &mut BufReader<R>) -> std::io::Result<Self> {
        let mut magic = [0; CACHEMAGIC.len()];
        rdr.read(&mut magic)?;

        Ok(CacheFile {
            magic: magic,
            nlibs: read_u32(rdr)?,
        })
    }
}

#[derive(Debug)]
struct FileEntry {
    flags: i32,
    key: u32,
    value: u32,
}
const FILE_ENTRY_LEN: usize = size_of::<FileEntry>();

impl FileEntry {
    fn from_reader<R: Read>(rdr: &mut BufReader<R>) -> std::io::Result<Self> {
        Ok(FileEntry {
            flags: read_i32(rdr)?,
            key: read_u32(rdr)?,
            value: read_u32(rdr)?,
        })
    }
}

#[derive(Debug)]
struct CacheFileNew {
    magic: [u8; CACHEMAGIC_NEW.len()],
    version: [u8; CACHE_VERSION.len()],
    nlibs: u32,
    _len_strings: u32,
    flags: u8,
    _padding_unused: [u8; 3],
    extension_offset: u32,
    _unused: [u32; 3],
}
const CACHE_FILE_NEW_LEN: usize = size_of::<CacheFileNew>();

impl CacheFileNew {
    fn from_reader<R: Read>(rdr: &mut BufReader<R>) -> std::io::Result<Self> {
        let mut magic = [0; CACHEMAGIC_NEW.len()];
        rdr.read(&mut magic)?;
        let mut version = [0; CACHE_VERSION.len()];
        rdr.read(&mut version)?;
        let nlibs = read_u32(rdr)?;
        let len_strings = read_u32(rdr)?;
        let flags = read_u8(rdr)?;
        let mut pending_unused: [u8; 3] = [0; 3];
        rdr.read(&mut pending_unused)?;
        let extension_offset = read_u32(rdr)?;
        let unused = [read_u32(rdr)?, read_u32(rdr)?, read_u32(rdr)?];

        Ok(CacheFileNew {
            magic: magic,
            version: version,
            nlibs: nlibs,
            _len_strings: len_strings,
            flags: flags,
            _padding_unused: pending_unused,
            extension_offset: extension_offset,
            _unused: unused,
        })
    }
}

#[derive(Debug)]
struct FileEntryNew {
    flags: i32,
    key: u32,
    value: u32,
    _osversion_unused: u32,
    hwcap: u64,
}
const FILE_ENTRY_NEW_LEN: usize = size_of::<FileEntryNew>();

impl FileEntryNew {
    fn from_reader<R: Read>(rdr: &mut BufReader<R>) -> std::io::Result<Self> {
        Ok(FileEntryNew {
            flags: read_i32(rdr)?,
            key: read_u32(rdr)?,
            value: read_u32(rdr)?,
            _osversion_unused: read_u32(rdr)?,
            hwcap: read_u64(rdr)?,
        })
    }
}

// The CacheFileNew extension header, pointer by extension_offset field.  The MAGIC should be
// 'cache_extension_magic' and COUNT indicates ow many CacheExtensionSection can be read
// (on glibc definition the CacheExtensionSection is defined as a flexible array meant to be
// accessed through mmap).
#[derive(Debug)]
struct CacheExtension {
    magic: u32,
    count: u32,
}
const CACHE_EXTENSION_LEN: usize = size_of::<CacheExtension>();

impl CacheExtension {
    fn from_reader<R: Read>(rdr: &mut BufReader<R>) -> std::io::Result<Self> {
        Ok(CacheExtension {
            magic: read_u32(rdr)?,
            count: read_u32(rdr)?,
        })
    }
}

#[allow(non_upper_case_globals)]
const cache_extension_magic: u32 = 0xeaa42174;

const CACHE_EXTENSION_TAG_GLIBC_HWCAPS: u32 = 1;

// Element in the array following struct CacheExtension.
#[derive(Debug)]
struct CacheExtensionSection {
    tag: u32,    // Type of the extension section (CACHE_EXTENSION_TAG_*).
    _flags: u32, // Extension-specific flags.  Currently generated as zero.
    offset: u32, // Offset from the start of the file for the data in this extension section.
    size: u32,   // Length in bytes of the extension data.
}
const CACHE_EXTENSION_SECTION_LEN: usize = size_of::<CacheExtensionSection>();

impl CacheExtensionSection {
    fn from_reader<R: Read>(rdr: &mut BufReader<R>) -> std::io::Result<Self> {
        Ok(CacheExtensionSection {
            tag: read_u32(rdr)?,
            _flags: read_u32(rdr)?,
            offset: read_u32(rdr)?,
            size: read_u32(rdr)?,
        })
    }
}

// Check the ld.so.cache FileEntryNew flags against a pre-defined value from glibc
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

fn check_file_entry_flags(flags: i32, ei_class: u8, e_machine: u16, e_flags: u32) -> bool {
    match e_machine {
        EM_AARCH64 => match ei_class {
            ELFCLASS64 => flags == FLAG_ELF_LIBC6 | FLAG_AARCH64_LIB64,
            _ => false,
        },
        EM_ARM => {
            if e_flags | EF_ARM_VFP_FLOAT == EF_ARM_VFP_FLOAT {
                (flags == FLAG_ARM_LIBHF | FLAG_ELF_LIBC6) | (flags == FLAG_ELF_LIBC6)
            } else if e_flags | EF_ARM_SOFT_FLOAT == EF_ARM_SOFT_FLOAT {
                (flags == FLAG_ARM_LIBSF | FLAG_ELF_LIBC6) | (flags == FLAG_ELF_LIBC6)
            } else {
                false
            }
        }
        EM_IA_64 => match ei_class {
            ELFCLASS64 => flags == FLAG_ELF_LIBC6 | FLAG_IA64_LIB64,
            _ => false,
        },
        EM_MIPS => match ei_class {
            ELFCLASS32 => {
                if e_flags & (EF_MIPS_NAN2008 | EF_MIPS_ABI_ON32)
                    == EF_MIPS_NAN2008 | EF_MIPS_ABI_ON32
                {
                    flags == FLAG_MIPS64_LIBN32_NAN2008 | FLAG_ELF_LIBC6
                } else if e_flags & EF_MIPS_NAN2008 == EF_MIPS_NAN2008 {
                    flags == FLAG_MIPS_LIB32_NAN2008 | FLAG_ELF_LIBC6
                } else if e_flags & EF_MIPS_ABI_ON32 == EF_MIPS_ABI_ON32 {
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
        EM_PPC64 => flags == FLAG_ELF_LIBC6 | FLAG_POWERPC_LIB64,
        EM_RISCV => {
            if e_flags | EF_RISCV_FLOAT_ABI_SOFT == EF_RISCV_FLOAT_ABI_SOFT {
                flags == FLAG_ELF_LIBC6 | FLAG_RISCV_FLOAT_ABI_SOFT
            } else if e_flags & EF_RISCV_FLOAT_ABI_DOUBLE == EF_RISCV_FLOAT_ABI_DOUBLE {
                flags == FLAG_ELF_LIBC6 | FLAG_RISCV_FLOAT_ABI_DOUBLE
            } else {
                flags == FLAG_ELF_LIBC6
            }
        }
        EM_S390 => match ei_class {
            ELFCLASS32 => flags == FLAG_ELF_LIBC6,
            ELFCLASS64 => flags == FLAG_ELF_LIBC6 | FLAG_S390_LIB64,
            _ => false,
        },
        EM_SPARC => match ei_class {
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
const CacheFileNew_flags_endian_big: u8 = 3u8;
#[allow(non_upper_case_globals, dead_code)]
const CacheFileNew_flags_endian_little: u8 = 2u8;
#[cfg(target_endian = "big")]
#[allow(non_upper_case_globals)]
const CacheFileNew_flags_endian_current: u8 = CacheFileNew_flags_endian_big;
#[cfg(target_endian = "little")]
#[allow(non_upper_case_globals)]
const CacheFileNew_flags_endian_current: u8 = CacheFileNew_flags_endian_little;

fn check_cache_new_endian(flags: u8) -> bool {
    // A zero value for cache->flags means that no endianness.
    flags == 0 || (flags & CacheFileNew_flags_endian_big) == CacheFileNew_flags_endian_current
}

fn read_string<R: Read + Seek>(
    reader: &mut BufReader<R>,
    prev_off: &mut i64,
    cur: i64,
) -> Result<String> {
    let mut value: Vec<u8> = Vec::<u8>::new();
    reader.seek_relative(cur - *prev_off)?;
    let size = reader.read_until(b'\0', &mut value)?;
    let value = str::from_utf8(&value)
        .map_err(|_| Error::new(ErrorKind::Other, "Invalid UTF8 value"))
        .map(|s| s.trim_matches(char::from(0)).to_string())?;
    *prev_off = cur + size as i64;
    Ok(value)
}

fn align_cache(value: usize) -> usize {
    (value + (align_of::<CacheFileNew>() - 1)) & !(align_of::<CacheFileNew>() - 1)
}

pub type LdCache = HashMap<String, String>;

fn parse_ld_so_cache_old<R: Read + Seek>(
    reader: &mut BufReader<R>,
    cache_size: usize,
    ei_class: u8,
    e_machine: u16,
    e_flags: u32,
) -> Result<LdCache> {
    let hdr = CacheFile::from_reader(reader)?;

    if (cache_size - CACHE_FILE_LEN) / FILE_ENTRY_LEN < hdr.nlibs as usize {
        return Err(Error::new(ErrorKind::Other, "Invalid cache file"));
    }

    let offset = align_cache(CACHE_FILE_LEN + (hdr.nlibs as usize * FILE_ENTRY_LEN));
    if cache_size > (offset + CACHE_FILE_NEW_LEN) {
        return parse_ld_so_cache_new(reader, offset, ei_class, e_machine, e_flags);
    }

    if hdr.magic != CACHEMAGIC.as_bytes() {
        return Err(Error::new(ErrorKind::Other, "Invalid cache magic"));
    }

    // The new string format starts at a different position than the newer one.
    let cache_off = CACHE_FILE_LEN as u32 + hdr.nlibs * FILE_ENTRY_LEN as u32;

    let mut offsets: Vec<(u32, u32)> = Vec::with_capacity(hdr.nlibs as usize);
    for _i in 0..hdr.nlibs {
        let entry = FileEntry::from_reader(reader)?;
        if !check_file_entry_flags(entry.flags, ei_class, e_machine, e_flags) {
            continue;
        }
        offsets.push((entry.key + cache_off, entry.value + cache_off));
    }

    let mut prev_off = cache_off as i64;

    let mut ldsocache = LdCache::new();
    for off in offsets {
        let key = read_string(reader, &mut prev_off, off.0 as i64)?;
        let value = read_string(reader, &mut prev_off, off.1 as i64)?;

        ldsocache.insert(key, value);
    }
    Ok(ldsocache)
}

fn parse_ld_so_cache_new<R: Read + Seek>(
    reader: &mut BufReader<R>,
    initial: usize,
    ei_class: u8,
    e_machine: u16,
    e_flags: u32,
) -> Result<LdCache> {
    reader.seek(SeekFrom::Start(initial as u64))?;
    let hdr = CacheFileNew::from_reader(reader)?;

    if hdr.magic != CACHEMAGIC_NEW.as_bytes() {
        return Err(Error::new(ErrorKind::Other, "Invalid new cache magic"));
    }
    if hdr.version != CACHE_VERSION.as_bytes() {
        return Err(Error::new(ErrorKind::Other, "Invalid new cache version"));
    }
    if !check_cache_new_endian(hdr.flags) {
        return Err(Error::new(ErrorKind::Other, "Invalid new cache endianness"));
    }

    // To optimize file read, create a list of file entries offset (name and path)
    // and then read the filaname and path.  Also keep track of hwcap index value used for
    // glibc-hwcap support.
    let mut offsets: Vec<(u32, u32, Option<u32>)> = Vec::with_capacity(hdr.nlibs as usize);

    for _i in 0..hdr.nlibs {
        let entry = FileEntryNew::from_reader(reader)?;
        // Skip not supported entries for the binary architecture, for instance x86_64/i686
        // with multilib support.
        if !check_file_entry_flags(entry.flags, ei_class, e_machine, e_flags) {
            continue;
        }

        offsets.push((
            entry.key,
            entry.value,
            check_cache_hwcap_extension(entry.hwcap),
        ));
    }

    let mut prev_off = CACHE_FILE_NEW_LEN as i64 + hdr.nlibs as i64 * FILE_ENTRY_NEW_LEN as i64;

    // Return vector of defined glibc-hwcap subfolder defined in the extension headers.  For
    // instance on x86_64 it mught return [x86-64-v2, x86-64-v3].
    let hwcap_idxs =
        parse_ld_so_cache_glibc_hwcap(reader, &mut prev_off, hdr.extension_offset as i64)?;

    // And obtain the current machine supported glibc-hwcap subfolder.
    let hwcap_supported = hwcap::hwcap_supported();

    let mut ldsocache = LdCache::new();
    // Keep track of the last glibc-hwcap value for the entry to allow check if the new entry is
    // new best-fit value.  Using an extra map avoid the need to add an extra field on the
    // returned ldsocache map.
    let mut hwcapseen = HashMap::<String, usize>::new();

    // Now read all library entries
    for off in offsets {
        let key = read_string(reader, &mut prev_off, off.0 as i64)?;
        let value = read_string(reader, &mut prev_off, off.1 as i64)?;

        // First check if there is an already found glibc-hwcap option for the entry.  In this case,
        // also check if the newer entry has a glibc-hwcap index associated and if it is also the case
        // check if the new glibc-hwcap is a better fit than the existent one.  This is done by
        // comparing the index value, since the supported hwcasp are sorted in priority order (with
        // the first entry being the better fit).
        if let Some(seen_idx) = hwcapseen.get(&key) {
            // It only makes sense to possible update a new entry if there is also a glibc-hwcap
            // entry associated.
            if let Some(new_idx) = check_hwcap_index(&off.2, &hwcap_idxs, &hwcap_supported) {
                if new_idx < *seen_idx {
                    // If the entry is a newer best fit, update both the cache and the seen map.
                    hwcapseen.insert(key.to_string(), new_idx);
                    ldsocache.insert(key, value);
                }
            }
        } else {
            if let Some(idx) = check_hwcap_index(&off.2, &hwcap_idxs, &hwcap_supported) {
                hwcapseen.insert(key.to_string(), idx);
            }
            ldsocache.insert(key, value);
        }
    }

    Ok(ldsocache)
}

// Return a new best-fit index for HWCAP_SUPPORTED if the HWCAPIDX contains a valid value.
fn check_hwcap_index(
    hwcapidx: &Option<u32>,
    hwcap_idxs: &Vec<String>,
    hwcap_supported: &Vec<&'static str>,
) -> Option<usize> {
    if let Some(hwidx) = hwcapidx {
        let hwcap_value = hwcap_idxs[*hwidx as usize].to_string();
        if let Some(new_idx) = hwcap_supported.iter().position(|&r| r == hwcap_value) {
            return Some(new_idx);
        }
    }
    None
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
// array is indexed by the 32-bit lower bit from FileEntryNew hwcap field.
fn parse_ld_so_cache_glibc_hwcap<R: Read + Seek>(
    reader: &mut BufReader<R>,
    prev_off: &mut i64,
    cur: i64,
) -> Result<Vec<String>> {
    if cur == 0 {
        return Ok(Vec::<String>::new());
    }
    reader.seek_relative(cur - *prev_off)?;
    let ext = CacheExtension::from_reader(reader)?;
    *prev_off = cur + CACHE_EXTENSION_LEN as i64;

    if ext.magic != cache_extension_magic {
        return Err(Error::new(
            ErrorKind::Other,
            "Invalid CacheExtension magic",
        ));
    }

    // Return an empty set if the cache does not have any glibc-hwcap extension.
    let mut r = Vec::<String>::new();
    for _i in 0..ext.count {
        let ext_sec = CacheExtensionSection::from_reader(reader)?;
        *prev_off += CACHE_EXTENSION_SECTION_LEN as i64;

        if ext_sec.tag == CACHE_EXTENSION_TAG_GLIBC_HWCAPS {
            reader.seek_relative(ext_sec.offset as i64 - *prev_off)?;

            let idxslen: usize = ext_sec.size as usize / 4;
            let mut idxs: Vec<u32> = Vec::with_capacity(idxslen);

            for _j in 0..idxslen {
                idxs.push(read_u32(reader)?);
            }

            *prev_off = ext_sec.offset as i64 + ext_sec.size as i64;
            for idx in &idxs {
                r.push(read_string(reader, prev_off, *idx as i64)?);
            }
        }
    }
    return Ok(r);
}

pub fn parse_ld_so_cache<P: AsRef<Path>>(
    filename: &P,
    ei_class: u8,
    e_machine: u16,
    e_flags: u32,
) -> Result<LdCache> {
    let file = File::open(filename)?;
    let size = file.metadata()?.len() as usize;

    let mut reader = BufReader::new(file);

    let mut magic = [0u8; CACHEMAGIC.len()];
    reader.read_exact(&mut magic[..])?;
    reader.rewind()?;

    if magic == CACHEMAGIC.as_bytes() {
        parse_ld_so_cache_old(&mut reader, size, ei_class, e_machine, e_flags)
    } else {
        parse_ld_so_cache_new(&mut reader, 0, ei_class, e_machine, e_flags)
    }
}
