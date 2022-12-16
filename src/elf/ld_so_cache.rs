use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Result, Seek, SeekFrom};
use std::mem::{size_of, transmute};
use std::path::Path;
use std::str;

use object::elf::*;

const CACHEMAGIC_NEW: &str = "glibc-ld.so.cache";
const CACHE_VERSION: &str = "1.1";

#[derive(Debug)]
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
const CACHE_FILE_NEW_LEN: usize = size_of::<cache_file_new>();

#[derive(Debug)]
#[repr(C)]
struct file_entry_new {
    flags: i32,
    key: u32,
    value: u32,
    osversion_unused: u32,
    hwcap: u64,
}
const FILE_ENTRY_NEW_LEN: usize = size_of::<file_entry_new>();

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
        EM_PPC64 => flags == FLAG_POWERPC_LIB64,
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
#[allow(non_upper_case_globals)]
const cache_file_new_flags_endian_big: u8 = 3u8;
#[allow(non_upper_case_globals)]
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

fn read_string<R: Read + Seek>(reader: &mut BufReader<R>, offset: u32) -> Result<String> {
    let pos = reader.stream_position()?;
    let mut value: Vec<u8> = Vec::<u8>::new();
    reader.seek(SeekFrom::Start(offset as u64))?;
    reader.read_until(b'\0', &mut value)?;
    let value = str::from_utf8(&value)
        .map_err(|_| Error::new(ErrorKind::Other, "Invalid UTF8 value"))
        .map(|s| s.trim_matches(char::from(0)).to_string())?;
    reader.seek(SeekFrom::Start(pos as u64))?;
    Ok(value)
}

pub type LdCache = HashMap<String, String>;

pub fn parse_ld_so_cache<P: AsRef<Path>>(
    filename: &P,
    ei_class: u8,
    e_machine: u16,
    e_flags: u32,
) -> Result<LdCache> {
    let mut reader = BufReader::new(File::open(filename)?);

    let hdr: cache_file_new = {
        let mut h = [0u8; CACHE_FILE_NEW_LEN];
        reader.read_exact(&mut h[..])?;
        unsafe { transmute(h) }
    };

    if hdr.magic != CACHEMAGIC_NEW.as_bytes() {
        return Err(Error::new(ErrorKind::Other, "Invalid cache magic"));
    }
    if hdr.version != CACHE_VERSION.as_bytes() {
        return Err(Error::new(ErrorKind::Other, "Invalid cache version"));
    }
    if !check_cache_new_endian(hdr.flags) {
        return Err(Error::new(ErrorKind::Other, "Invalid cache endianness"));
    }

    let mut ldsocache = LdCache::new();

    for _i in 0..hdr.nlibs {
        let entry: file_entry_new = {
            let mut e = [0u8; FILE_ENTRY_NEW_LEN];
            reader.read_exact(&mut e[..])?;
            unsafe { transmute(e) }
        };
        let key = read_string(&mut reader, entry.key)?;
        let value = read_string(&mut reader, entry.value)?;

        if !check_file_entry_flags(entry.flags, ei_class, e_machine, e_flags) {
            continue;
        }

        // For now create a direct map to library map, without taking in consideration hwcaps.
        ldsocache.insert(key, value);
    }

    Ok(ldsocache)
}
