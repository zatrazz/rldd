// Run-time link-editor configuration file parsing function.  OpenBSD version.

use std::fs::File;
use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Result, Seek, SeekFrom};
use std::mem::{size_of, transmute};
use std::path::Path;
use std::str;

use crate::search_path;

#[repr(C)]
struct hints_header {
    hh_magic: i64,
    hh_version: i64,
    hh_hashtab: i64,
    hh_nbucket: i64,
    hh_strtab: i64,
    hh_strtab_sz: i64,
    hh_ehints: i64,
    hh_dirlist: i64,
}
const HINTS_HEADER_LEN: u32 = size_of::<hints_header>() as u32;

const HH_MAGIC: i64 = 0o11421044151;
const LD_HINTS_VERSION_2: i64 = 2;
const HINTS_MAXFILESIZE: i64 = i32::MAX as i64;

pub fn parse_ld_so_hints<P: AsRef<Path>>(filename: &P) -> Result<search_path::SearchPathVec> {
    let mut file = File::open(filename)?;

    let hsize = file.metadata()?.len() as i64;
    if hsize > HINTS_MAXFILESIZE {
        return Err(Error::new(
            ErrorKind::Other,
            format!("File larger than {}", HINTS_MAXFILESIZE),
        ));
    }

    let hdr: hints_header = {
        let mut h = [0u8; HINTS_HEADER_LEN as usize];
        file.read_exact(&mut h[..])?;
        unsafe { transmute(h) }
    };

    if hdr.hh_magic != HH_MAGIC || hdr.hh_ehints > hsize {
        return Err(Error::new(ErrorKind::Other, "Invalid ELFHINTS_MAGIC"));
    }
    if hdr.hh_version != LD_HINTS_VERSION_2 {
        return Err(Error::new(ErrorKind::Other, "Invalid elfhints_hdr version"));
    }

    let dirlistoff: u64 = (hdr.hh_strtab + hdr.hh_dirlist) as u64;
    file.seek(SeekFrom::Start(dirlistoff))?;

    // OpenBSD header file does not specify the hh_dirlist len, but it encodes it as a
    // C string (with a NULL terminator).
    let mut reader = BufReader::new(file);
    let mut dirlist: Vec<u8> = Vec::<u8>::new();
    reader.read_until(b'\0', &mut dirlist)?;

    if let Some(dirlist) = str::from_utf8(&dirlist)
        .ok()
        .map(|s| s.trim_matches(char::from(0)).to_string())
    {
        return Ok(search_path::from_string(&dirlist, &[':', ';']));
    }

    Err(Error::new(
        ErrorKind::Other,
        "Invalid directory list in hint file",
    ))
}
